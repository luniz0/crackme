"""Binary frame format + rolling transcript for RankGate Insane.

This is NOT JSON. The HTTP body is base64 of the binary frame below; the
application protocol itself is binary and authenticated.

Frame layout (all integers big-endian) -- see docs/protocol.md:

    offset field                 size
    ------ --------------------- ----
    0      magic                 4     ("RG6\\x00")
    4      version               1     (6)
    5      message_type          1
    6      session_id            16
    22     monotonic_counter     8
    30     nonce                 24    (XChaCha20-Poly1305 IETF)
    54     encrypted_payload_len 4
    58     encrypted_payload     N
    58+N   authentication_tag    16    (Poly1305 tag, split from AEAD output)
    74+N   transcript_mac        32    (HMAC-SHA256 over T_prev || pre_mac)

`pre_mac`  = header(58) || encrypted_payload || authentication_tag
`AAD`      = header(58)            (so the whole header is authenticated)
`full`     = pre_mac || transcript_mac

Transcript binding (rolling SHA-256):
    T0     = SHA256(TRANSCRIPT_SEED)
    mac_i  = HMAC-SHA256(k_mac, T_{i-1} || pre_mac_i)
    T_i    = SHA256(T_{i-1} || full_i)

The MAC of frame i therefore commits to every previous frame, and the next
frame's MAC commits to frame i -- a single tamper anywhere breaks the chain.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import config
from . import crypto_box as cb
from .errors import ProtocolError


@dataclass
class Frame:
    message_type: int
    session_id: bytes        # 16
    counter: int             # u64
    nonce: bytes             # 24
    encrypted_payload: bytes
    auth_tag: bytes          # 16
    transcript_mac: bytes    # 32

    # -- serialization -----------------------------------------------------
    def header(self) -> bytes:
        return (
            config.MAGIC
            + bytes([config.PROTO_VERSION, self.message_type])
            + self.session_id
            + self.counter.to_bytes(config.SZ_COUNTER, "big")
            + self.nonce
            + len(self.encrypted_payload).to_bytes(config.SZ_PAYLEN, "big")
        )

    def pre_mac(self) -> bytes:
        return self.header() + self.encrypted_payload + self.auth_tag

    def serialize(self) -> bytes:
        return self.pre_mac() + self.transcript_mac

    @staticmethod
    def parse(buf: bytes) -> "Frame":
        if len(buf) < config.HEADER_SIZE + config.SZ_AUTHTAG + config.SZ_TRANSCRIPT_MAC:
            raise ProtocolError("parse", "frame too short")
        off = 0

        def take(n: int) -> bytes:
            nonlocal off
            chunk = buf[off:off + n]
            if len(chunk) != n:
                raise ProtocolError("parse", "truncated frame")
            off += n
            return chunk

        magic = take(config.SZ_MAGIC)
        if magic != config.MAGIC:
            raise ProtocolError("parse", "bad magic")
        version = take(config.SZ_VERSION)[0]
        if version != config.PROTO_VERSION:
            raise ProtocolError("parse", "bad version")
        msgtype = take(config.SZ_MSGTYPE)[0]
        session_id = take(config.SZ_SESSION_ID)
        counter = int.from_bytes(take(config.SZ_COUNTER), "big")
        nonce = take(config.SZ_NONCE)
        paylen = int.from_bytes(take(config.SZ_PAYLEN), "big")
        if paylen > 1 << 20:
            raise ProtocolError("parse", "payload too large")
        payload = take(paylen)
        tag = take(config.SZ_AUTHTAG)
        tmac = take(config.SZ_TRANSCRIPT_MAC)
        if off != len(buf):
            raise ProtocolError("parse", "trailing bytes")
        return Frame(msgtype, session_id, counter, nonce, payload, tag, tmac)


class Transcript:
    """Rolling SHA-256 transcript with HMAC-SHA256 framing MAC."""

    def __init__(self) -> None:
        self.state = cb.sha256(config.TRANSCRIPT_SEED)

    def mac_for(self, mac_key: bytes, frame_pre_mac: bytes) -> bytes:
        return cb.hmac_sha256(mac_key, self.state + frame_pre_mac)

    def absorb(self, full_frame: bytes) -> None:
        self.state = cb.sha256(self.state + full_frame)

    # convenience: build an outgoing frame with a correct MAC, then absorb it
    def seal_frame(self, mac_key: bytes, message_type: int, session_id: bytes,
                   counter: int, nonce: bytes, encrypted_payload: bytes,
                   auth_tag: bytes) -> Frame:
        f = Frame(message_type, session_id, counter, nonce,
                  encrypted_payload, auth_tag, b"\x00" * config.SZ_TRANSCRIPT_MAC)
        f.transcript_mac = self.mac_for(mac_key, f.pre_mac())
        self.absorb(f.serialize())
        return f

    # convenience: verify an incoming frame's MAC, then absorb it
    def open_frame(self, mac_key: bytes, frame: Frame) -> None:
        expected = self.mac_for(mac_key, frame.pre_mac())
        if not cb.ct_equal(expected, frame.transcript_mac):
            raise ProtocolError("transcript_mac", "transcript MAC mismatch")
        self.absorb(frame.serialize())
