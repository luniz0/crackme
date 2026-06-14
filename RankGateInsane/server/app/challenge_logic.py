"""Protocol orchestration + the 7-stage validation pipeline for RankGate Insane.

Three entry points, one per HTTP endpoint, each taking a raw binary frame and
returning a raw binary frame (the HTTP layer in main.py only does base64):

    handle_hello     : HELLO          -> SERVER_CHALLENGE
    handle_exchange  : CLIENT_PROOF_1 -> SERVER_PROOF_1
    handle_finalize  : CLIENT_PROOF_2 -> SEALED_FLAG

Transcript progression (rolling SHA-256), identical on client and server:
    T0 -> +HELLO -> T1 -> +SERVER_CHALLENGE -> T2(=salt) -> +CLIENT_PROOF_1
       -> T3 -> +SERVER_PROOF_1 -> T4 -> +CLIENT_PROOF_2 -> T5 -> +SEALED_FLAG

Session keys are HKDF-derived from the ECDH shared secret with salt = T2.
The flag is sealed twice: an inner XChaCha20-Poly1305 layer keyed by the
accepted transcript (T5), wrapped again by the normal s2c frame encryption.
"""

from __future__ import annotations

import os

from . import config
from . import crypto_box as cb
from . import verifier
from . import vm_reference
from .errors import ProofError, ProtocolError
from .protocol import Frame, Transcript
from .sessions import STORE, Session


# ---------------------------------------------------------------------------
# Key schedule
# ---------------------------------------------------------------------------
def _bootstrap_mac_key() -> bytes:
    return cb.sha256(config.BOOTSTRAP_MAC_LABEL)


def _derive_keys(prk: bytes) -> dict:
    e = cb.hkdf_expand
    return {
        "c2s": e(prk, config.HKDF_C2S, 32),
        "s2c": e(prk, config.HKDF_S2C, 32),
        "mac": e(prk, config.HKDF_MAC, 32),
        "proof1": e(prk, config.HKDF_PROOF1, 32),
        "sproof1": e(prk, config.HKDF_SPROOF1, 32),
        "proof2": e(prk, config.HKDF_PROOF2, 32),
        "seal": e(prk, config.HKDF_SEAL, 32),
    }


# ---------------------------------------------------------------------------
# Frame helpers (bind a Transcript + keys)
# ---------------------------------------------------------------------------
def _restore_transcript(state: bytes) -> Transcript:
    t = Transcript()
    t.state = state
    return t


def _plain_seal(t: Transcript, mac_key: bytes, mt: int, sid: bytes,
                counter: int, payload: bytes) -> Frame:
    nonce = os.urandom(config.SZ_NONCE)
    return t.seal_frame(mac_key, mt, sid, counter, nonce, payload,
                        b"\x00" * config.SZ_AUTHTAG)


def _plain_open(t: Transcript, mac_key: bytes, frame: Frame) -> bytes:
    t.open_frame(mac_key, frame)
    return frame.encrypted_payload


def _aead_seal(t: Transcript, mac_key: bytes, aead_key: bytes, mt: int,
               sid: bytes, counter: int, plaintext: bytes) -> Frame:
    nonce = os.urandom(config.SZ_NONCE)
    aad = Frame(mt, sid, counter, nonce, b"\x00" * len(plaintext),
                b"", b"").header()
    ct, tag = cb.aead_encrypt(aead_key, nonce, plaintext, aad)
    return t.seal_frame(mac_key, mt, sid, counter, nonce, ct, tag)


def _aead_open(t: Transcript, mac_key: bytes, aead_key: bytes,
               frame: Frame) -> bytes:
    t.open_frame(mac_key, frame)
    aad = frame.header()
    try:
        return cb.aead_decrypt(aead_key, frame.nonce, frame.encrypted_payload,
                               frame.auth_tag, aad)
    except Exception as exc:  # noqa: BLE001
        raise ProtocolError("aead", f"decrypt failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Stage 1/2 helper: turn HELLO username + later license into normalized form
# ---------------------------------------------------------------------------
def _parse_hello_payload(payload: bytes) -> tuple[bytes, bytes, str]:
    if len(payload) < 32 + 16 + 2:
        raise ProtocolError("hello", "short hello payload")
    client_pub = payload[0:32]
    client_random = payload[32:48]
    ulen = int.from_bytes(payload[48:50], "big")
    uname_raw = payload[50:50 + ulen]
    if len(uname_raw) != ulen:
        raise ProtocolError("hello", "bad username length")
    return client_pub, client_random, uname_raw.decode("latin-1")


# ===========================================================================
# /api/v1/hello  :  HELLO -> SERVER_CHALLENGE
# ===========================================================================
def handle_hello(raw: bytes) -> bytes:
    frame = Frame.parse(raw)
    if frame.message_type != config.MT_HELLO:
        raise ProtocolError("hello", "unexpected message type")

    sess = STORE.create(frame.session_id)
    sess.accept_client_counter(frame.counter)

    t = Transcript()
    payload = _plain_open(t, _bootstrap_mac_key(), frame)
    client_pub, client_random, uname_raw = _parse_hello_payload(payload)

    # Stage 1 (eager): username normalization / canonical encoding.
    sess.username_norm = verifier.normalize_username(uname_raw)
    sess.client_eph_pub = client_pub

    # Server ephemeral X25519 + signed challenge.
    server_priv, server_pub = cb.x25519_keypair()
    server_random = os.urandom(16)
    shared = cb.x25519_shared(server_priv, client_pub)

    signed = (config.SIGN_CONTEXT + t.state + server_pub + server_random)
    signature = cb.ed25519_sign(config.SERVER_SIGN_SK, signed)

    chal_payload = server_pub + server_random + signature
    out = _plain_seal(t, _bootstrap_mac_key(), config.MT_SERVER_CHALLENGE,
                      frame.session_id, sess.next_server_counter(), chal_payload)

    # Derive session keys: salt = T2 (transcript after SERVER_CHALLENGE).
    salt = t.state
    prk = cb.hkdf_extract(salt, shared)
    sess.prk = prk
    sess.keys = _derive_keys(prk)
    sess.transcript_state = t.state
    sess.salt = salt
    sess.server_random = server_random
    sess.server_eph_pub = server_pub
    return out.serialize()


# ===========================================================================
# /api/v1/exchange  :  CLIENT_PROOF_1 -> SERVER_PROOF_1
# ===========================================================================
def handle_exchange(raw: bytes) -> bytes:
    frame = Frame.parse(raw)
    if frame.message_type != config.MT_CLIENT_PROOF_1:
        raise ProtocolError("exchange", "unexpected message type")

    sess = STORE.get(frame.session_id)
    sess.accept_client_counter(frame.counter)

    t = _restore_transcript(sess.transcript_state)
    keys = sess.keys
    payload = _aead_open(t, keys["mac"], keys["c2s"], frame)

    # Decrypted CLIENT_PROOF_1 payload layout.
    need = 25 + 32 + 32 + 4 + 4 + 32
    if len(payload) != need:
        raise ProtocolError("exchange", "bad proof1 payload length")
    off = 0

    def take(n):
        nonlocal off
        c = payload[off:off + n]
        off += n
        return c

    license_struct = take(25)
    vm_digest = take(32)
    vm_state_hash = take(32)
    vm_path_id = int.from_bytes(take(4), "big")
    vm_halt_code = int.from_bytes(take(4), "big")
    proof1 = take(32)

    # Stage 2: license format + checksum + username binding.
    verifier.validate_license(sess.username_norm, license_struct)

    # Stage 4: VM-derived digest (server recomputes independently).
    supplied_vm = vm_reference.VMResult(vm_digest, vm_state_hash,
                                        vm_path_id, vm_halt_code)
    # The session nonce that drives the handler permutation is the server
    # ephemeral random (public, transcript-bound).
    verifier.validate_vm(sess.username_norm, license_struct, sess.server_random,
                         sess.session_id, sess.salt, sess.server_random,
                         supplied_vm)

    # Stage 3: nonce-bound client proof #1.
    verifier.validate_proof1(
        keys["proof1"], proof1,
        sess.username_norm, license_struct, vm_digest, vm_state_hash,
        vm_path_id, vm_halt_code, sess.server_random, sess.session_id, sess.salt)

    # Stage 5: transcript MAC -- already enforced by _aead_open against the
    # server's own rolling transcript; reaching here means it matched.

    # Build SERVER_PROOF_1 (introduces server_challenge2 for stage 6).
    server_challenge2 = os.urandom(16)
    server_proof1 = cb.hmac_sha256(
        keys["sproof1"],
        b"RG6-SPROOF1/v6" + t.state + vm_digest + server_challenge2)
    sp_payload = server_proof1 + server_challenge2
    out = _aead_seal(t, keys["mac"], keys["s2c"], config.MT_SERVER_PROOF_1,
                     sess.session_id, sess.next_server_counter(), sp_payload)

    sess.transcript_state = t.state
    sess.server_challenge2 = server_challenge2
    sess.vm_digest = vm_digest
    sess.proof1_ok = True
    return out.serialize()


# ===========================================================================
# /api/v1/finalize  :  CLIENT_PROOF_2 -> SEALED_FLAG
# ===========================================================================
def handle_finalize(raw: bytes) -> bytes:
    frame = Frame.parse(raw)
    if frame.message_type not in (config.MT_CLIENT_PROOF_2, config.MT_FINALIZE):
        raise ProtocolError("finalize", "unexpected message type")

    sess = STORE.get(frame.session_id)
    sess.accept_client_counter(frame.counter)
    if not sess.proof1_ok:
        raise ProofError("finalize", "proof1 not completed")

    t = _restore_transcript(sess.transcript_state)
    keys = sess.keys
    payload = _aead_open(t, keys["mac"], keys["c2s"], frame)
    if len(payload) != 32:
        raise ProtocolError("finalize", "bad proof2 payload length")
    proof2 = payload

    # Stage 6: client proof #2, bound to server challenge material.
    verifier.validate_proof2(
        keys["proof2"], proof2,
        sess.server_challenge2, sess.server_random, sess.server_eph_pub,
        sess.vm_digest, sess.salt)

    # Stage 7: seal the flag with a key derived from the accepted transcript.
    final_transcript = t.state  # T5
    k_seal = cb.hkdf(final_transcript, keys["seal"], b"RG6 seal", 32)
    seal_nonce = os.urandom(config.SZ_NONCE)
    inner_ct, inner_tag = cb.aead_encrypt(k_seal, seal_nonce, config.FLAG,
                                          final_transcript)
    inner_blob = seal_nonce + inner_ct + inner_tag

    out = _aead_seal(t, keys["mac"], keys["s2c"], config.MT_SEALED_FLAG,
                     sess.session_id, sess.next_server_counter(), inner_blob)
    sess.transcript_state = t.state
    return out.serialize()
