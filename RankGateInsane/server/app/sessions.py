"""In-memory session store for RankGate Insane.

State must survive across the three HTTP calls (/hello, /exchange, /finalize)
of a single solve attempt. This is a local single-process challenge server, so
a plain dict guarded by nothing fancy is sufficient. Sessions expire by count
(oldest evicted) to bound memory.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from .errors import ProtocolError


@dataclass
class Session:
    session_id: bytes
    username_norm: bytes = b""
    client_eph_pub: bytes = b""
    server_eph_pub: bytes = b""
    server_random: bytes = b""
    prk: bytes = b""
    keys: dict = field(default_factory=dict)
    transcript_state: bytes = b""     # rolling SHA-256 transcript snapshot
    salt: bytes = b""                 # T2 (== transcript prefix for VM/proofs)
    client_counter: int = 0           # last accepted client monotonic counter
    server_counter: int = 0           # next server outbound counter
    server_challenge2: bytes = b""
    vm_digest: bytes = b""
    proof1_ok: bool = False

    def next_server_counter(self) -> int:
        self.server_counter += 1
        return self.server_counter

    def accept_client_counter(self, counter: int) -> None:
        # Strict monotonic increase -> replay / reorder protection.
        if counter <= self.client_counter:
            raise ProtocolError("replay", "non-monotonic client counter")
        self.client_counter = counter


class SessionStore:
    MAX_SESSIONS = 1024

    def __init__(self) -> None:
        self._store: "OrderedDict[bytes, Session]" = OrderedDict()

    def create(self, session_id: bytes) -> Session:
        s = Session(session_id=session_id)
        self._store[session_id] = s
        self._store.move_to_end(session_id)
        while len(self._store) > self.MAX_SESSIONS:
            self._store.popitem(last=False)
        return s

    def get(self, session_id: bytes) -> Session:
        s = self._store.get(session_id)
        if s is None:
            raise ProtocolError("session", "unknown session")
        self._store.move_to_end(session_id)
        return s


# Module-level singleton used by the handlers.
STORE = SessionStore()
