"""Error handling for RankGate Insane.

CRITICAL DESIGN RULE (spec stage requirement):
Every validation failure -- regardless of which of the 7 stages failed --
must surface to the network as the SAME generic response:

    {"ok": false, "error": "invalid proof"}

We never leak which stage failed, never leak whether the username, license,
proof, VM digest, transcript MAC, or second proof was the problem. Internally
we carry a stage tag for *server-side logging only* (never serialized to the
client) so the challenge author can debug, but the wire response is constant.
"""

from __future__ import annotations

from dataclasses import dataclass


# The single, constant, public-facing failure body. Do not vary this.
GENERIC_ERROR = {"ok": False, "error": "invalid proof"}


@dataclass
class ProofError(Exception):
    """Raised anywhere validation fails.

    `stage` and `detail` are for local logging ONLY and must never be placed
    in an HTTP response body. The handler layer catches this and emits the
    constant GENERIC_ERROR.
    """

    stage: str
    detail: str = ""

    def __str__(self) -> str:  # pragma: no cover - debugging aid only
        return f"ProofError(stage={self.stage!r}, detail={self.detail!r})"


class ProtocolError(ProofError):
    """Malformed frame / bad magic / replay / decrypt failure.

    Subclass of ProofError so it collapses to the same generic response, but
    distinguishable in local logs.
    """
