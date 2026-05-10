"""Deterministic semantic probes — static analysis of proposed actions.

These probes inspect an :class:`~cordon.core.types.Action`'s code/file/URL
payload without executing it. They are fast (< 10ms), deterministic, and
LLM-free. This is the "Semantic Guard" suite that closes the detection
gap on semantic attacks (supply-chain, silent failure, exfiltration,
test tampering, security weakening, secret leak).

Public probe classes:

* :class:`TyposquatProbe`
* :class:`SecretLeakProbe`

Stubs (coming in v0.2): ``SilentFailureProbe``, ``ExfiltrationProbe``,
``TestSuppressionProbe``, ``SecurityWeakeningProbe``.
"""

from .secret_leak import SecretLeakProbe
from .typosquat import TyposquatProbe

__all__ = ["TyposquatProbe", "SecretLeakProbe"]
