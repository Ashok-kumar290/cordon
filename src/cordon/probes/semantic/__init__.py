"""Deterministic semantic probes — static analysis of proposed actions.

These probes inspect an :class:`~cordon.core.types.Action`'s code/file/URL
payload without executing it. They are fast (< 10ms), deterministic, and
LLM-free. This is the "Semantic Guard" suite that closes the detection
gap on semantic attacks (supply-chain, silent failure, exfiltration,
test tampering, security weakening, secret leak).

Public probe classes (full Semantic Guard suite, v0.2):

* :class:`TyposquatProbe`           — supply-chain typosquat detection
* :class:`SecretLeakProbe`          — local exfiltration via artifact files
* :class:`SilentFailureProbe`       — bare-except / empty catch / shell mufflers
* :class:`ExfiltrationProbe`        — sensitive data over the network
* :class:`TestSuppressionProbe`     — skip markers / assertion deletion / CI tampering
* :class:`SecurityWeakeningProbe`   — TLS off, eval, chmod 777, crypto downgrade, etc.
"""

from .exfiltration import ExfiltrationProbe
from .secret_leak import SecretLeakProbe
from .security_weakening import SecurityWeakeningProbe
from .silent_failure import SilentFailureProbe
from .test_suppression import TestSuppressionProbe
from .typosquat import TyposquatProbe

__all__ = [
    "TyposquatProbe",
    "SecretLeakProbe",
    "SilentFailureProbe",
    "ExfiltrationProbe",
    "TestSuppressionProbe",
    "SecurityWeakeningProbe",
]
