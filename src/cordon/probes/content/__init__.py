"""Content-aware probes — parse file payloads rather than substring-matching.

Where ``cordon.probes.semantic`` looks at the *shape* of an action
(command strings, file paths, change-set keys), this family looks at
the *content* of file writes — parsing Python ASTs, package
manifests, base64-encoded blobs, and archive headers — to catch the
camouflage attack class documented in :doc:`/docs/threat-model`.

Each probe in this family targets one attack pattern:

* :class:`PythonASTProbe` — closes
  :ref:`threat-model:3.5` (Python files that compose
  ``os.system`` calls without the literal pattern appearing).
* :class:`PackageManifestProbe` — closes
  :ref:`threat-model:3.2` (requirements.txt etc. with
  non-canonical sources).
* :class:`Base64DecoderProbe` — closes
  :ref:`threat-model:3.4` (base64-encoded payloads in
  otherwise-binary files).
* :class:`ArchiveInspectorProbe` — flags zip-slip and other archive
  extraction attacks before the archive is unpacked.

All four probes are still deterministic and run in well under 10 ms
on typical payloads. They sit in the ``fast`` tier alongside the
semantic suite so the existing :meth:`cordon.Guard.strict` /
:meth:`Guard.default` / :meth:`Guard.permissive` constructors pick
them up automatically once they're registered.
"""

from cordon.probes.content.base64_decoder import Base64DecoderProbe
from cordon.probes.content.package_manifest import PackageManifestProbe
from cordon.probes.content.python_ast import PythonASTProbe

__all__ = ["Base64DecoderProbe", "PackageManifestProbe", "PythonASTProbe"]
