"""Tests for SecurityWeakeningProbe."""

from __future__ import annotations

from cordon import Action
from cordon.core.types import Severity
from cordon.probes.semantic import SecurityWeakeningProbe


probe = SecurityWeakeningProbe()


# ─── TLS disabled ─────────────────────────────────────────────────────────────


def test_verify_false_dangerous() -> None:
    old = "requests.get(url)\n"
    new = "requests.get(url, verify=False)\n"
    result = probe.analyze(Action(
        kind="file",
        changes={"client.py": new},
        workspace_files={"client.py": old},
    ))
    assert result.severity is Severity.DANGEROUS


def test_curl_insecure_flag_dangerous() -> None:
    result = probe.analyze(Action(
        kind="shell",
        command="curl -k https://api.example.com/data",
    ))
    assert result.severity is Severity.DANGEROUS


def test_node_tls_env_zero_dangerous() -> None:
    result = probe.analyze(Action(
        kind="shell",
        command="NODE_TLS_REJECT_UNAUTHORIZED=0 node app.js",
    ))
    assert result.severity is Severity.DANGEROUS


def test_existing_verify_false_unchanged_safe() -> None:
    code = "requests.get(url, verify=False)\n"
    result = probe.analyze(Action(
        kind="file",
        changes={"client.py": code},
        workspace_files={"client.py": code},  # unchanged delta
    ))
    assert result.severity is Severity.SAFE


# ─── Auth weakening ───────────────────────────────────────────────────────────


def test_git_push_no_verify_dangerous() -> None:
    result = probe.analyze(Action(
        kind="shell",
        command="git push origin main --no-verify",
    ))
    assert result.severity is Severity.DANGEROUS


def test_iam_wildcard_action_dangerous() -> None:
    old = '{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:..."}\n'
    new = '{"Effect": "Allow", "Action": "*", "Resource": "*"}\n'
    result = probe.analyze(Action(
        kind="file",
        changes={"policy.json": new},
        workspace_files={"policy.json": old},
    ))
    assert result.severity is Severity.DANGEROUS


# ─── Dangerous primitives ─────────────────────────────────────────────────────


def test_subprocess_shell_true_dangerous() -> None:
    old = "subprocess.run(['ls', '-la'])\n"
    new = "subprocess.run('ls -la', shell=True)\n"
    result = probe.analyze(Action(
        kind="file",
        changes={"x.py": new},
        workspace_files={"x.py": old},
    ))
    assert result.severity is Severity.DANGEROUS


def test_eval_introduced_suspicious() -> None:
    old = "result = parse(expr)\n"
    new = "result = eval(expr)\n"
    result = probe.analyze(Action(
        kind="file",
        changes={"x.py": new},
        workspace_files={"x.py": old},
    ))
    assert result.severity is Severity.SUSPICIOUS


# ─── Privilege widening ───────────────────────────────────────────────────────


def test_chmod_777_dangerous() -> None:
    result = probe.analyze(Action(
        kind="shell",
        command="chmod -R 777 /app/data",
    ))
    assert result.severity is Severity.DANGEROUS


def test_k8s_privileged_true_dangerous() -> None:
    old = "securityContext:\n  privileged: false\n"
    new = "securityContext:\n  privileged: true\n"
    result = probe.analyze(Action(
        kind="file",
        changes={"k8s/pod.yaml": new},
        workspace_files={"k8s/pod.yaml": old},
    ))
    assert result.severity is Severity.DANGEROUS


# ─── Crypto downgrade ─────────────────────────────────────────────────────────


def test_md5_introduced_suspicious() -> None:
    old = "h = hashlib.sha256(pwd.encode()).hexdigest()\n"
    new = "h = hashlib.md5(pwd.encode()).hexdigest()\n"
    result = probe.analyze(Action(
        kind="file",
        changes={"auth.py": new},
        workspace_files={"auth.py": old},
    ))
    assert result.severity is Severity.SUSPICIOUS


def test_jwt_alg_none_dangerous() -> None:
    old = '{"alg": "RS256"}\n'
    new = '{"alg": "none"}\n'
    result = probe.analyze(Action(
        kind="file",
        changes={"jwt.json": new},
        workspace_files={"jwt.json": old},
    ))
    assert result.severity is Severity.DANGEROUS


# ─── Negatives ────────────────────────────────────────────────────────────────


def test_safe_change_unflagged() -> None:
    result = probe.analyze(Action(
        kind="file",
        changes={"x.py": "print('hello')\n"},
    ))
    assert result.severity is Severity.SAFE


def test_safe_shell_unflagged() -> None:
    result = probe.analyze(Action(kind="shell", command="ls -la"))
    assert result.severity is Severity.SAFE
