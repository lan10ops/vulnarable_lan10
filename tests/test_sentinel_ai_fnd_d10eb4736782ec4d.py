# AI-authored regression test for finding fnd_d10eb4736782ec4d (role: test_design, model: claude-sonnet-5-5).
# SENTINEL policy-checked it and ran it only in an isolated sandbox. Review it before merging.
import subprocess
import pytest
from app import ping
import app as app_module


def _run(monkeypatch, host):
    calls = []

    def fake(*args, **kwargs):
        calls.append((args, kwargs))
        return b"ok"

    monkeypatch.setattr(app_module.subprocess, "check_output", fake)
    for name in ("run", "Popen", "call", "check_call"):
        monkeypatch.setattr(app_module.subprocess, name, lambda *a, _n=name, **k: calls.append((a, k)) or (_ for _ in ()).throw(RuntimeError("blocked")))
    client = app_module.app.test_client()
    try:
        client.get("/ping", query_string={"host": host})
    except Exception:
        pass
    return calls


def test_ping_does_not_use_shell_with_untrusted_host(monkeypatch):
    payload = "127.0.0.1; echo INJECTED"
    calls = _run(monkeypatch, payload)
    for args, kwargs in calls:
        cmd = args[0] if args else kwargs.get("args")
        if kwargs.get("shell"):
            # if a shell is used, the payload must not appear in the command string
            assert payload not in str(cmd)
            assert ";" not in str(cmd)
        if isinstance(cmd, str) and not kwargs.get("shell"):
            assert ";" not in cmd


def test_ping_host_is_separate_argument_or_rejected(monkeypatch):
    payload = "127.0.0.1; echo INJECTED"
    calls = _run(monkeypatch, payload)
    for args, kwargs in calls:
        cmd = args[0] if args else kwargs.get("args")
        assert not isinstance(cmd, str), "command must be an argument list, not a string"
        assert not kwargs.get("shell")
        # injected text must not be interpreted: either never passed or kept as single item
        assert "echo" not in [str(x) for x in cmd]
