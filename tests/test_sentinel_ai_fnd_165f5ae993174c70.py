# AI-authored regression test for finding fnd_165f5ae993174c70 (role: test_design, model: claude-sonnet-5-5).
# SENTINEL policy-checked it and ran it only in an isolated sandbox. Review it before merging.
import app as app_module
from app import fetch


class FakeResp:
    text = "ok"
    status_code = 200
    content = b"ok"


def test_fetch_does_not_disable_tls_verification(monkeypatch):
    calls = []

    def fake_get(*args, **kwargs):
        calls.append((args, kwargs))
        return FakeResp()

    monkeypatch.setattr(app_module.requests, "get", fake_get)
    flask_app = app_module.app
    with flask_app.test_request_context("/fetch?url=https://example.com/"):
        try:
            fetch()
        except Exception:
            pass
    assert calls, "requests.get was expected to be called"
    for args, kwargs in calls:
        assert kwargs.get("verify", True) is not False
        assert kwargs.get("verify", True) not in (0, None, "")
