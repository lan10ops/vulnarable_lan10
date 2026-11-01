# AI-authored regression test for finding fnd_e78890787c1096e0 (role: test_design, model: claude-sonnet-5-5).
# SENTINEL policy-checked it and ran it only in an isolated sandbox. Review it before merging.
import app as app_module
from app import admin_users


class _Cursor:
    def fetchall(self):
        return [{"id": 1, "username": "alice", "password": "HASH", "role": "admin"}]


class _FakeDB:
    def execute(self, *a, **k):
        return _Cursor()

    def commit(self):
        pass


def _status_and_body(result):
    body = result
    status = 200
    if isinstance(result, tuple):
        body = result[0]
        if len(result) > 1 and isinstance(result[1], int):
            status = result[1]
    elif hasattr(result, "status_code"):
        status = result.status_code
        body = result.get_data(as_text=True)
    return status, body


def test_client_supplied_admin_header_does_not_grant_access(monkeypatch):
    monkeypatch.setattr(app_module, "get_db", lambda: _FakeDB())
    with app_module.app.test_request_context("/admin/users", headers={"X-Admin": "true"}):
        result = admin_users()
    status, body = _status_and_body(result)
    assert status in (401, 403)
    assert "HASH" not in str(body)
    assert not (isinstance(body, dict) and "users" in body)


def test_no_credentials_forbidden(monkeypatch):
    monkeypatch.setattr(app_module, "get_db", lambda: _FakeDB())
    with app_module.app.test_request_context("/admin/users"):
        result = admin_users()
    status, body = _status_and_body(result)
    assert status in (401, 403)
    assert "HASH" not in str(body)
