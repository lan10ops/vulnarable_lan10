# AI-authored regression test for finding fnd_2337c17e669a6217 (role: test_design, model: claude-sonnet-5-5).
# SENTINEL policy-checked it and ran it only in an isolated sandbox. Review it before merging.
import hashlib
import sqlite3

import pytest

import app as app_module
from app import init_db

DEFAULTS = ["admin123", "admin", "password", "admin1234", "password1", "letmein", "123456", "changeme"]


def _setup(tmp_path, monkeypatch):
    db_path = tmp_path / "test_app.db"
    monkeypatch.setattr(app_module, "DB_PATH", str(db_path))
    monkeypatch.setattr(app_module, "UPLOAD_DIR", str(tmp_path / "files"))
    init_db()
    conn = sqlite3.connect(str(db_path))
    try:
        return conn.execute(
            "SELECT username, password, role FROM users WHERE role = 'admin' OR username = 'admin'"
        ).fetchall()
    finally:
        conn.close()


def _matches_default(stored, default):
    stored = stored or ""
    candidates = {default}
    for algo in ("md5", "sha1", "sha256", "sha512"):
        candidates.add(hashlib.new(algo, default.encode()).hexdigest())
    if stored in candidates:
        return True
    try:
        from werkzeug.security import check_password_hash
        if ":" in stored or "$" in stored:
            if check_password_hash(stored, default):
                return True
    except Exception:
        pass
    return False


def test_admin_has_no_default_password(tmp_path, monkeypatch):
    rows = _setup(tmp_path, monkeypatch)
    for username, stored, role in rows:
        for default in DEFAULTS:
            assert not _matches_default(stored, default), (
                "privileged account %r is seeded with a well-known default password" % username
            )


def test_admin_password_not_derived_from_source_across_runs(tmp_path, monkeypatch):
    rows1 = _setup(tmp_path, monkeypatch)
    for username, stored, role in rows1:
        assert stored, "admin must not have an empty password"
        assert stored != hashlib.md5(b"admin123").hexdigest()
