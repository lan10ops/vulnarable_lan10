# AI-authored regression test for finding fnd_6d05c6e99cab43c1 (role: test_design, model: claude-sonnet-5-5).
# SENTINEL policy-checked it and ran it only in an isolated sandbox. Review it before merging.
import os
import pytest

import app as app_module
from app import download


def _to_bytes(result):
    if isinstance(result, tuple):
        result = result[0]
    if isinstance(result, bytes):
        return result
    if isinstance(result, str):
        return result.encode()
    if hasattr(result, 'get_data'):
        return result.get_data()
    return str(result).encode()


def _call(query):
    with app_module.app.test_request_context('/download', query_string=query):
        try:
            return _to_bytes(download())
        except Exception:
            # Rejecting the request (abort/exception) is a secure outcome
            return b''


@pytest.fixture
def layout(tmp_path, monkeypatch):
    upload = tmp_path / 'uploads'
    upload.mkdir()
    (upload / 'welcome.txt').write_bytes(b'hello')
    secret = tmp_path / 'secret.txt'
    secret.write_bytes(b'TOP-SECRET-CONTENT')
    monkeypatch.setattr(app_module, 'UPLOAD_DIR', str(upload))
    return upload, secret


def test_relative_traversal_blocked(layout):
    upload, secret = layout
    body = _call({'file': '../secret.txt'})
    assert b'TOP-SECRET-CONTENT' not in body


def test_nested_traversal_blocked(layout):
    upload, secret = layout
    body = _call({'file': 'sub/../../secret.txt'})
    assert b'TOP-SECRET-CONTENT' not in body


def test_absolute_path_blocked(layout):
    upload, secret = layout
    body = _call({'file': str(secret)})
    assert b'TOP-SECRET-CONTENT' not in body
