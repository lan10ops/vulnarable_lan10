# AI-authored regression test for finding fnd_fab8be6d800493db (role: test_design, model: claude-sonnet-5-5).
# SENTINEL policy-checked it and ran it only in an isolated sandbox. Review it before merging.
import os
import sys

import pytest

from app import import_config


def _flask_app():
    return sys.modules[import_config.__module__].app


def test_import_config_rejects_python_object_tags():
    payload = b"!!python/object/apply:os.getpid []\n"
    flask_app = _flask_app()
    result = None
    raised = False
    with flask_app.test_request_context("/import-config", method="POST", data=payload,
                                        content_type="application/x-yaml"):
        try:
            result = import_config()
        except Exception:
            raised = True
    if raised:
        # Safe loader refused the python-specific tag: secure behaviour.
        return
    text = repr(result)
    pid = str(os.getpid())
    if isinstance(result, dict):
        assert result.get("config") != pid
    assert ("'config': '%s'" % pid) not in text


def test_import_config_still_parses_plain_yaml():
    flask_app = _flask_app()
    with flask_app.test_request_context("/import-config", method="POST", data=b"a: 1\nb: [x, y]\n",
                                        content_type="application/x-yaml"):
        result = import_config()
    assert isinstance(result, dict)
    assert "a" in result["config"]
