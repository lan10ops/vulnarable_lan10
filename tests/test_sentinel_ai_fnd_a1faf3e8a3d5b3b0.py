# AI-authored regression test for finding fnd_a1faf3e8a3d5b3b0 (role: test_design, model: claude-sonnet-5-5).
# SENTINEL policy-checked it and ran it only in an isolated sandbox. Review it before merging.
import os
import sys

from app import calc  # noqa: F401
import app as appmod


def _get(expr):
    client = appmod.app.test_client()
    return client.get("/calc", query_string={"expr": expr})


def test_calc_does_not_execute_arbitrary_python():
    pid = str(os.getpid())
    resp = _get("__import__('os').getpid()")
    body = resp.get_data(as_text=True)
    assert pid not in body


def test_calc_has_no_side_effects_from_expression():
    marker = "sentinel_rce_marker"
    sys.modules.pop(marker, None)
    try:
        _get("__import__('sys').modules.__setitem__('sentinel_rce_marker', 1)")
        assert marker not in sys.modules
    finally:
        sys.modules.pop(marker, None)


def test_calc_still_does_simple_arithmetic():
    resp = _get("1+1")
    assert resp.status_code == 200
    assert resp.get_data(as_text=True).strip() == "2"
