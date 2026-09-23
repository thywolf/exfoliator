"""Server tests via the Flask test client (no real sockets)."""
import json
import re

import pytest

import client.client as c
import server.server as s

SECRET = "brass-gears-2026"
JS = json.dumps({"cmd": "test", "v": [1, 2, 3]})


@pytest.fixture
def app():
    return s.create_app()


@pytest.fixture
def t(app):
    return app.test_client()


def _number(html: bytes) -> int:
    m = re.search(rb'class="big">(\d+)<', html)
    assert m, "result number not rendered"
    return int(m.group(1))


def test_initial_page(t):
    r = t.get("/")
    assert r.status_code == 200
    for marker in (b'id="box"', b'id="go"', b'id="result"', b'id="rain"'):
        assert marker in r.data
    assert b'class="big"' not in r.data  # no number before first submit
    assert r.headers["Cache-Control"].startswith("no-store")


def test_query_params_ignored(t):
    r = t.get("/?text=hello&x=1")
    assert r.status_code == 200 and b'class="big"' not in r.data


def test_header_submit_shows_number(t):
    r = t.get("/", headers={s.HEADER_NAME: "hello entropy"})
    assert r.status_code == 200
    assert 0 <= _number(r.data) <= 999999
    assert b"bits/char" in r.data


def test_numbers_are_fresh(t):
    assert _number(t.get("/", headers={s.HEADER_NAME: "same"}).data) != \
           _number(t.get("/", headers={s.HEADER_NAME: "same"}).data)


def test_post_fallback_multiline_unicode(t):
    r = t.post("/", data={"entropy_input": "line1\nline2 caf\u00e9"})
    assert r.status_code == 200 and 0 <= _number(r.data) <= 999999


def test_json_branch_returns_only_random(t):
    r = t.get("/", headers={s.HEADER_NAME: "hello", "Accept": "application/json"})
    assert r.status_code == 200 and r.content_type.startswith("application/json")
    assert set(json.loads(r.data)) == {"random"}


def test_json_missing_input_is_400(t):
    r = t.get("/", headers={"Accept": "application/json"})
    assert r.status_code == 400 and "error" in json.loads(r.data)


def test_payload_calls_dummy_html_and_json(t, monkeypatch):
    calls = []
    monkeypatch.setattr(s, "dummy", lambda d: (calls.append(d), d)[1])
    p = c.encode_payload(JS)
    r = t.get("/", headers={s.HEADER_NAME: p})
    assert calls == [JS] and b"dummy" in r.data and b'class="big"' in r.data
    r = t.get("/", headers={s.HEADER_NAME: p, "Accept": "application/json"})
    assert calls == [JS, JS] and set(json.loads(r.data)) == {"random"}


def test_secret_payload_end_to_end(t, monkeypatch):
    monkeypatch.setenv("PAYLOAD_SECRET", SECRET)
    calls = []
    monkeypatch.setattr(s, "dummy", lambda d: (calls.append(d), d)[1])
    p = c.encode_payload(JS, secret=SECRET)
    t.get("/", headers={s.HEADER_NAME: p, "Accept": "application/json"})
    assert calls == [JS]


def test_wrong_or_missing_secret_no_dummy(t, monkeypatch):
    calls = []
    monkeypatch.setattr(s, "dummy", lambda d: (calls.append(d), d)[1])
    p = c.encode_payload(JS, secret=SECRET)
    monkeypatch.setenv("PAYLOAD_SECRET", "wrong-secret")
    t.get("/", headers={s.HEADER_NAME: p})
    assert calls == []
    monkeypatch.delenv("PAYLOAD_SECRET")
    t.get("/", headers={s.HEADER_NAME: p})
    assert calls == []


def test_custom_path(monkeypatch):
    monkeypatch.setenv("ENTROPY_PATH", "/random")
    t2 = s.create_app().test_client()
    assert t2.get("/random").status_code == 200
    assert t2.get("/").status_code == 404


def test_entropy_math():
    assert s.shannon_entropy("") == (0.0, 0.0)
    per, tot = s.shannon_entropy("aaaa")
    assert per == 0.0 and tot == 0.0
    per, tot = s.shannon_entropy("ab")
    assert per == pytest.approx(1.0) and tot == pytest.approx(2.0)


def test_generate_number_range():
    for _ in range(50):
        assert 0 <= s.generate_number("x") <= 999999
