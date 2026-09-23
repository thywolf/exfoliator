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


def _answer(html: bytes) -> str:
    m = re.search(rb'class="big(?:\s+\w+)?">([^<]+)<', html)
    assert m, "oracle answer not rendered"
    return m.group(1).decode("utf-8")


def test_initial_page(t):
    r = t.get("/")
    assert r.status_code == 200
    for marker in (b'id="box"', b'id="go"', b'id="result"', b'id="stars"'):
        assert marker in r.data
    assert b'class="moon"' in r.data
    assert b'rel="icon"' in r.data and b"data:image/svg+xml" in r.data
    assert b'class="big' not in r.data  # no answer before first submit
    assert r.headers["Cache-Control"].startswith("no-store")


def test_query_params_ignored(t):
    r = t.get("/?text=hello&x=1")
    assert r.status_code == 200 and b'class="big' not in r.data


def test_header_submit_shows_answer(t):
    r = t.get("/", headers={s.HEADER_NAME: "will it rain tomorrow?"})
    assert r.status_code == 200
    assert _answer(r.data) in dict(s.ANSWERS)
    assert b"bits/" not in r.data  # no lab-coat units on the page
    m = re.search(rb'id="entropy">([^<]*)<', r.data)
    assert m and m.group(1).strip()  # a mood line is shown instead


def test_mood_line_tiers():
    assert s.mood_line("") == ""
    assert s.mood_line("aaaa") == "The veil barely stirs... lend the oracle more words."
    assert s.mood_line("abcdefghij") == "Faint whispers gather in the dark."
    assert s.mood_line("abcdefghij" * 4) == "The mists thicken - the vision sharpens."
    assert s.mood_line("The quick brown fox jumps over the lazy dog! " * 5) == \
        "The cosmos roars - the vision is crystal clear."


def test_answers_drawn_from_table(t):
    seen = {_answer(t.get("/", headers={s.HEADER_NAME: "same"}).data) for _ in range(60)}
    assert seen <= set(dict(s.ANSWERS)) and len(seen) > 1


def test_post_fallback_multiline_unicode(t):
    r = t.post("/", data={"entropy_input": "line1\nline2 caf\u00e9"})
    assert r.status_code == 200 and _answer(r.data) in dict(s.ANSWERS)


def test_json_branch_returns_only_answer(t):
    r = t.get("/", headers={s.HEADER_NAME: "hello", "Accept": "application/json"})
    assert r.status_code == 200 and r.content_type.startswith("application/json")
    data = json.loads(r.data)
    assert set(data) == {"answer"} and data["answer"] in dict(s.ANSWERS)


def test_json_missing_input_is_400(t):
    r = t.get("/", headers={"Accept": "application/json"})
    assert r.status_code == 400 and "error" in json.loads(r.data)


def test_payload_calls_dummy_html_and_json(t, monkeypatch):
    calls = []
    monkeypatch.setattr(s, "dummy", lambda d: (calls.append(d), d)[1])
    p = c.encode_payload(JS)
    r = t.get("/", headers={s.HEADER_NAME: p})
    assert calls == [JS] and b'class="big' in r.data
    assert b"dummy" not in r.data and b"payload" not in r.data.lower()
    assert JS.encode() not in r.data  # decoded content leaves no trace
    r = t.get("/", headers={s.HEADER_NAME: p, "Accept": "application/json"})
    assert calls == [JS, JS] and set(json.loads(r.data)) == {"answer"}


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


def test_answer_table_shape():
    assert len(s.ANSWERS) == 40
    cats = [c for _, c in s.ANSWERS]
    assert cats.count("positive") == 20 and cats.count("neutral") == 10
    assert cats.count("negative") == 10
    assert len({t for t, _ in s.ANSWERS}) == 40  # all phrasings unique


def test_generate_answer_valid():
    table = dict(s.ANSWERS)
    seen = set()
    for _ in range(60):
        answer, category = s.generate_answer("x")
        assert table[answer] == category
        seen.add(answer)
    assert len(seen) > 1
