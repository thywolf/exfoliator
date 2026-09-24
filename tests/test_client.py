"""Client tests, incl. live HTTP roundtrips against a real local server."""
import json
import threading

import pytest
from werkzeug.serving import make_server

import client.client as c
import server.server as s

SECRET = "brass-gears-2026"


@pytest.fixture
def live_url(monkeypatch):
    monkeypatch.setenv("ENTROPY_PATH", "/oracle")
    app = s.create_app()
    srv = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()
    thread.join(timeout=5)


def test_main_returns_answer(live_url):
    a = c.main(json.dumps({"live": True}), server_url=live_url)
    assert isinstance(a, str) and a in dict(s.ANSWERS)


def test_main_accepts_full_endpoint_url(live_url):
    answer = c.main(json.dumps({"live": True}), server_url=f"{live_url}/oracle")
    assert answer in dict(s.ANSWERS)


def test_main_accepts_trailing_slash_endpoint(live_url):
    answer = c.main(json.dumps({"live": True}), server_url=f"{live_url}/oracle/")
    assert answer in dict(s.ANSWERS)


def test_send_payload_sets_custom_user_agent(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"answer":"ok"}'

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["user_agent"] = request.get_header("User-agent")
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(c.urllib.request, "urlopen", fake_urlopen)
    assert c.send_payload("payload", server_url="https://example.test/oracle") == "ok"
    assert captured == {
        "url": "https://example.test/oracle",
        "user_agent": c.USER_AGENT,
        "timeout": 15,
    }


def test_request_url_rejects_query_parameters():
    with pytest.raises(ValueError):
        c._request_url("https://example.test/oracle?unexpected=1", None)


def test_main_with_secret_fires_server_dummy(live_url, monkeypatch):
    monkeypatch.setenv("PAYLOAD_SECRET", SECRET)
    calls = []
    monkeypatch.setattr(s, "dummy", lambda d: (calls.append(d), d)[1])
    js = json.dumps({"secret": "roundtrip"})
    a = c.main(js, server_url=live_url, secret=SECRET)
    assert isinstance(a, str) and a in dict(s.ANSWERS) and calls == [js]


def test_send_payload_html_variant(live_url):
    html = c.send_payload(c.encode_payload(json.dumps({"a": 1})),
                          server_url=live_url, accept_json=False)
    assert isinstance(html, str) and 'class="big' in html


def test_main_unreachable_raises():
    with pytest.raises(OSError):
        c.main(json.dumps({"a": 1}), server_url="http://127.0.0.1:1", timeout=5)
