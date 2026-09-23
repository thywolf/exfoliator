# client/example.py
"""Example: test JSON transmission to the server.

Default sample is a representative sensor-readings JSON of exactly 2048 bytes,
so you can see compression at work: the example prints the base63 body length
per compressor (zlib-9 / bz2-9 / lzma-9 / raw) and the client ships the
shortest one, plus a 6-char checksum word and one space separator.

Full path: JSON string -> compress + base63-encode -> GET with the payload in
the ``X-Entropy-Input`` header, ``Accept: application/json`` -> server
decodes/decompresses, passes it to ``dummy()``, and returns ``{"answer": "..."}``.

Prerequisites: the server must be running, e.g.::

    uv run python -m server.server

Run (optionally pass your own JSON and server URL)::

    uv run python client/example.py
    uv run python client/example.py '{"hello": "world"}'
    uv run python client/example.py '{"a": 1}' http://127.0.0.1:5000

With a secret word set (same value server-side), the compressed bytes are
XOR-scrambled first -- identical payload length, but base63-decoding no longer
reveals anything decompressible::

    PAYLOAD_SECRET=brass-gears-2026 uv run python client/example.py
"""
import bz2
import json
import lzma
import os
import sys
import urllib.error
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.client import base63_decode, candidate_lengths, decode_payload, encode_payload, main

DEFAULT_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:5000")
SAMPLE_BYTES = 2048


def sample_2048() -> str:
    """Representative ASCII JSON of exactly 2048 bytes (compact separators)."""
    items = [
        {"id": i, "sensor": "alpha", "active": True,
         "v": [round(i * 1.5, 2), round(i * 2.5, 2)], "u": "celsius"}
        for i in range(24)
    ]
    doc = {"station": "warehouse-7", "readings": items, "pad": ""}
    need = SAMPLE_BYTES - len(json.dumps(doc, separators=(",", ":")).encode("utf-8"))
    assert need > 0, "sample skeleton exceeds 2048 bytes"
    doc["pad"] = "x" * need
    out = json.dumps(doc, separators=(",", ":"))
    assert len(out.encode("utf-8")) == SAMPLE_BYTES, len(out.encode("utf-8"))
    return out


def transmit(data, server_url=DEFAULT_URL):
    """Send *data* (JSON-serializable object or JSON string); return the oracle answer."""
    json_string = data if isinstance(data, str) else json.dumps(data)
    json.loads(json_string)  # fail fast on invalid JSON
    raw = len(json_string.encode("utf-8"))
    payload = encode_payload(json_string)
    assert decode_payload(payload) == json_string, "local roundtrip failed"
    secret = os.environ.get("PAYLOAD_SECRET", "")
    stats = candidate_lengths(json_string, secret or None)
    best = min(stats, key=stats.get)
    print(f"json     ({raw} bytes)")
    print("compressor -> base63 body length:")
    for name, length in stats.items():
        print(f"  {name:<5} {length}{'   <-- shipped' if name == best else ''}")
    print(f"payload  ({len(payload)} chars = body + 6-char checksum + 1 space)")
    print(f"ratio: {len(payload) / raw:.3f}x of original "
          f"({100 * (1 - len(payload) / raw):.1f}% smaller)")
    print(f"secret scrambling: {'ON' if secret else 'OFF'}")
    if secret:
        blob = base63_decode(payload.split(" ", 1)[1])
        for name, fn in (("zlib", zlib.decompress), ("bz2", bz2.decompress),
                         ("lzma", lzma.decompress)):
            try:
                fn(blob)
                print(f"WARNING: body decompresses directly as {name}!")
                break
            except Exception:
                continue
        else:
            print("body does not decompress directly: scrambling layer holds")
    number = main(json_string, server_url=server_url)
    print(f"server answer: {number}")
    return number


if __name__ == "__main__":
    sample = sys.argv[1] if len(sys.argv) > 1 else sample_2048()
    url = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_URL
    try:
        transmit(sample, url)
    except urllib.error.URLError as exc:
        sys.exit(f"cannot reach server at {url} ({exc}). Is it running? Try: uv run python -m server.server")
