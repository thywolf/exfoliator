"""Codec unit tests: base63/62, checksum, scramble, pick-optimality. No HTTP."""
import bz2
import json
import lzma
import random
import zlib

import pytest

import client.client as c
import server.server as s
from client.example import sample_2048

SECRET = "brass-gears-2026"
SMALL = json.dumps({"name": "ada", "id": 7, "active": True})
MEDIUM = json.dumps({"user": "ada", "id": 7, "roles": ["admin", "dev"], "note": "x" * 200})


def _rand_bytes(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def test_base63_roundtrip_both_sides():
    rng = random.Random(1234)
    vectors = [b"", b"\x00", b"\x00\x00\x00", b"\x00\x01\x02", b"hello",
               bytes(range(256)), _rand_bytes(rng, 64), _rand_bytes(rng, 1024)]
    for blob in vectors:
        body = c.base63_encode(blob)
        assert set(body) <= set(c.ALPHABET63)
        assert c.base63_decode(body) == blob
        assert s.base63_decode(body) == blob  # same codec, both components


def test_base63_rejects_bad_input():
    with pytest.raises(ValueError):
        c.base63_decode("abc!")
    with pytest.raises(ValueError):
        s.base63_decode("h\xe9llo")


def test_checksum_word_shape():
    for mod in (c, s):
        w = mod.checksum_word("some body")
        assert len(w) == 6 and set(w) <= set(mod.ALPHABET62)
        assert mod.checksum_word("some body") == w  # deterministic


def test_scramble_involution_and_scope():
    blob = _rand_bytes(random.Random(3), 300)
    assert c._scramble(c._scramble(blob, "s3cret"), "s3cret") == blob
    assert s._scramble(blob, "s3cret") == c._scramble(blob, "s3cret")  # shared construction
    assert len(c._scramble(blob, "k")) == len(blob)  # byte length preserved
    assert c._scramble(blob, "a") != c._scramble(blob, "b")


def test_roundtrip_battery():
    for js in (SMALL, MEDIUM,
               json.dumps({"u": "caf\u00e9 \u00fcn\u00efcod\u00e9 \u6f22\u5b57"}),
               json.dumps({"zeros": "\u0000\u0000abc"}),
               sample_2048()):
        p = c.encode_payload(js)
        first, rest = p.split(" ", 1)
        assert " " not in first and set(first) <= set(c.ALPHABET62)
        assert set(rest) <= set(c.ALPHABET63)
        assert c.decode_payload(p) == js
        back, _ = s.extract_payload(p)
        assert back == js


def test_shipped_body_is_minimal_plain_and_secret():
    for js in (SMALL, MEDIUM, sample_2048()):
        for secret in (None, SECRET):
            got = c.encode_payload(js, secret=secret).split(" ", 1)[1]
            key = secret or ""
            brute = min(
                (c.base63_encode(c._scramble(b, key) if key else b)
                 for b in c._candidates(js.encode("utf-8")).values()),
                key=len,
            )
            assert got == brute


def test_candidate_lengths_match_shipped():
    stats = c.candidate_lengths(MEDIUM)
    assert set(stats) == {"zlib", "bz2", "lzma", "raw"}
    shipped = c.encode_payload(MEDIUM).split(" ", 1)[1]
    assert len(shipped) == min(stats.values())


def test_lower_bound_never_exceeds():
    rng = random.Random(42)
    blobs = [_rand_bytes(rng, n) for n in (1, 2, 5, 64, 300)]
    blobs += [b"\x00" * 10, b"\x00\x00hello", b"\x00" * 200 + b"A" * 50]
    for blob in blobs:
        assert c._body_len_lower_bound(blob) <= len(c.base63_encode(blob))


def test_checksum_tamper_detected():
    p = c.encode_payload(SMALL)
    first, rest = p.split(" ", 1)
    bad = f"{first} {rest[:-1]}{'b' if rest[-1] != 'b' else 'c'}"
    with pytest.raises(ValueError):
        c.decode_payload(bad)
    assert s.extract_payload(bad) == (None, None)


def test_trailing_space_recovery():
    payload = js = None
    for i in range(60000):  # deterministic search; zlib output is stable
        cand = c.encode_payload(json.dumps({"i": i}))
        if cand.endswith(" "):
            payload, js = cand, json.dumps({"i": i})
            break
    assert payload is not None
    assert c.decode_payload(payload.rstrip(" ")) == js
    back, _ = s.extract_payload(payload.rstrip(" "))
    assert back == js


@pytest.mark.parametrize("text", ["", "nospacehere", "hello world",
                                  "ABCDEF also not a payload body", "x "])
def test_non_payload_rejected(text):
    assert s.extract_payload(text) == (None, None)


def test_secret_roundtrip_and_hiding(monkeypatch):
    monkeypatch.setenv("PAYLOAD_SECRET", SECRET)
    p = c.encode_payload(MEDIUM, secret=SECRET)
    assert c.decode_payload(p) == MEDIUM
    back, _ = s.extract_payload(p)
    assert back == MEDIUM
    blob = c.base63_decode(p.split(" ", 1)[1])
    for fn in (zlib.decompress, bz2.decompress, lzma.decompress):
        with pytest.raises(Exception):
            fn(blob)


def test_wrong_secret_rejected(monkeypatch):
    monkeypatch.setenv("PAYLOAD_SECRET", "wrong-secret")
    p = c.encode_payload(MEDIUM, secret=SECRET)
    assert s.extract_payload(p) == (None, None)
    with pytest.raises(ValueError):
        c.decode_payload(p)


def test_no_secret_ignores_scrambled():
    p = c.encode_payload(MEDIUM, secret=SECRET)
    assert s.extract_payload(p) == (None, None)  # env has no secret (see conftest)


def test_sample_2048_exact_size():
    assert len(sample_2048().encode("utf-8")) == 2048
