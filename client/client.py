# client/client.py
"""Client module: compress + base63-encode a JSON string and GET it to the server.

Usage from another script::

    import client.client as client  # or add client/ to sys.path and ``import client``
    answer = client.main('{"hello": "world"}')  # -> str, server sends {"answer": "..."}

Only the allowed charset is used on the wire: payload body ``a-z A-Z 0-9``
plus space (base63); leading checksum word ``a-z A-Z 0-9`` only (base62).
No URL query parameters are used -- the payload travels in the
``X-Entropy-Input`` header, simulating the regular browser request.

Shortness: the JSON is compressed with every available compressor
(zlib-9, bz2-9, lzma-9, raw) and the shortest base63 body wins; the server
trial-decompresses, so no method marker is needed (0 overhead).

Secrecy: with a secret word (``secret`` arg or ``PAYLOAD_SECRET`` env, also
configured server-side) the compressed bytes are XOR-scrambled with a
SHA-256-CTR keystream first -- identical length, but base63-decoding no longer
reveals anything decompressible.
"""
import argparse
import bz2
import hashlib
import json
import lzma
import os
import urllib.request
import zlib

ALPHABET63 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
ALPHABET62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B63 = [255] * 256  # byte -> base63 value, 255 = invalid (fast table decode)
for _i, _ch in enumerate(ALPHABET63):
    _B63[ord(_ch)] = _i
HEADER_NAME = "X-Entropy-Input"
CHECKSUM_LEN = 6
MAX_STRIPPED_SPACES = 8


# ------------------------------------------------------------ base63 / base62
def base63_encode(blob: bytes) -> str:
    """Encode bytes to base63 (big-int; leading 0x00 -> 'a', bitcoin-style)."""
    if not blob:
        return ""
    n_leading = len(blob) - len(blob.lstrip(b"\x00"))
    if n_leading == len(blob):
        return ALPHABET63[0] * len(blob)
    num = int.from_bytes(blob, "big")
    out = []
    while num:
        num, r = divmod(num, 63)
        out.append(ALPHABET63[r])
    return ALPHABET63[0] * n_leading + "".join(reversed(out))


def base63_decode(body: str) -> bytes:
    if body == "":
        return b""
    try:
        raw = body.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError(f"bad base63 body: {body[:20]!r}")
    n = 0
    for byte in raw:  # count leading 'a's (value 0); invalid bytes break out
        if _B63[byte] != 0:
            break
        n += 1
    num = 0
    for byte in raw[n:]:
        v = _B63[byte]
        if v == 255:
            raise ValueError(f"bad base63 char: {chr(byte)!r}")
        num = num * 63 + v
    return b"\x00" * n + num.to_bytes((num.bit_length() + 7) // 8, "big")


def _encode_base62(num: int, width: int = CHECKSUM_LEN) -> str:
    if num == 0:
        s = ALPHABET62[0]
    else:
        out = []
        while num:
            num, r = divmod(num, 62)
            out.append(ALPHABET62[r])
        s = "".join(reversed(out))
    return s.rjust(width, ALPHABET62[0])


def checksum_word(body: str) -> str:
    """Short checksum: CRC32 of the base63 body, base62-encoded (6 chars)."""
    return _encode_base62(zlib.crc32(body.encode("utf-8")) & 0xFFFFFFFF)


# ------------------------------------------------------------ secret scramble
def _keystream(secret: str, length: int) -> bytes:
    """SHA-256-CTR keystream of exactly *length* bytes (no expansion)."""
    key = hashlib.sha256(secret.encode("utf-8")).digest()
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _scramble(blob: bytes, secret: str) -> bytes:
    """XOR stream layer (its own inverse); hides the compressed magic bytes."""
    ks = _keystream(secret, len(blob))
    return bytes(b ^ k for b, k in zip(blob, ks))


def _payload_secret(explicit: str | None) -> str:
    if explicit is not None:
        return explicit
    return os.environ.get("PAYLOAD_SECRET", "")


# ------------------------------------------------------------ compress / pack
def _candidates(raw: bytes) -> dict[str, bytes]:
    cands: dict[str, bytes] = {}
    cands["zlib"] = zlib.compress(raw, 9)
    try:
        cands["bz2"] = bz2.compress(raw, 9)
    except Exception:
        pass
    try:
        cands["lzma"] = lzma.compress(raw, preset=9)
    except Exception:
        pass
    cands["raw"] = raw
    return cands


def candidate_lengths(json_string: str, secret: str | None = None) -> dict[str, int]:
    """Base63 body length per compressor; ``encode_payload`` ships the shortest."""
    raw = json_string.encode("utf-8")
    key = _payload_secret(secret)
    out = {}
    for name, blob in _candidates(raw).items():
        if key:
            blob = _scramble(blob, key)
        out[name] = len(base63_encode(blob))
    return out


def _body_len_lower_bound(blob: bytes) -> int:
    """Proven lower bound on the base63 body length (exact integer math).

    Lets ``encode_payload`` skip big-int-encoding compressors that cannot beat
    the current best; the shipped body is identical to encoding everything.
    """
    stripped = blob.lstrip(b"\x00")
    leading = len(blob) - len(stripped)
    if not stripped:
        return len(blob)  # all zeros -> 'a' * len
    # stripped[0] != 0, so value >= 256**(L-1): bit length >= 8*L-7, and each
    # base63 digit holds < 6 bits -> digits >= (bitlen-1)//6 + 1.
    return leading + (8 * len(stripped) - 8) // 6 + 1


def encode_payload(json_string: str, secret: str | None = None) -> str:
    """Compress + base63-encode *json_string*; return ``'<checksum> <body>'``.

    Tries zlib-9 / bz2-9 / lzma-9 / raw and ships the shortest body; hopeless
    candidates are skipped via the proven bound above (same result, less work).
    If *secret* (or the ``PAYLOAD_SECRET`` env var) is set, every candidate is
    XOR-scrambled before encoding, so the shipped body is still the true
    minimum -- while base63-decoding reveals nothing decompressible.
    """
    json.loads(json_string)  # validate early; keep original string verbatim
    raw = json_string.encode("utf-8")
    key = _payload_secret(secret)
    best_body = None
    for blob in _candidates(raw).values():  # dict order: first minimal wins ties
        if key:
            blob = _scramble(blob, key)
        if best_body is not None and _body_len_lower_bound(blob) >= len(best_body):
            continue
        body = base63_encode(blob)
        if best_body is None or len(body) < len(best_body):
            best_body = body
    return f"{checksum_word(best_body)} {best_body}"


def decode_payload(payload: str, secret: str | None = None) -> str:
    """Inverse of encode_payload (tolerates header-stripped trailing spaces).

    Tries the body as-is, then XOR-descrambled with *secret* (or the
    ``PAYLOAD_SECRET`` env var); returns the first result that is valid JSON.
    """
    first, rest = payload.split(" ", 1)
    crc = zlib.crc32(rest.encode("utf-8")) & 0xFFFFFFFF
    body = None
    for k in range(MAX_STRIPPED_SPACES + 1):
        if _encode_base62(crc) == first:
            body = rest + " " * k
            break
        crc = zlib.crc32(b" ", crc) & 0xFFFFFFFF
    if body is None:
        raise ValueError("checksum mismatch")
    blob = base63_decode(body)
    key = _payload_secret(secret)
    cands = [blob] + ([_scramble(blob, key)] if key else [])
    for cand in cands:
        for fn in (zlib.decompress, bz2.decompress, lzma.decompress):
            try:
                text = fn(cand).decode("utf-8")
                break
            except Exception:
                continue
        else:
            try:
                text = cand.decode("utf-8")
            except Exception:
                continue
        try:
            json.loads(text)
        except Exception:
            continue
        return text
    raise ValueError("payload unreadable (wrong secret?)")


# ------------------------------------------------------------------ transport
def _server_path(path: str | None) -> str:
    if path:
        return path if path.startswith("/") else "/" + path
    for var in ("ENTROPY_PATH", "APP_PATH", "BASE_PATH", "ROUTE_PATH"):
        val = os.environ.get(var, "").strip()
        if val:
            return val if val.startswith("/") else "/" + val
    return "/"


def send_payload(payload: str, server_url: str | None = None,
                 path: str | None = None, timeout: int = 15,
                 accept_json: bool = True) -> str:
    """GET *server_url+path* with the payload in the header (no query params).

    With ``accept_json=True`` (default) asks for ``Accept: application/json``
    and returns the server's oracle answer as str. With ``accept_json=False``
    returns the full webpage HTML (regular browser-style response).
    """
    base = (server_url or os.environ.get("SERVER_URL", "http://127.0.0.1:5000")).rstrip("/")
    url = base + _server_path(path)
    headers = {HEADER_NAME: payload}
    if accept_json:
        headers["Accept"] = "application/json"
    req = urllib.request.Request(url, method="GET", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", "replace")
    if accept_json:
        return str(json.loads(body)["answer"])
    return body


def main(json_string: str, server_url: str | None = None,
         path: str | None = None, timeout: int = 15,
         accept_json: bool = True, secret: str | None = None) -> str:
    """Compress, encode and send *json_string*; return the server's oracle answer.

    *secret* (else the ``PAYLOAD_SECRET`` env var) XOR-scrambles the compressed
    bytes before encoding; the server must be configured with the same secret.
    """
    return send_payload(encode_payload(json_string, secret), server_url, path, timeout, accept_json)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Send a JSON string as compressed payload.")
    ap.add_argument("json_string", help='JSON string, e.g. \'{"a": 1}\'')
    ap.add_argument("--server-url", default=None)
    ap.add_argument("--path", default=None)
    ap.add_argument("--print-payload", action="store_true")
    ap.add_argument("--secret", default=None, help="secret word (else PAYLOAD_SECRET env)")
    args = ap.parse_args()
    payload = encode_payload(args.json_string, args.secret)
    if args.print_payload:
        print(payload)
    else:
        print(f"payload ({len(payload)} chars)")
    print(send_payload(payload, args.server_url, args.path))
