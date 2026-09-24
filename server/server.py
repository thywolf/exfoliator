# server/server.py
"""Entropy oracle server (single GET endpoint, header-transported input).

Web interaction (regular use):
  1. GET the page (no header) -> empty question form.
  2. User types a question; JS shows Shannon entropy of the text live.
  3. User clicks "Ask the oracle"; JS re-issues GET with the
     textarea content in the ``X-Entropy-Input`` header (no URL query params).
  4. Server normalizes the question into sorted unique words, combines that
     key with the current local calendar day, and draws the same daily oracle
     answer for equivalent questions.

Payload interaction (from client/client.py):
  Identical HTTP round-trip. If the header text starts with a base62 checksum
  word matching the CRC32 of the remainder (base63 body, tolerating stripped
  trailing spaces), the body is base63-decoded, decompressed (zlib/bz2/lzma/raw
  trial) and the resulting JSON string is passed to ``dummy()``
  (see ``server/handlers.py`` — user logic lives there, not here).
  If ``PAYLOAD_SECRET`` is set, an XOR-descrambled variant (SHA-256-CTR
  keystream, same secret client-side) is tried too; the first valid JSON wins.
  The returned webpage is identical to the regular web flow.

Content negotiation: callers sending ``Accept: application/json`` (the python
client) receive only ``{"answer": "..."}`` instead of the HTML page; the entropy
use, answer draw and ``dummy()`` processing are identical.
"""
import bz2
import hashlib
import json
import lzma
import math
import os
import re
import zlib
from collections import Counter
from datetime import date

from dotenv import load_dotenv
from flask import Flask, jsonify, request

from .handlers import dummy

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
load_dotenv()  # also honour root .env / environment

# ---------------------------------------------------------------- codec setup
# base63 payload alphabet: a-z A-Z 0-9 + space (63 symbols, shortest for the
# allowed charset). base62 checksum alphabet: 0-9 A-Z a-z (no space, so the
# checksum is always one independent word).
ALPHABET63 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
ALPHABET62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
HEADER_NAME = "X-Entropy-Input"
FORM_FIELD = "entropy_input"
_B63 = [255] * 256  # byte -> base63 value, 255 = invalid (fast table decode)
for _i, _ch in enumerate(ALPHABET63):
    _B63[ord(_ch)] = _i
CHECKSUM_LEN = 6  # ceil(32 / log2(62)); CRC32 fits in 6 base62 chars
MAX_STRIPPED_SPACES = 8  # trailing spaces HTTP may trim -> recover via checksum


# ---------------------------------------------------------- entropy/temporal
# NOTE: decoded client payloads are handed to ``dummy()`` from
# ``server/handlers.py`` — implement your logic there, not here.
def shannon_entropy(text: str) -> tuple[float, float]:
    """Return (bits_per_char, total_bits) Shannon entropy of *text*."""
    if not text:
        return 0.0, 0.0
    n = len(text)
    per_char = -sum((c / n) * math.log2(c / n) for c in Counter(text).values())
    return per_char, per_char * n


def mood_line(text: str) -> str:
    """Mystical reading of the text's entropy. Tiers must match the JS mood()."""
    if not text:
        return ""
    _, tot = shannon_entropy(text)
    if tot < 32:
        return "The veil barely stirs... lend the oracle more words."
    if tot < 96:
        return "Faint whispers gather in the dark."
    if tot < 192:
        return "The mists thicken - the vision sharpens."
    return "The cosmos roars - the vision is crystal clear."


def stable_question_key(text: str) -> str:
    words = re.findall(r"[^\W_]+", text.casefold())
    return " ".join(sorted(set(words)))


def day_anchor() -> str:
    return date.today().isoformat()


def draw_index(text: str, n: int) -> int:
    """Stable index in ``range(n)`` for *text* on the current local day."""
    material = f"{day_anchor()}\0{stable_question_key(text)}".encode("utf-8")
    digest = hashlib.sha256(material).digest()
    return int.from_bytes(digest, "big") % n


# Original oracle phrasing (10 favorable / 5 neutral / 5 unfavorable).
# Deliberately not the Mattel "Magic 8-Ball" wording or name.
ANSWERS: tuple[tuple[str, str], ...] = (
    ("It is certain.", "positive"),
    ("Without a doubt.", "positive"),
    ("The entropy aligns in your favor.", "positive"),
    ("Yes -- all signs agree.", "positive"),
    ("Most likely.", "positive"),
    ("The currents say yes.", "positive"),
    ("Count on it.", "positive"),
    ("Fortune favors this path.", "positive"),
    ("Outlook is bright.", "positive"),
    ("The stars incline toward yes.", "positive"),
    ("The wheel turns in your favor.", "positive"),
    ("Yes, and sooner than you think.", "positive"),
    ("The deep currents carry you forward.", "positive"),
    ("Every omen points to yes.", "positive"),
    ("The forge-fire burns bright for this.", "positive"),
    ("Destiny has already nodded.", "positive"),
    ("The path is open -- walk it.", "positive"),
    ("Ancient winds whisper yes.", "positive"),
    ("Your stars are aligned.", "positive"),
    ("Triumph is written in the static.", "positive"),
    ("The mists have not cleared -- ask again.", "neutral"),
    ("Concentrate, then ask once more.", "neutral"),
    ("The oracle withholds its answer for now.", "neutral"),
    ("Unclear. The patterns are still forming.", "neutral"),
    ("Not yet decided -- time will tell.", "neutral"),
    ("The mirror is clouded -- return at dawn.", "neutral"),
    ("Even the oracle must sleep on this one.", "neutral"),
    ("The threads tangle -- ask with a clearer heart.", "neutral"),
    ("Silence. The answer is still being dreamed.", "neutral"),
    ("Neither sun nor shadow -- wait and watch.", "neutral"),
    ("The signs say no.", "negative"),
    ("Do not count on it.", "negative"),
    ("The entropy scatters -- outlook is dark.", "negative"),
    ("Very doubtful.", "negative"),
    ("The currents turn against this.", "negative"),
    ("The void stares back -- turn away.", "negative"),
    ("No. The gears grind against this.", "negative"),
    ("A cold wind answers: not this way.", "negative"),
    ("The pattern breaks -- abandon this hope.", "negative"),
    ("Dark waters. Do not sail them.", "negative"),
)


def generate_answer(text: str) -> tuple[str, str]:
    """Return today's (answer, category) pair for *text*."""
    return ANSWERS[draw_index(text, len(ANSWERS))]


# ------------------------------------------------------------- payload decode
def _crc32(text: str) -> int:
    return zlib.crc32(text.encode("utf-8")) & 0xFFFFFFFF


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
    return _encode_base62(_crc32(body))


def base63_decode(body: str) -> bytes:
    """Decode base63 *body* (big-int, 'a' == leading 0x00 preservation)."""
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


def _payload_secret() -> str:
    return os.environ.get("PAYLOAD_SECRET", "")


def trial_decompress(blob: bytes) -> str:
    """Try zlib / bz2 / lzma / raw-utf8; return decoded JSON string."""
    for name, fn in (
        ("zlib", zlib.decompress),
        ("bz2", bz2.decompress),
        ("lzma", lzma.decompress),
    ):
        try:
            return fn(blob).decode("utf-8")
        except Exception:
            continue
    return blob.decode("utf-8")  # raw (uncompressed) fallback, tried last


def extract_payload(text: str):
    """If *text* is a client payload, return (json_str, body_used); else (None, None).

    Verifies the leading base62 checksum word against the base63 body, retrying
    with up to MAX_STRIPPED_SPACES trailing spaces appended (HTTP header OWS
    trimming may strip them). Then base63-decodes and tries the bytes as-is
    (plain payloads) and XOR-descrambled with ``PAYLOAD_SECRET`` (scrambled
    payloads); the first result that is valid JSON wins.
    """
    if " " not in text:
        return None, None
    first, rest = text.split(" ", 1)
    if not (1 <= len(first) <= 8) or any(c not in ALPHABET62 for c in first):
        return None, None
    if any(c not in ALPHABET63 for c in rest):
        return None, None
    # HTTP may trim trailing spaces: resume one CRC with 0..N appended spaces
    # instead of re-hashing every candidate (1 pass + N single-byte updates).
    crc = zlib.crc32(rest.encode("utf-8")) & 0xFFFFFFFF
    body = None
    for k in range(MAX_STRIPPED_SPACES + 1):
        if _encode_base62(crc) == first:
            body = rest + " " * k
            break
        crc = zlib.crc32(b" ", crc) & 0xFFFFFFFF
    if body is None:
        return None, None
    try:
        blob = base63_decode(body)
    except Exception as exc:
        print(f"[payload] decode failed: {exc}")
        return None, None
    secret = _payload_secret()
    cands = [blob] + ([_scramble(blob, secret)] if secret else [])
    for cand in cands:
        try:
            text = trial_decompress(cand)
        except Exception:
            continue
        try:
            json.loads(text)
        except Exception:
            continue
        return text, body
    return None, None


# ------------------------------------------------------------------ web page
def get_configured_path() -> str:
    for var in ("ENTROPY_PATH", "APP_PATH", "BASE_PATH", "ROUTE_PATH"):
        val = os.environ.get(var, "").strip()
        if val:
            return val if val.startswith("/") else "/" + val
    return "/"


HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entropy Oracle</title>
<meta name="theme-color" content="#07090d">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='9' fill='%2307090d'/%3E%3Cpath d='M22.8 6.8a10 10 0 1 0 2.4 15.1 8.5 8.5 0 0 1-2.4-15.1Z' fill='%23e6c779'/%3E%3C/svg%3E">
<style>
:root {{
  --bg: #07090d;
  --surface: rgba(14, 17, 23, .9);
  --surface-deep: rgba(7, 9, 13, .82);
  --ink: #f3f0e7;
  --muted: #a5a8ae;
  --faint: #686e78;
  --gold: #e6c779;
  --gold-deep: #9d7d37;
  --line: rgba(240, 232, 213, .12);
  --aurora: #9ce7b5;
  --moon: #e8e5dc;
  --ember: #ff8b80;
  --sans: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --serif: Didot, "Bodoni MT", "Iowan Old Style", Georgia, serif;
}}
* {{ box-sizing: border-box; }}
html {{ min-height: 100%; background: var(--bg); }}
body {{
  min-height: 100vh; min-height: 100dvh; margin: 0;
  padding: clamp(1rem, 4vw, 3.5rem) 1rem;
  display: flex; align-items: center; justify-content: center;
  overflow-x: hidden;
  font-family: var(--sans);
  color: var(--ink);
  background:
    radial-gradient(900px 620px at 84% 8%, rgba(94, 65, 139, .22), transparent 68%),
    radial-gradient(760px 620px at 8% 92%, rgba(25, 92, 101, .17), transparent 66%),
    var(--bg);
}}
body::before {{
  content: ""; position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background-image:
    linear-gradient(rgba(255, 255, 255, .018) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, .018) 1px, transparent 1px);
  background-size: 72px 72px;
  mask-image: radial-gradient(circle at center, black, transparent 76%);
  -webkit-mask-image: radial-gradient(circle at center, black, transparent 76%);
}}
#stars {{ position: fixed; inset: 0; width: 100%; height: 100%; opacity: .58; z-index: 0; }}
.moon {{
  position: fixed; top: clamp(2rem, 8vh, 6rem); right: clamp(1rem, 8vw, 8rem);
  width: clamp(84px, 10vw, 144px); aspect-ratio: 1; z-index: 0;
  border-radius: 50%;
  background: radial-gradient(circle at 34% 31%, #fffdf5 0, #d9d4c6 54%, #8f8c86 100%);
  box-shadow: 0 0 50px rgba(255, 251, 229, .18), 0 0 150px rgba(230, 199, 121, .12);
  opacity: .78;
}}
.moon::before {{
  content: ""; position: absolute; inset: -34%; border: 1px solid rgba(230, 199, 121, .14);
  border-radius: 50%; transform: rotate(-18deg) scaleY(.38);
}}
.moon::after {{
  content: ""; position: absolute; width: 7px; height: 7px; right: -47%; top: 45%;
  border-radius: 50%; background: var(--gold);
  box-shadow: 0 0 16px rgba(230, 199, 121, .9);
}}
.vignette {{
  position: fixed; inset: 0; z-index: 1; pointer-events: none;
  background: radial-gradient(ellipse at center, transparent 28%, rgba(0, 0, 0, .58) 100%);
}}
.card {{
  position: relative; z-index: 2; width: 100%; max-width: 880px;
  overflow: hidden; isolation: isolate;
  background: var(--surface);
  border: 1px solid var(--line); border-radius: 26px;
  box-shadow: 0 34px 100px rgba(0, 0, 0, .58), 0 0 0 1px rgba(0, 0, 0, .45);
  backdrop-filter: blur(24px) saturate(120%); -webkit-backdrop-filter: blur(24px) saturate(120%);
}}
.card::before {{
  content: ""; position: absolute; inset: 0 0 auto; height: 1px; z-index: 5;
  background: linear-gradient(90deg, transparent 5%, rgba(230, 199, 121, .9) 50%, transparent 95%);
}}
.masthead {{
  display: flex; align-items: center; justify-content: space-between; gap: 1rem;
  padding: 1.25rem 1.75rem; border-bottom: 1px solid var(--line);
  background: rgba(255, 255, 255, .012);
}}
.brand {{ display: flex; align-items: center; gap: .8rem; }}
.brand-mark {{
  position: relative; flex: 0 0 auto; width: 38px; height: 38px;
  border: 1px solid rgba(230, 199, 121, .45); border-radius: 50%;
  box-shadow: inset 0 0 18px rgba(230, 199, 121, .06);
}}
.brand-mark::before {{
  content: ""; position: absolute; width: 19px; height: 19px; top: 8px; left: 8px;
  border-radius: 50%; background: var(--gold);
  box-shadow: 0 0 14px rgba(230, 199, 121, .35);
}}
.brand-mark::after {{
  content: ""; position: absolute; width: 17px; height: 17px; top: 6px; left: 14px;
  border-radius: 50%; background: #0d1016;
}}
.brand-name {{ font-size: .72rem; font-weight: 700; letter-spacing: .24em; text-transform: uppercase; }}
.brand-meta {{ margin-top: .25rem; color: var(--faint); font-size: .62rem; letter-spacing: .15em; text-transform: uppercase; }}
.signal {{
  display: flex; align-items: center; gap: .5rem; white-space: nowrap;
  color: var(--muted); font-size: .64rem; letter-spacing: .16em; text-transform: uppercase;
}}
.signal::before {{
  content: ""; width: 6px; height: 6px; border-radius: 50%; background: var(--aurora);
  box-shadow: 0 0 10px rgba(156, 231, 181, .8);
}}
.prompt-panel {{
  display: grid; grid-template-columns: minmax(0, .78fr) minmax(0, 1.22fr);
  gap: clamp(2rem, 5vw, 4.5rem); padding: clamp(2rem, 5vw, 3.7rem);
}}
.kicker {{
  display: inline-flex; align-items: center; gap: .65rem; margin-bottom: 1.2rem;
  color: var(--gold); font-size: .65rem; font-weight: 700; letter-spacing: .25em; text-transform: uppercase;
}}
.kicker::before {{ content: ""; width: 1.8rem; height: 1px; background: currentColor; }}
h1 {{
  margin: 0; font-family: var(--serif); font-size: clamp(3rem, 6vw, 4.8rem);
  font-weight: 400; line-height: .94; letter-spacing: -.045em; color: #f7f3e9;
}}
h1 em {{ display: block; color: var(--gold); font-weight: 400; }}
.intro p {{
  max-width: 24rem; margin: 1.5rem 0 0; color: var(--muted);
  font-family: var(--serif); font-size: 1rem; line-height: 1.65;
}}
.form-column {{ min-width: 0; align-self: center; }}
.label-row {{ display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: .7rem; }}
label {{ color: var(--ink); font-size: .7rem; font-weight: 650; letter-spacing: .18em; text-transform: uppercase; }}
#character-count {{ color: var(--faint); font-size: .66rem; letter-spacing: .1em; text-transform: uppercase; }}
textarea {{
  display: block; width: 100%; min-height: 178px; resize: vertical;
  padding: 1.05rem 1.15rem; outline: none;
  font-family: var(--serif); font-size: 1.08rem; line-height: 1.65; color: var(--ink);
  caret-color: var(--gold);
  background: linear-gradient(145deg, rgba(255, 255, 255, .025), transparent 45%), var(--surface-deep);
  border: 1px solid var(--line); border-radius: 15px;
  box-shadow: inset 0 1px 20px rgba(0, 0, 0, .32);
  transition: border-color .2s, box-shadow .2s, background .2s;
}}
textarea::placeholder {{ color: #666b74; font-style: italic; }}
textarea:focus {{
  border-color: rgba(230, 199, 121, .58);
  box-shadow: inset 0 1px 20px rgba(0, 0, 0, .3), 0 0 0 3px rgba(230, 199, 121, .07);
}}
.entropy-row {{ display: flex; align-items: center; gap: .85rem; min-height: 3.25rem; margin-top: .8rem; }}
.entropy-icon {{
  position: relative; flex: 0 0 auto; width: 28px; height: 28px;
  border: 1px solid rgba(230, 199, 121, .28); border-radius: 50%;
}}
.entropy-icon::before {{
  content: ""; position: absolute; inset: 7px; border-radius: 50%; background: var(--gold);
  box-shadow: 0 0 12px rgba(230, 199, 121, .55);
}}
.entropy-icon::after {{
  content: ""; position: absolute; inset: -5px; border: 1px solid rgba(230, 199, 121, .08); border-radius: 50%;
}}
.entropy-copy {{ min-width: 0; }}
.entropy-kicker {{ display: block; margin-bottom: .2rem; color: var(--faint); font-size: .58rem; letter-spacing: .19em; text-transform: uppercase; }}
#entropy {{ color: var(--muted); font-family: var(--serif); font-size: .88rem; font-style: italic; line-height: 1.35; }}
button {{
  display: flex; align-items: center; justify-content: space-between; gap: 1rem;
  width: 100%; margin-top: 1.25rem; padding: 1rem 1.15rem 1rem 1.3rem;
  color: #16120a; background: var(--gold); border: 0; border-radius: 12px;
  font-family: var(--sans); font-size: .72rem; font-weight: 800; letter-spacing: .17em; text-transform: uppercase;
  cursor: pointer; box-shadow: 0 12px 30px rgba(0, 0, 0, .24), inset 0 1px rgba(255, 255, 255, .3);
  transition: transform .18s, box-shadow .18s, background .18s;
}}
button svg {{ width: 18px; height: 18px; flex: 0 0 auto; transition: transform .18s; }}
button:hover:not(:disabled) {{ background: #f0d791; box-shadow: 0 15px 36px rgba(0, 0, 0, .3), 0 0 28px rgba(230, 199, 121, .12); transform: translateY(-1px); }}
button:hover:not(:disabled) svg {{ transform: translateX(3px); }}
button:active:not(:disabled) {{ transform: translateY(0); }}
button:focus-visible, textarea:focus-visible {{ outline: 2px solid var(--gold); outline-offset: 3px; }}
button:disabled {{ opacity: .62; cursor: wait; }}
button.is-loading svg {{ animation: orbit .9s linear infinite; }}
#result {{
  position: relative; min-height: 152px; margin: 0 clamp(2rem, 5vw, 3.7rem) 2.5rem;
  display: grid; place-items: center; overflow: hidden;
  padding: 1.8rem; text-align: center;
  background: radial-gradient(circle at 50% 110%, rgba(230, 199, 121, .1), transparent 52%), rgba(255, 255, 255, .018);
  border: 1px solid var(--line); border-radius: 18px; {result_style}
}}
.result-label {{
  display: flex; align-items: center; justify-content: center; gap: .8rem;
  color: var(--gold); font-size: .61rem; font-weight: 700; letter-spacing: .24em; text-transform: uppercase;
}}
.result-label::before, .result-label::after {{ content: ""; width: 1.5rem; height: 1px; background: rgba(230, 199, 121, .35); }}
.big {{
  max-width: 38rem; margin: .85rem auto 0;
  font-family: var(--serif); font-size: clamp(1.7rem, 4vw, 2.65rem); font-weight: 400;
  line-height: 1.2; letter-spacing: -.02em; color: var(--aurora);
  text-shadow: 0 0 26px rgba(156, 231, 181, .22);
}}
.big.neutral {{ color: var(--moon); text-shadow: 0 0 26px rgba(232, 229, 220, .18); }}
.big.negative {{ color: var(--ember); text-shadow: 0 0 26px rgba(255, 139, 128, .2); }}
.hint {{ display: flex; align-items: center; gap: .7rem; margin-top: .9rem; color: var(--faint); font-family: var(--serif); font-size: .9rem; font-style: italic; }}
.hint-mark {{ width: 5px; height: 5px; flex: 0 0 auto; border-radius: 50%; background: var(--gold-deep); box-shadow: 0 0 9px rgba(230, 199, 121, .4); }}
.card-footer {{
  display: flex; align-items: center; justify-content: space-between; gap: 1.5rem;
  padding: 1rem clamp(2rem, 5vw, 3.7rem); border-top: 1px solid var(--line);
  color: var(--faint); font-size: .58rem; letter-spacing: .14em; text-transform: uppercase;
}}
.card-footer span:last-child {{ color: rgba(230, 199, 121, .55); white-space: nowrap; }}
::selection {{ color: #111; background: var(--gold); }}
@keyframes orbit {{ to {{ transform: rotate(360deg); }} }}
@media (max-width: 720px) {{
  body {{ align-items: flex-start; padding: .8rem; }}
  .moon {{ opacity: .28; }}
  .card {{ border-radius: 20px; }}
  .prompt-panel {{ grid-template-columns: 1fr; gap: 2rem; }}
  .intro p {{ margin-top: 1rem; }}
  .form-column {{ align-self: auto; }}
  #result {{ margin: 0 1.5rem 1.5rem; }}
  .card-footer {{ padding: 1rem 1.5rem; }}
}}
@media (max-width: 440px) {{
  .masthead {{ padding: 1rem 1.2rem; }}
  .brand-meta {{ display: none; }}
  .signal {{ font-size: .57rem; }}
  .prompt-panel {{ padding: 2.2rem 1.2rem; }}
  h1 {{ font-size: 3.2rem; }}
  textarea {{ min-height: 165px; }}
  #result {{ margin: 0 1.2rem 1.2rem; padding: 1.5rem 1rem; }}
  .card-footer {{ align-items: flex-start; flex-direction: column; gap: .45rem; padding: 1rem 1.2rem; }}
}}
@media (prefers-reduced-motion: reduce) {{
  *, *::before, *::after {{ scroll-behavior: auto !important; animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; }}
}}
@supports not (backdrop-filter: blur(1px)) {{
  .card {{ background: #0e1117; }}
}}
</style>
</head>
<body>
<canvas id="stars" aria-hidden="true"></canvas>
<div class="moon" aria-hidden="true"></div>
<div class="vignette" aria-hidden="true"></div>
<main class="card">
<header class="masthead">
<div class="brand">
<span class="brand-mark" aria-hidden="true"></span>
<div>
<div class="brand-name">Entropy Oracle</div>
<div class="brand-meta">Chamber of chance &middot; MMXXVI</div>
</div>
</div>
<div class="signal">Signal open</div>
</header>
<section class="prompt-panel">
<div class="intro">
<div class="kicker">Beyond the possible</div>
<h1>What does the<br><em>entropy say?</em></h1>
<p>Form a question, trust the signal, and let the unseen decide.</p>
</div>
<div class="form-column">
<div class="label-row">
<label for="box">Pose your question</label>
<span id="character-count">0 characters</span>
</div>
<textarea id="box" placeholder="What waits beyond the edge of possibility?" aria-describedby="entropy" spellcheck="true">{text}</textarea>
<div class="entropy-row">
<span class="entropy-icon" aria-hidden="true"></span>
<div class="entropy-copy">
<span class="entropy-kicker">Entropy reading</span>
<div id="entropy">{entropy_line}</div>
</div>
</div>
<button id="go" type="button">
<span>Ask the oracle</span>
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
<path d="M5 12h13M14 7l5 5-5 5"/>
</svg>
</button>
</div>
</section>
<section id="result" aria-live="polite" aria-atomic="true">{result_block}</section>
<footer class="card-footer">
<span>The oracle's answer holds for the day. No question is stored.</span>
<span>Entropy / 01</span>
</footer>
</main>
<script>
(function stars() {{
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const cv = document.getElementById('stars');
  const ctx = cv.getContext('2d');
  let W = 0, H = 0, pts = [];
  function size() {{
    cv.width = innerWidth; cv.height = innerHeight; W = cv.width; H = cv.height;
    const n = Math.min(220, Math.floor(W * H / 9000));
    pts = Array.from({{length: n}}, () => ({{x: Math.random() * W, y: Math.random() * H, r: Math.random() * 1.3 + 0.3, p: Math.random() * Math.PI * 2, s: 0.5 + Math.random() * 1.5}}));
  }}
  size(); addEventListener('resize', size);
  let t = 0;
  (function tick() {{
    requestAnimationFrame(tick);
    if (document.hidden) return;
    t += 0.02;
    ctx.clearRect(0, 0, W, H);
    for (const q of pts) {{
      ctx.globalAlpha = 0.25 + 0.55 * (0.5 + 0.5 * Math.sin(t * q.s + q.p));
      ctx.fillStyle = q.r > 1.2 ? '#e8f5e9' : '#00b32e';
      ctx.beginPath(); ctx.arc(q.x, q.y, q.r, 0, 7); ctx.fill();
    }}
    ctx.globalAlpha = 1;
  }})();
}})();
function scramble(el, final) {{
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) {{ el.textContent = final; return; }}
  const glyphs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz·*~';
  const total = 22;
  let frame = 0;
  const timer = setInterval(() => {{
    frame++;
    if (frame >= total) {{ clearInterval(timer); el.textContent = final; return; }}
    const show = Math.floor(final.length * frame / total);
    let out = final.slice(0, show);
    for (let i = show; i < final.length; i++) out += glyphs[(Math.random() * glyphs.length) | 0];
    el.textContent = out;
  }}, 28);
}}
const box = document.getElementById('box');
const ent = document.getElementById('entropy');
const count = document.getElementById('character-count');
function shannon(s) {{
  if (!s.length) return [0, 0];
  const f = {{}};
  for (const ch of s) f[ch] = (f[ch] || 0) + 1;
  let h = 0;
  for (const k in f) {{ const p = f[k] / s.length; h -= p * Math.log2(p); }}
  return [h, h * s.length];
}}
function mood(text) {{
  if (!text.length) return '';
  const tot = shannon(text)[1];
  if (tot < 32) return 'The veil barely stirs... lend the oracle more words.';
  if (tot < 96) return 'Faint whispers gather in the dark.';
  if (tot < 192) return 'The mists thicken - the vision sharpens.';
  return 'The cosmos roars - the vision is crystal clear.';
}}
function refresh() {{
  ent.textContent = mood(box.value);
  const length = Array.from(box.value).length;
  count.textContent = length + (length === 1 ? ' character' : ' characters');
}}
box.addEventListener('input', refresh);
refresh();
async function fetchPage(v) {{
  // Headers cannot carry CR/LF (multiline text) or non-Latin1 chars, and long
  // values may be rejected (431/413): fall back to form-body POST, same page.
  if (!/[\\r\\n]/.test(v)) {{
    try {{
      const r = await fetch(window.location.pathname, {{
        method: 'GET', headers: {{ '{header}': v }}
      }});
      if (r.status !== 431 && r.status !== 413 && r.status !== 400) return r;
    }} catch (e) {{ /* fall through to POST */ }}
  }}
  return fetch(window.location.pathname, {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' }},
    body: '{form_field}=' + encodeURIComponent(v)
  }});
}}
document.getElementById('go').addEventListener('click', async () => {{
  const btn = document.getElementById('go');
  const btnLabel = btn.querySelector('span');
  const res = document.getElementById('result');
  btn.disabled = true;
  btn.classList.add('is-loading');
  btnLabel.textContent = 'Reading the signal';
  try {{
    const r = await fetchPage(box.value);
    const doc = new DOMParser().parseFromString(await r.text(), 'text/html');
    const newResult = doc.getElementById('result');
    if (newResult) {{
      res.innerHTML = newResult.innerHTML;
      const big = res.querySelector('.big');
      if (big) scramble(big, big.textContent);
    }}
    const newEnt = doc.getElementById('entropy');
    if (newEnt && newEnt.textContent) ent.textContent = newEnt.textContent;
    else refresh();
  }} catch (e) {{
    res.textContent = 'The signal broke. Please try again.';
  }} finally {{
    btn.disabled = false;
    btn.classList.remove('is-loading');
    btnLabel.textContent = 'Ask the oracle';
  }}
}});
</script>
</body>
</html>"""


def render_page(text: str, answer=None, category: str = "neutral") -> str:
    import html as _html

    entropy_line = mood_line(text)
    if answer is None:
        result = (
            '<div class="result-label">Oracle response</div>'
            '<div class="hint"><span class="hint-mark" aria-hidden="true"></span>'
            '<span>The oracle awaits your question.</span></div>'
        )
    else:
        result = (
            '<div class="result-label">The oracle speaks</div>'
            f'<div class="big {category}">{_html.escape(answer)}</div>'
        )
    return HTML.format(
        header=HEADER_NAME,
        form_field=FORM_FIELD,
        text=_html.escape(text),
        entropy_line=_html.escape(entropy_line),
        result_block=result,
        result_style="",
    )


def wants_json() -> bool:
    """True when the caller asks for ``Accept: application/json``.

    JSON callers (the python client) get only ``{"answer": "..."}`` instead of
    the HTML page; browsers (``Accept: */*``) keep getting the webpage.
    """
    return "application/json" in request.headers.get("Accept", "")


def create_app() -> Flask:
    app = Flask(__name__)
    path = get_configured_path()

    @app.after_request
    def _no_cache(resp):
        # The page embeds JS; never allow a stale cached copy to survive a fix.
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        return resp

    @app.route(path, methods=["GET", "POST"])
    def index():
        # Header transport first (used by both browser JS and python client);
        # POST form field accepted as fallback (e.g. oversized headers). Never query params.
        text = request.headers.get(HEADER_NAME)
        if text is None:
            text = request.headers.get("X-Payload")
        submitted = text is not None
        if text is None:
            text = request.form.get(FORM_FIELD, "")
            submitted = submitted or bool(text)
        if not submitted:
            if wants_json():
                return jsonify({"error": f"missing input: send text in the {HEADER_NAME} header"}), 400
            return render_page("")
        answer, category = generate_answer(text)
        json_str, _ = extract_payload(text)
        if json_str is not None:
            try:
                json.loads(json_str)  # validate; keep original string for dummy()
            except Exception:
                pass
            dummy(json_str)  # silent: no trace of this in the response
        if wants_json():
            return jsonify({"answer": answer})
        return render_page(text, answer, category)

    return app


app = create_app()

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    print(f"Serving on http://{host}:{port}{get_configured_path()}  (header {HEADER_NAME})")
    app.run(host=host, port=port, threaded=True)
