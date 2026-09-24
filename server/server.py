# server/server.py
"""Entropy oracle server (single GET endpoint, header-transported input).

Web interaction (regular use):
  1. GET the page (no header) -> empty question form.
  2. User types a question; JS shows Shannon entropy of the text live.
  3. User clicks "Ask the oracle"; JS re-issues GET with the
     textarea content in the ``X-Entropy-Input`` header (no URL query params).
  4. Server mixes the text with fresh OS randomness (``secrets``), draws a
     fresh oracle answer on every click, and returns the SAME page with it shown.

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
import secrets
import zlib
from collections import Counter

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


# ------------------------------------------------------------- entropy/random
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


def draw_index(text: str, n: int) -> int:
    """Fresh index in ``range(n)`` from *text* entropy plus OS randomness."""
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    mixed = hashlib.sha256(digest + secrets.token_bytes(32)).digest()
    return int.from_bytes(mixed, "big") % n


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
    """Draw a fresh (answer, category) pair with *text* as entropy source."""
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
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ccircle cx='16' cy='16' r='13' fill='%23d4af37'/%3E%3Ccircle cx='21' cy='12' r='10' fill='%23050510'/%3E%3C/svg%3E">
<style>
:root {{
  --bg: #050510;
  --card: rgba(10, 10, 24, .88);
  --ink: #e9e6da; --dim: #9a94a8; --faint: #57536a;
  --gold: #d4af37; --gold-dim: #8a6f1f; --copper: #b87333;
  --aurora: #8dffb0; --ember: #ff6b5e; --moon: #e8e4d8;
  --line: #2a2640; --field: #07070f;
}}
* {{ box-sizing: border-box; }}
html, body {{ margin: 0; padding: 0; }}
body {{
  min-height: 100vh; padding: 2.5rem 1rem 3rem;
  font-family: Georgia, "Palatino Linotype", "Book Antiqua", Palatino, serif;
  background:
    radial-gradient(1100px 650px at 78% -10%, rgba(88, 40, 140, .32), transparent 60%),
    radial-gradient(900px 650px at 8% 108%, rgba(20, 90, 110, .2), transparent 60%),
    var(--bg);
  background-attachment: fixed;
  color: var(--ink);
  display: flex; align-items: flex-start; justify-content: center;
}}
#stars {{ position: fixed; inset: 0; width: 100%; height: 100%; opacity: .8; z-index: 0; }}
.moon {{
  position: fixed; top: 6%; right: 9%; width: 110px; height: 110px; z-index: 0;
  border-radius: 50%;
  background: radial-gradient(circle at 35% 35%, #fdfbf0, #d9d4c0 60%, #a8a294 100%);
  box-shadow: 0 0 40px rgba(253, 251, 240, .35), 0 0 120px rgba(212, 175, 55, .25);
  opacity: .9;
}}
.vignette {{
  position: fixed; inset: 0; z-index: 1; pointer-events: none;
  background: radial-gradient(ellipse at 50% 32%, transparent 35%, rgba(0, 0, 0, .78) 100%);
}}
.card {{
  position: relative; z-index: 2; width: 100%; max-width: 660px;
  background: var(--card);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(212, 175, 55, .45); border-radius: 6px;
  padding: 2rem 2rem 1.6rem;
  box-shadow: 0 0 0 1px rgba(0, 0, 0, .8), 0 0 60px rgba(88, 40, 140, .25), 0 30px 80px rgba(0, 0, 0, .65);
}}
.card::before {{
  content: ""; display: block; height: 3px; margin: -2rem -2rem 1.6rem;
  background: linear-gradient(90deg, transparent, var(--gold) 20%, var(--copper) 50%, var(--gold) 80%, transparent);
}}
.overline {{ font-size: .68rem; letter-spacing: .35em; color: var(--gold); margin-bottom: .6rem; }}
h1 {{
  margin: 0 0 1.3rem;
  font-family: Didot, "Bodoni MT", "Playfair Display", Georgia, serif;
  font-size: 2.1rem; font-weight: 700; letter-spacing: .01em; color: #f5edd6;
  text-shadow: 0 0 24px rgba(212, 175, 55, .35);
}}
label {{ display: block; font-size: .78rem; letter-spacing: .24em; text-transform: uppercase; color: var(--dim); margin-bottom: .45rem; }}
textarea {{
  width: 100%; min-height: 150px; resize: vertical;
  font-family: Georgia, "Palatino Linotype", "Book Antiqua", Palatino, serif;
  font-size: 1rem; line-height: 1.7; color: var(--ink);
  caret-color: var(--gold);
  background: var(--field);
  border: 1px solid var(--line); border-radius: 4px;
  padding: .8rem .95rem; outline: none;
  box-shadow: inset 0 0 30px rgba(0, 0, 0, .7);
  transition: border-color .15s, box-shadow .15s;
}}
textarea:focus {{ border-color: var(--gold-dim); box-shadow: inset 0 0 30px rgba(0, 0, 0, .7), 0 0 0 1px rgba(212, 175, 55, .3), 0 0 22px rgba(212, 175, 55, .15); }}
textarea::placeholder {{ color: var(--faint); font-style: italic; }}
#entropy {{ margin-top: .55rem; font-size: .88rem; font-style: italic; color: var(--dim); min-height: 1.2em; }}
button {{
  margin-top: 1.1rem; width: 100%; padding: .9rem 1rem;
  font-family: inherit; font-size: .95rem; font-weight: 700;
  letter-spacing: .22em; text-transform: uppercase;
  color: var(--gold);
  background: linear-gradient(180deg, rgba(212, 175, 55, .12), rgba(212, 175, 55, .03));
  border: 1px solid var(--gold-dim); border-radius: 4px; cursor: pointer;
  text-shadow: 0 0 14px rgba(212, 175, 55, .4);
  box-shadow: inset 0 0 18px rgba(212, 175, 55, .06);
  transition: box-shadow .15s, background .15s, transform .08s;
}}
button:hover:not(:disabled) {{ background: linear-gradient(180deg, rgba(212, 175, 55, .2), rgba(212, 175, 55, .06)); box-shadow: 0 0 26px rgba(212, 175, 55, .3), inset 0 0 24px rgba(212, 175, 55, .12); }}
button:active:not(:disabled) {{ transform: translateY(1px); }}
button:disabled {{ opacity: .55; cursor: wait; }}
#result {{
  margin-top: 1.3rem; padding: 1.5rem 1rem; text-align: center;
  background: rgba(20, 16, 40, .5); border: 1px solid var(--line);
  border-radius: 4px; {result_style}
}}
.result-label {{ font-size: .72rem; letter-spacing: .3em; text-transform: uppercase; color: var(--gold); }}
.big {{
  font-family: Didot, "Bodoni MT", "Playfair Display", Georgia, serif;
  font-style: italic;
  font-size: 1.7rem; font-weight: 700; letter-spacing: .02em; line-height: 1.4;
  color: var(--aurora);
  text-shadow: 0 0 8px rgba(141, 255, 176, .7), 0 0 30px rgba(141, 255, 176, .35);
}}
.big.neutral {{
  color: var(--moon);
  text-shadow: 0 0 8px rgba(232, 228, 216, .7), 0 0 30px rgba(232, 228, 216, .3);
}}
.big.negative {{
  color: var(--ember);
  text-shadow: 0 0 8px rgba(255, 107, 94, .8), 0 0 30px rgba(255, 107, 94, .4);
}}
.hint {{ color: var(--faint); font-size: .9rem; font-style: italic; }}
</style>
</head>
<body>
<canvas id="stars" aria-hidden="true"></canvas>
<div class="moon" aria-hidden="true"></div>
<div class="vignette" aria-hidden="true"></div>
<div class="card">
<div class="overline">ENTROPY ORACLE &middot; MMXXVI</div>
<h1>Entropy Oracle</h1>
<label for="box">Your question</label>
<textarea id="box" placeholder="Ask your question, then consult the oracle...">{text}</textarea>
<div id="entropy">{entropy_line}</div>
<button id="go" type="button">Ask the oracle</button>
<div id="result">{result_block}</div>
</div>
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
    ctx.fillStyle = '#040705';
    ctx.fillRect(0, 0, W, H);
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
  const res = document.getElementById('result');
  btn.disabled = true;
  try {{
    const r = await fetchPage(box.value);
    const doc = new DOMParser().parseFromString(await r.text(), 'text/html');
    const newResult = doc.getElementById('result');
    if (newResult) {{
      res.innerHTML = newResult.innerHTML;
      res.style.display = 'block';
      const big = res.querySelector('.big');
      if (big) scramble(big, big.textContent);
    }}
    const newEnt = doc.getElementById('entropy');
    if (newEnt && newEnt.textContent) ent.textContent = newEnt.textContent;
    else refresh();
  }} catch (e) {{
    res.style.display = 'block';
    res.textContent = 'Request failed: ' + e;
  }} finally {{
    btn.disabled = false;
  }}
}});
</script>
</body>
</html>"""


def render_page(text: str, answer=None, category: str = "neutral") -> str:
    import html as _html

    entropy_line = mood_line(text)
    if answer is None:
        result, style = '<span class="hint">The oracle awaits your question.</span>', "display:none"
    else:
        result = (
            '<div class="result-label">The oracle speaks</div>'
            f'<div class="big {category}">{_html.escape(answer)}</div>'
        )
        style = ""
    return HTML.format(
        header=HEADER_NAME,
        form_field=FORM_FIELD,
        text=_html.escape(text),
        entropy_line=_html.escape(entropy_line),
        result_block=result,
        result_style=style,
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
