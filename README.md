# Entropy Oracle

Ask a question, consult the oracle. A tiny Flask web app that reads the
Shannon entropy of your words and answers with a freshly drawn fortune —
plus a compressed-payload channel that lets a Python client smuggle a JSON
document to the server inside a normal-looking oracle request.

## How it works

**Browser flow (regular use):**

1. Open the page, type a question. The page shows a live reading of the
   text's entropy (no numbers, just mood).
2. Click "Ask the oracle". The browser re-issues a GET with your text in the
   `X-Entropy-Input` header — never in URL query parameters.
3. The server mixes your text with fresh OS randomness, draws an answer from
   its table (20 positive / 10 neutral / 10 negative), and returns the same
   page with the answer revealed.

**Payload flow (Python client):**

Identical HTTP round-trip, but the header text is a compressed + encoded
JSON document: `<6-char checksum> <base63 body>`. The server verifies the
checksum, decodes and decompresses the body, hands the JSON string to
`dummy()` in `server/handlers.py`, and answers exactly as in the browser
flow. Callers sending `Accept: application/json` get back just
`{"answer": "..."}` instead of the HTML page.

## Quickstart

Requires Python 3.10+ and [`uv`](https://docs.astral.sh/uv/).

```bash
uv sync
cp .env.example .env   # optional: defaults work out of the box
uv run python -m server.server
```

Then open `http://127.0.0.1:5000` in a browser, or send a JSON payload
from another terminal (server must be running):

```bash
uv run python client/example.py '{"hello": "world"}'
```

The demo defaults to a 2048-byte sample document and prints per-compressor
sizes, the shipped payload length, and the server's answer. With a secret
set, the compressed bytes are XOR-scrambled first (same length, opaque body):

```bash
PAYLOAD_SECRET=brass-gears-2026 uv run python client/example.py
```

From your own script:

```python
import client.client as client
answer = client.main('{"hello": "world"}')
```

## Configuration

| Var | Used by | Default | Meaning |
| --- | ------- | ------- | ------- |
| `ENTROPY_PATH` (`APP_PATH`/`BASE_PATH`/`ROUTE_PATH` aliases) | server | `/` | endpoint path |
| `HOST`, `PORT` | server | `127.0.0.1:5000` | bind address |
| `SERVER_URL` | client | `http://127.0.0.1:5000` | server base URL |
| `PAYLOAD_SECRET` | both | unset (layer off) | secret word for the scramble layer; must match on both sides |

## Custom logic

Decoded payloads land in `dummy()` in `server/handlers.py`. Edit that file
to implement your own handling — `server/server.py` needs no changes.
The call leaves no trace in the HTTP response.

## Wire format (frozen)

- Body alphabet (base63): `a-z A-Z 0-9` + space; big-int encoding, leading
  `0x00` bytes preserved as leading `a`s.
- Checksum: CRC32 of the base63 body, base62-encoded (`0-9 A-Z a-z`) to
  exactly 6 chars. Payload = `<checksum><space><body>`.
- Compressor trial order `zlib → bz2 → lzma → raw`; shortest body wins.
- Optional scramble: XOR with a SHA-256-CTR keystream, key = `sha256(secret)`.
  Obfuscation, not authenticated encryption.

## Layout

- `server/server.py` — Flask app, single endpoint, entropy + answer draw.
- `server/handlers.py` — user-editable `dummy()` payload hook.
- `client/client.py` — importable sender (`client.main(json_string, ...)`).
- `client/example.py` — runnable demo incl. the 2048-byte showcase.
- `tests/` — pytest suite.

```bash
uv run pytest -q   # full suite, keep it green
```

## License

MIT — see [LICENSE](LICENSE).
