# AGENTS.md — Exfoliator (oracle branch)

Entropy-based oracle web app. Two components, one repo, managed with `uv`.
Browser and python-client flows share one endpoint and must behave identically.

## Layout

- `server/server.py` — Flask app. Single GET endpoint (GET + POST accepted on the
  same path; POST form field is only a fallback for header-unfriendly text).
  Renders the page, computes entropy, draws the oracle answer, detects client
  payloads and calls `dummy()`.
- `client/client.py` — importable module (`client.main(json_string, ...)`).
  Compresses + encodes a JSON string and GETs it to the server.
- `client/example.py` — runnable demo incl. the 2048-byte compression showcase.
- `tests/` — pytest suite (`test_codec.py`, `test_server.py`, `test_client.py`).

## Commands (run from repo root)

- `uv sync` — install runtime + dev deps.
- `uv run python -m server.server` — start the server (`HOST`/`PORT` env).
- `uv run python client/example.py '{"a": 1}'` — demo transmission.
- `uv run pytest -q` — full suite. Run it before and after every change.

## Environment

| Var | Used by | Meaning |
| --- | ------- | ------- |
| `ENTROPY_PATH` (`APP_PATH`/`BASE_PATH`/`ROUTE_PATH` aliases) | server | endpoint path, default `/` |
| `HOST`, `PORT` | server | bind address, defaults `127.0.0.1:5000` |
| `SERVER_URL` | client | server base URL, default `http://127.0.0.1:5000` |
| `PAYLOAD_SECRET` | both | secret word for the scramble layer; must match. Unset = layer off |

Copy `.env.example` (or `server/.env.example`) to `.env`; never commit `.env`.

## Hard rules

- **No URL query parameters, ever.** Input travels in the `X-Entropy-Input`
  header (browser JS and python client) or, as fallback, the `entropy_input`
  form field. `request.args` must stay unused.
- **Web and payload flows behave identically**: same entropy calc, same answer
  draw, same response. Only the representation differs (HTML page vs
  `{"answer": "..."}` for `Accept: application/json`).
- **Wire format is frozen** — client and server implement it independently, so
  these must stay in sync on both sides:
  - base63 alphabet order: `a-z A-Z 0-9` + space (space = value 62);
    big-int encoding, leading `0x00` bytes preserved as leading `a`s.
  - base62 checksum alphabet: `0-9 A-Z a-z`; checksum = CRC32 of the base63
    body, encoded to exactly 6 chars. Payload = `<checksum><space><body>`.
  - Split payloads on the **first** space only; tolerate stripped trailing
    spaces by resuming the CRC (never by re-hashing).
  - Compressor trial order `zlib → bz2 → lzma → raw`; shortest-body pick with
    ties broken by that dict order.
  - Scramble: XOR with SHA-256-CTR keystream, key = `sha256(secret)`,
    block = `sha256(key + u64be(counter))`. Obfuscation, not authenticated
    encryption — do not oversell it.
- **Page contract**: element ids `box`, `entropy`, `go`, `result` and the
  `.big` result class are load-bearing for the inline JS. Single file, no
  external web assets (works offline / under subpaths).
- Stdlib-first: new third-party deps need a reason. No emojis in UI copy.

## When changing behavior

- Update/add tests in `tests/` and keep `uv run pytest -q` green.
- Keep `client/example.py` output truthful (lengths, ratios, shipped winner).
