# AGENTS.md — Exfoliator

Entropy-based oracle web app. Two components, one repo, managed with `uv`
(Python >= 3.10). Browser and python-client flows share one endpoint and must
behave identically.

## Layout

- `server/server.py` — Flask app. Single endpoint (GET + POST accepted on the
  same path; the POST form field is only a fallback for header-unfriendly text).
  Renders the page, computes entropy, draws the oracle answer, detects client
  payloads and calls `dummy()`.
- `server/handlers.py` — user-editable `dummy()` payload hook. Deployments may
  bind-mount a host-provided replacement over this file (`HANDLERS_FILE`).
- `client/client.py` — importable module (`client.main(json_string, ...)`).
  Compresses + encodes a JSON string and GETs it to the server.
- `client/example.py` — runnable demo incl. the 2048-byte compression showcase.
- `tests/` — pytest suite (`test_codec.py`, `test_server.py`, `test_client.py`;
  shared fixtures in `conftest.py`).

## Commands (run from repo root)

- `uv sync` — install runtime + dev deps (do this first).
- `uv run pytest -q` — full suite. Run it before and after every change.
- `uv run pytest -q tests/test_codec.py` — codec-only subset while iterating on
  the wire format; still run the full suite before finishing.
- `uv run python -m server.server` — start the server (`HOST`/`PORT` env).
- `uv run python client/example.py '{"a": 1}'` — demo transmission (needs the
  server running).
- `uv run gunicorn --check-config server.server:app` — validate production
  config; CI runs this before publishing the image.

## Environment

| Var | Used by | Meaning |
| --- | ------- | ------- |
| `ENTROPY_PATH` (`APP_PATH`/`BASE_PATH`/`ROUTE_PATH` aliases) | server | endpoint path, default `/` |
| `HOST`, `PORT` | server | bind address, defaults `127.0.0.1:5000` |
| `SERVER_URL` | client | server base URL, default `http://127.0.0.1:5000` |
| `PAYLOAD_SECRET` | both | secret word for the scramble layer; must match. Unset = layer off |
| `TZ` | server | local calendar day used by the daily answer draw |

Copy `.env.example` (or `server/.env.example`) to `.env`; never commit `.env`.
Deployment-only vars (image tag, host port, handlers mount, Gunicorn args) are
documented in `README.md` — leave them alone unless the task is deployment.

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
  - Any change here is a breaking wire change: update client, server,
    `client/example.py` and the tests in one commit and say so in its message.
- **Page contract**: element ids `box`, `entropy`, `go`, `result` and the
  `.big` result class are load-bearing for the inline JS. Single file, no
  external web assets (works offline / under subpaths).

## Conventions

- Stdlib-first: new third-party deps need a reason.
- No emojis in UI copy (or anywhere in the repo).
- Code style: double-quoted strings, type hints on public functions, source
  lines wrapped to ~79 columns like the existing code. Comments explain *why*
  (invariants, wire-format constraints), not *what*.
- Payload failures stay invisible: a bad checksum, undecodable body or wrong
  secret falls through to the normal oracle answer; nothing about the payload
  path may leak into the HTTP response.
- `dummy()` in `server/handlers.py` must never raise on decoded input, and its
  call leaves no trace in the response — its docstring is the contract.

## When changing behavior

- Update/add tests in `tests/` and keep `uv run pytest -q` green.
- Keep `client/example.py` output truthful (lengths, ratios, shipped winner).
- Client and server codec sides change together — `tests/test_codec.py`
  asserts they stay in lockstep.

## Git

- Follow Conventional Commits 1.0.0: `type(scope): summary` — imperative
  mood, lowercase start, no trailing period. Common types here: `feat`,
  `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `build`, `ci`; scope
  is the component (`server`, `client`, `tests`, ...) and is optional.
- Use the body to explain *why*, not *what* (same philosophy as comments).
- Mark breaking changes with `!` after the type and a `BREAKING CHANGE:`
  footer naming what breaks — a frozen wire-format change is the prime case
  and must bundle client, server, `client/example.py` and the tests in that
  one commit (see Hard rules).
- History before this convention uses an `Oracle: <summary>` prefix; don't
  imitate it in new commits.
- Never push, force-push, or rewrite history unless explicitly asked.
