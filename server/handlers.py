# server/handlers.py
"""User-editable payload handler for the entropy oracle server.

This module owns ``dummy()`` — the hook the server calls with every decoded
client payload (the final decompressed JSON string). Edit this file to
implement your own logic; ``server/server.py`` needs no changes.

Contract (keep it stable so the server and tests keep working):
  - ``dummy(data: str)`` receives the decompressed JSON string verbatim.
  - Return value is currently ignored by the server (may be used later),
    so return ``data`` (or your processed result) for forward compatibility.
  - Keep it side-effect free or explicitly logged; it runs on every payload
    request, in the request thread. Never raise for malformed input the
    server already validated — handle your own errors internally.
  - The call leaves no trace in the HTTP response (HTML or JSON answer).
"""


def dummy(data: str):
    """Further processing hook for decoded client payloads.

    Receives the final decompressed JSON string. Default: log and return it.
    Replace the body with your own logic.
    """
    print(f"[dummy] received payload json ({len(data)} chars): {data[:200]}")
    return data
