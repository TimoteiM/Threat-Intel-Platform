"""Generate and install ALERT_CALLBACK_SECRET in .env, once.

**Never prints the secret.** It prints a short SHA-256 fingerprint of it, so
the two sides of the integration can confirm they hold the SAME secret
without either side transmitting it in a chat, ticket or email.

Idempotent: refuses if the key already exists, rather than rotating something
the receiver is already verifying against.
"""
from __future__ import annotations

import hashlib
import pathlib
import re
import secrets
import sys

ENV = pathlib.Path(__file__).resolve().parent.parent / ".env"
KEY = "ALERT_CALLBACK_SECRET"


def main() -> int:
    text = ENV.read_text()
    if re.search(rf"^\s*{KEY}\s*=", text, re.MULTILINE):
        print(f"{KEY} is already present in .env — refusing to overwrite.")
        print("Rotating it would break any receiver already verifying against")
        print("the current value. Remove the line by hand first if you mean to.")
        return 1

    # 32 bytes of CSPRNG output, hex-encoded. HMAC-SHA256 keys longer than the
    # 64-byte block size are hashed down, so 32 bytes is the useful maximum
    # and well above the 16-byte floor.
    secret = secrets.token_hex(32)
    fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:16]

    block = (
        "\n"
        "# HMAC key for outbound callback integrity. Set 2026-10-22 because it\n"
        "# was empty, and alert_ingest_service.sign_payload returns None when\n"
        "# empty — so every callback was delivered UNSIGNED.\n"
        "# Sent as: X-Alert-Signature: sha256=<hex> over the raw body bytes.\n"
        "# NOTE: the header is OMITTED when this is empty, so the receiver must\n"
        "# REQUIRE it and reject when absent. A receiver that verifies only when\n"
        "# the header is present is still unauthenticated.\n"
        f"{KEY}={secret}\n"
    )
    # Append, so nothing already in the file is rewritten.
    with ENV.open("a") as handle:
        handle.write(block)

    print(f"{KEY} generated and appended to .env")
    print(f"  length      : {len(secret)} hex chars (32 bytes of entropy)")
    print(f"  fingerprint : sha256(secret)[:16] = {fingerprint}")
    print()
    print("The secret itself is NOT printed. Read it with:")
    print("    grep '^ALERT_CALLBACK_SECRET=' .env")
    print()
    print("Give the VALUE to the Tracecat workflow owner over a secret channel")
    print("(password manager share), and the FINGERPRINT in the ticket, so they")
    print("can confirm they loaded the right one without it appearing in a")
    print("ticket, chat or email.")
    print()
    print("Then restart the services so Settings picks it up:")
    print("    docker compose up -d --force-recreate api worker beat")
    return 0


if __name__ == "__main__":
    sys.exit(main())
