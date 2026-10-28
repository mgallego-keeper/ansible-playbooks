#!/usr/bin/env python3
"""
KSM-1103 live-vault test helper.

Derives the same Fernet key KeeperAnsible.get_encryption_key() derives from
keeper_record_cache_secret (PBKDF2-HMAC-SHA256, hostname-zfill salt, 390000
iterations - see __init__.py), then encrypts a payload that starts with the
pickle protocol-2 marker byte (0x80) so decrypt() takes the legacy-cache
branch. This is NOT a working pickle exploit (no __reduce__ gadget) - the
actual RCE-prevention proof is the unit test test_decrypt_rejects_pickle_payload
in tests/keeper_cache_encrypt_test.py (Layer 1/2). This helper only proves
the live plugin recognizes a legacy-format cache and falls back safely
instead of crashing or attempting to deserialize it.

Usage: make_legacy_cache_blob.py <cache_secret> <output_path> [shape]

shape is "legacy-pickle" (default) or "invalid-json".
"""
import base64
import socket
import sys

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def main():
    cache_secret, output_path = sys.argv[1], sys.argv[2]
    shape = sys.argv[3] if len(sys.argv) > 3 else "legacy-pickle"

    salt = socket.gethostname().zfill(32)[0:32]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(cache_secret.encode()))

    if shape == "invalid-json":
        payload = b'{"not": "a list"}'
    else:
        payload = b"\x80\x04legacy-pickle-protocol-2-marker-not-a-real-exploit"

    ciphertext = Fernet(key).encrypt(payload)

    with open(output_path, "wb") as f:
        f.write(ciphertext)


if __name__ == "__main__":
    main()
