#!/usr/bin/env python3
"""Phase 19 ONLY: independent offline RFC 9180 conformance reference, NOT library code.

Requires `cryptography` for P-256 ECDH/AESGCM; uses test-only published private keys.
Never ship this script or its fixed test keys as production encryption facilities.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

VECTOR = Path(__file__).resolve().parent.parent / "tests" / "hpke-gate" / "rfc9180-a3-base.json"


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    assert 0 <= length <= 255 * 32
    result = b""
    previous = b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        result += previous
    return result[:length]


def labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def labeled_expand(suite_id: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite_id + label + info, length)


def require_equal(label: str, actual: bytes, expected_hex: str) -> None:
    expected = bytes.fromhex(expected_hex)
    if actual != expected:
        raise AssertionError(f"{label}: reference vector mismatch")


def expect_invalid_tag(action) -> None:
    try:
        action()
    except InvalidTag:
        return
    raise AssertionError("Tampered ciphertext, AAD, recipient or info unexpectedly authenticated")


def verify() -> None:
    data = json.loads(VECTOR.read_text(encoding="utf-8"))
    assert (data["mode"], data["kem_id"], data["kdf_id"], data["aead_id"]) == (0, 16, 1, 1)
    suite = b"HPKE" + bytes.fromhex("001000010001")
    kem_suite = b"KEM" + bytes.fromhex("0010")
    sk_e = ec.derive_private_key(int(data["sk_em"], 16), ec.SECP256R1())
    sk_r = ec.derive_private_key(int(data["sk_rm"], 16), ec.SECP256R1())
    enc = sk_e.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    pk_r = sk_r.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    require_equal("enc public key", enc, data["pk_em"])
    require_equal("recipient public key", pk_r, data["pk_rm"])

    # RFC 9180 Section 4.1 DHKEM: input is raw ECDH shared secret, NOT Phase 18's custom HKDF transcript.
    dh_sender = sk_e.exchange(ec.ECDH(), sk_r.public_key())
    dh_recipient = sk_r.exchange(ec.ECDH(), sk_e.public_key())
    assert dh_sender == dh_recipient and len(dh_sender) == 32
    kem_context = enc + pk_r
    eae_prk = labeled_extract(kem_suite, b"", b"eae_prk", dh_sender)
    shared_secret = labeled_expand(kem_suite, eae_prk, b"shared_secret", kem_context, 32)
    require_equal("KEM shared secret", shared_secret, data["shared_secret"])

    # RFC 9180 Section 5.1: Base mode, empty PSK and PSK ID.
    psk_id_hash = labeled_extract(suite, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(suite, b"", b"info_hash", bytes.fromhex(data["info"]))
    context = b"\x00" + psk_id_hash + info_hash
    require_equal("key schedule context", context, data["key_schedule_context"])
    secret = labeled_extract(suite, shared_secret, b"secret", b"")
    require_equal("key schedule secret", secret, data["secret"])
    key = labeled_expand(suite, secret, b"key", context, 16)
    base_nonce = labeled_expand(suite, secret, b"base_nonce", context, 12)
    exporter_secret = labeled_expand(suite, secret, b"exp", context, 32)
    require_equal("AEAD key", key, data["key"])
    require_equal("AEAD base nonce", base_nonce, data["base_nonce"])
    require_equal("exporter secret", exporter_secret, data["exporter_secret"])

    aead = AESGCM(key)
    for row in data["encryptions"]:
        seq = row["sequence"]
        nonce = bytes(a ^ b for a, b in zip(base_nonce, seq.to_bytes(12, "big"), strict=True))
        pt, aad, ct = (bytes.fromhex(row[f]) for f in ("plaintext", "aad", "ciphertext"))
        require_equal(f"seq={seq} nonce", nonce, row["nonce"])
        assert aead.encrypt(nonce, pt, aad) == ct, f"seq={seq} ciphertext mismatch"
        assert aead.decrypt(nonce, ct, aad) == pt, f"seq={seq} roundtrip mismatch"
        expect_invalid_tag(lambda: aead.decrypt(nonce, ct[:-1] + bytes([ct[-1] ^ 1]), aad))
        expect_invalid_tag(lambda: aead.decrypt(nonce, ct, aad + b"tampered"))

    # Control cases: re-keying for different HPKE info or a different recipient must not authenticate.
    sample = data["encryptions"][0]
    nonce = bytes.fromhex(sample["nonce"])
    ct = bytes.fromhex(sample["ciphertext"])
    aad = bytes.fromhex(sample["aad"])
    other_info_hash = labeled_extract(suite, b"", b"info_hash", bytes.fromhex(data["info"]) + b"!")
    other_context = b"\x00" + psk_id_hash + other_info_hash
    other_key = labeled_expand(suite, secret, b"key", other_context, 16)
    expect_invalid_tag(lambda: AESGCM(other_key).decrypt(nonce, ct, aad))
    other_receiver = ec.generate_private_key(ec.SECP256R1())
    bad_dh = other_receiver.exchange(ec.ECDH(), sk_e.public_key())
    bad_pk = other_receiver.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    bad_shared = labeled_expand(kem_suite, labeled_extract(kem_suite, b"", b"eae_prk", bad_dh), b"shared_secret", enc + bad_pk, 32)
    bad_secret = labeled_extract(suite, bad_shared, b"secret", b"")
    bad_key = labeled_expand(suite, bad_secret, b"key", context, 16)
    expect_invalid_tag(lambda: AESGCM(bad_key).decrypt(nonce, ct, aad))
    print(f"PASS: official RFC 9180 A.3.1 Base vector, {len(data['encryptions'])} sequences, 14 tamper checks, recipient/info mismatch")
    print("REFERENCE ONLY: .NET Seal/Open and product security gate are NOT validated by this script.")


if __name__ == "__main__":
    verify()
