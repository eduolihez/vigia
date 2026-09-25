from __future__ import annotations

from vigia.crypto import decrypt, encrypt


def test_encrypt_decrypt_roundtrip() -> None:
    ciphertext = encrypt("some-secret-key", "hunter2")
    assert ciphertext != b"hunter2"
    assert decrypt("some-secret-key", ciphertext) == "hunter2"


def test_different_keys_produce_different_ciphertext() -> None:
    a = encrypt("key-a", "hunter2")
    b = encrypt("key-b", "hunter2")
    assert a != b
