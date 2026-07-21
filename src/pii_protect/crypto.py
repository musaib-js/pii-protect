"""
pii_protect.crypto
===================
AES-256-GCM encryption helper used by PIIMaskingEngine to encrypt PII
values before they are handed to a storage backend, and to decrypt them
on unmask.

Encryption:
  - AES-256-GCM with a fresh 96-bit (12-byte) IV per encryption operation.
  - GCM produces a 128-bit (16-byte) authentication tag stored alongside
    the ciphertext.
  - The entity type is used as additional authenticated data (AAD) to
    prevent token/value swapping attacks (the tag covers the entity type).

This module has no storage or NER dependencies — it is pure crypto and
can be reused/tested in isolation.

Author: Musaib Altaf
"""

from __future__ import annotations

import logging
import secrets
from typing import NamedTuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pii_protect.exceptions import DecryptionError

logger = logging.getLogger(__name__)

AES_KEY_LEN_BYTES = 32  # 256-bit key
IV_LEN_BYTES = 12  # 96-bit IV (GCM standard)
TAG_LEN_BYTES = 16  # 128-bit GCM auth tag


class Ciphertext(NamedTuple):
    """Result of an encrypt operation: ciphertext, IV, and auth tag, stored separately."""

    ciphertext: bytes
    iv: bytes
    tag: bytes


class AESGCMCipher:
    """
    Thin wrapper around ``cryptography``'s AESGCM for PII field-level encryption.

    Attributes
    ----------
    key : bytes
        32-byte AES-256 key. Keep this secret; losing it makes all
        previously masked data permanently unrecoverable.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != AES_KEY_LEN_BYTES:
            raise ValueError(
                f"AES-256-GCM requires a {AES_KEY_LEN_BYTES}-byte key, got {len(key)} bytes."
            )
        self.key = key
        self._aesgcm = AESGCM(key)

    @classmethod
    def generate_key(cls) -> bytes:
        """Generate a new random 32-byte AES-256 key."""
        return secrets.token_bytes(AES_KEY_LEN_BYTES)

    @classmethod
    def from_hex(cls, key_hex: str) -> "AESGCMCipher":
        """
        Build a cipher from a 64-character hex-encoded key string.

        Parameters
        ----------
        key_hex : str
            64 hex characters (32 bytes) of key material.
        """
        key_hex = key_hex.strip()
        if len(key_hex) != AES_KEY_LEN_BYTES * 2:
            raise ValueError(
                f"Expected a {AES_KEY_LEN_BYTES * 2}-character hex key, got {len(key_hex)} characters."
            )
        return cls(bytes.fromhex(key_hex))

    def encrypt(self, plaintext: str, aad: bytes) -> Ciphertext:
        """
        Encrypt a plaintext string.

        Parameters
        ----------
        plaintext : str
            Raw value to encrypt (e.g. a detected PII span).
        aad : bytes
            Additional authenticated data (e.g. the entity type), bound
            into the GCM tag but not encrypted.

        Returns
        -------
        Ciphertext
            (ciphertext, iv, tag) tuple, each stored separately.
        """
        iv = secrets.token_bytes(IV_LEN_BYTES)
        ciphertext_with_tag = self._aesgcm.encrypt(iv, plaintext.encode("utf-8"), aad)
        ciphertext = ciphertext_with_tag[:-TAG_LEN_BYTES]
        tag = ciphertext_with_tag[-TAG_LEN_BYTES:]
        return Ciphertext(ciphertext=ciphertext, iv=iv, tag=tag)

    def decrypt(self, ciphertext: bytes, iv: bytes, tag: bytes, aad: bytes) -> str:
        """
        Decrypt a previously encrypted value.

        Raises
        ------
        DecryptionError
            If AES-GCM tag verification fails (data tampering or wrong key).
        """
        try:
            plaintext_bytes = self._aesgcm.decrypt(iv, ciphertext + tag, aad)
        except Exception as exc:
            raise DecryptionError(
                "AES-GCM decryption failed (bad key, tag, or tampered data)."
            ) from exc
        return plaintext_bytes.decode("utf-8")
