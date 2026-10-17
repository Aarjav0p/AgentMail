"""Cryptographic envelope operations for the AgentMail relay.

Every function is pure and stateless — they operate on raw key bytes /
hex strings and return deterministic results.  All secret handling is
left to :pymod:`relay.crypto.vault`.

Uses PyNaCl (libsodium) exclusively for cryptographic primitives.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets

import nacl.secret
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey

from relay.config import settings

# -- Base62 alphabet used for API key generation -------------------------
_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


# -----------------------------------------------------------------------
# Server KEK helpers (§4)
# -----------------------------------------------------------------------


def get_server_kek_bytes() -> bytes:
    """Return decoded 32-byte server KEK from settings."""
    if not settings.encryption_key:
        raise ValueError("ENCRYPTION_KEY is not configured.")
    key = base64.b64decode(settings.encryption_key)
    if len(key) != 32:
        raise ValueError("ENCRYPTION_KEY must be exactly 32 bytes (base64-encoded).")
    return key


def encrypt_server_kek(plaintext: str) -> str:
    """Encrypt plaintext string with the server KEK using SecretBox."""
    kek = get_server_kek_bytes()
    box = nacl.secret.SecretBox(kek)
    return base64.b64encode(bytes(box.encrypt(plaintext.encode("utf-8")))).decode("ascii")


def decrypt_server_kek(ciphertext_b64: str) -> str:
    """Decrypt a base64-encoded ciphertext using the server KEK."""
    kek = get_server_kek_bytes()
    box = nacl.secret.SecretBox(kek)
    return box.decrypt(base64.b64decode(ciphertext_b64)).decode("utf-8")


def decrypt_server_kek_blob(key_blob_b64: str) -> tuple[bytes, bytes] | None:
    """Decrypt a server-custody key blob and return (enc_sk, sign_sk)."""
    try:
        blob_plaintext = decrypt_server_kek(key_blob_b64)
        blob = json.loads(blob_plaintext)
        current = blob["epochs"][-1]
        return bytes.fromhex(current["enc_sk"]), bytes.fromhex(current["sign_sk"])
    except Exception:
        return None


# -----------------------------------------------------------------------
# Fingerprint
# -----------------------------------------------------------------------


def generate_fingerprint(enc_pub_hex: str, sign_pub_hex: str) -> str:
    """Produce a human-readable fingerprint from an agent's public keys.

    The fingerprint is the first 16 bytes of ``SHA-256(enc_pub || sign_pub)``
    formatted as four groups of four uppercase hex characters separated by
    spaces, e.g. ``A3F9 27C1 88D0 4E21``.

    Args:
        enc_pub_hex: X25519 public key as a hex string.
        sign_pub_hex: Ed25519 public key as a hex string.

    Returns:
        Formatted fingerprint string.
    """
    digest = hashlib.sha256(
        bytes.fromhex(enc_pub_hex) + bytes.fromhex(sign_pub_hex),
    ).digest()
    first_8 = digest[:8].hex().upper()
    return " ".join(first_8[i : i + 4] for i in range(0, 16, 4))


# -----------------------------------------------------------------------
# Sealed-box encrypt / decrypt
# -----------------------------------------------------------------------


def seal_message(payload_json: str, recipient_enc_pub_hex: str) -> str:
    """Encrypt *payload_json* to the recipient's X25519 public key.

    Uses NaCl ``SealedBox`` (anonymous sender).

    Args:
        payload_json: The JSON payload to encrypt.
        recipient_enc_pub_hex: Recipient's X25519 public key as hex.

    Returns:
        Standard base64-encoded ciphertext.
    """
    pub = PublicKey(bytes.fromhex(recipient_enc_pub_hex))
    box = SealedBox(pub)
    ciphertext = box.encrypt(payload_json.encode("utf-8"))
    return base64.b64encode(ciphertext).decode("ascii")


def open_message(ciphertext_b64: str, recipient_enc_sk_bytes: bytes) -> str:
    """Decrypt a sealed-box ciphertext using the recipient's secret key.

    Args:
        ciphertext_b64: Standard base64-encoded ciphertext.
        recipient_enc_sk_bytes: Recipient's X25519 secret key (raw 32 bytes).

    Returns:
        Decrypted plaintext JSON string.
    """
    sk = PrivateKey(recipient_enc_sk_bytes)
    box = SealedBox(sk)
    plaintext = box.decrypt(base64.b64decode(ciphertext_b64))
    return plaintext.decode("utf-8")


# -----------------------------------------------------------------------
# Ed25519 signing
# -----------------------------------------------------------------------


def sign_ciphertext(ciphertext_bytes: bytes, sender_sign_sk_bytes: bytes) -> str:
    """Create a detached Ed25519 signature over *ciphertext_bytes*.

    Args:
        ciphertext_bytes: The raw ciphertext to sign.
        sender_sign_sk_bytes: Sender's Ed25519 signing key (seed or full 64-byte).

    Returns:
        Standard base64-encoded signature.
    """
    signing_key = SigningKey(sender_sign_sk_bytes)
    signed = signing_key.sign(ciphertext_bytes)
    # ``signed.signature`` is the detached 64-byte signature.
    return base64.b64encode(signed.signature).decode("ascii")


def verify_signature(
    ciphertext_bytes: bytes,
    sig_b64: str,
    sender_sign_pub_hex: str,
) -> bool:
    """Verify a detached Ed25519 signature.

    Args:
        ciphertext_bytes: The raw ciphertext that was signed.
        sig_b64: Standard base64-encoded detached signature.
        sender_sign_pub_hex: Sender's Ed25519 verify key as hex.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
        Never raises on invalid signatures.
    """
    try:
        verify_key = VerifyKey(bytes.fromhex(sender_sign_pub_hex))
        signature = base64.b64decode(sig_b64)
        verify_key.verify(ciphertext_bytes, signature)
        return True
    except Exception:  # noqa: BLE001 — intentionally broad
        return False


# -----------------------------------------------------------------------
# API key helpers
# -----------------------------------------------------------------------


def hash_api_key(api_key: str) -> str:
    """Return the SHA-256 hex digest of *api_key*.

    This is the value stored in ``agents.api_key_hash``.
    """
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    """Generate a new API key with the ``am_live_`` prefix.

    Format: ``am_live_`` followed by 43 base62 characters derived from
    32 bytes of cryptographic randomness.

    Returns:
        A new API key string (total length 51).
    """
    raw = secrets.token_bytes(32)
    # Convert the 32-byte integer to base62.
    num = int.from_bytes(raw, "big")
    chars: list[str] = []
    base = len(_BASE62)
    while num > 0:
        num, remainder = divmod(num, base)
        chars.append(_BASE62[remainder])
    # Pad to exactly 43 characters (leading zeros in base62).
    while len(chars) < 43:
        chars.append(_BASE62[0])
    return "am_live_" + "".join(reversed(chars))[:43]
