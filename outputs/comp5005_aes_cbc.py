"""COMP5005 demonstration of CBC bit-flipping and encrypt-then-MAC.

Requires the cryptography package. Run with Python 3.10 or newer.
"""

import hmac
from secrets import token_bytes

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# AES uses 128-bit blocks even when the key is 256 bits. The padding
# API expects bits, while the IV generator takes a byte count.
AES_BLOCK_BITS = algorithms.AES.block_size
AES_BLOCK_BYTES = AES_BLOCK_BITS // 8
KEY_BYTES = 32


def encrypt(aes_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    # CBC needs a fresh, unpredictable IV for each encryption.
    iv = token_bytes(AES_BLOCK_BYTES)
    # PKCS#7 makes the plaintext a whole number of AES blocks.
    padder = padding.PKCS7(AES_BLOCK_BITS).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext


def decrypt(aes_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    # This function handles only CBC decryption. The caller is responsible
    # for checking the tag when authentication is enabled.
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    # Strip the padding after decrypting the complete message.
    unpadder = padding.PKCS7(AES_BLOCK_BITS).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def authentication_tag(hmac_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    # Cover both values so that changing the IV or ciphertext invalidates
    # the original tag. Both sides use the same byte order.
    return hmac.digest(hmac_key, iv + ciphertext, "sha256")


def verify_and_decrypt(
    aes_key: bytes, hmac_key: bytes, iv: bytes, ciphertext: bytes, received_tag: bytes
) -> bytes | None:
    expected_tag = authentication_tag(hmac_key, iv, ciphertext)
    # Compare the tags without stopping at the first different byte.
    # Returning here is the Python equivalent of closing the CrypTool Gate.
    if not hmac.compare_digest(expected_tag, received_tag):
        return None
    return decrypt(aes_key, iv, ciphertext)


def main() -> None:
    message = "PL4 8AA, Drake Circus, this is a secret code: 453"
    plaintext = message.encode("utf-8")
    # Alice and Bob use independent shared secrets for AES and HMAC.
    aes_key = token_bytes(KEY_BYTES)
    hmac_key = token_bytes(KEY_BYTES)
    iv, ciphertext = encrypt(aes_key, plaintext)

    print("Alice's AES-256-CBC encryption with PKCS#7 padding")
    print(f"Plaintext: {len(plaintext)} bytes")
    print(f"PKCS#7 padding: {len(ciphertext) - len(plaintext)} bytes")
    print(f"IV: {len(iv)} bytes | Ciphertext: {len(ciphertext)} bytes")
    print("IV (hex):", iv.hex(" ").upper())
    print("Ciphertext (hex):", ciphertext.hex(" ").upper())

    # Flip the lowest bit of the first IV byte. CBC applies the same change
    # to the first plaintext byte, turning P into Q without altering ciphertext.
    tampered_iv = bytes([iv[0] ^ 0x01]) + iv[1:]
    original = decrypt(aes_key, iv, ciphertext)
    altered = decrypt(aes_key, tampered_iv, ciphertext)
    print("\nBefore the fix (CBC only)")
    print("Plaintext with original IV:", original.decode("utf-8"))
    print(f"First IV byte flipped: {iv[0]:02X} -> {tampered_iv[0]:02X}")
    print("Plaintext with tampered IV:", altered.decode("utf-8"))

    # Alice authenticates the original IV followed by the ciphertext.
    tag = authentication_tag(hmac_key, iv, ciphertext)
    verified = verify_and_decrypt(aes_key, hmac_key, iv, ciphertext, tag)
    # The attacker reuses Alice's original tag with the altered IV.
    rejected = verify_and_decrypt(aes_key, hmac_key, tampered_iv, ciphertext, tag)
    # Check both runs so a failure on the original message cannot pass as a fix.
    if verified != plaintext or rejected is not None:
        raise RuntimeError("Unexpected result in the HMAC verification demonstration")

    print(f"\nAfter the fix (HMAC-SHA256, {len(tag)}-byte tag)")
    print("Alice's tag (hex):", tag.hex(" ").upper())
    print("Valid tag:", verified.decode("utf-8"))
    print("Tampered IV: rejected before AES decryption")


if __name__ == "__main__":
    main()
