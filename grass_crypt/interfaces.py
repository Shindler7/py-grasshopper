"""Интерфейс взаимодействия с инфраструктурой шифрования cryptor."""

from cryptor import do_decrypt, do_encrypt


def encrypt(plaintext: bytes, *, key: bytes) -> bytes:
    """Закодировать переданную кодовую строку.

    Returns:
        Зашифрованная строка в формате байт.

    """
    return do_encrypt(plaintext, key)


def decrypt(plaintext: bytes, *, key: bytes) -> bytes:
    """Декодировать переданную строку.

    Returns:
        Расшифрованная строка в формате байт.

    """
    return do_decrypt(plaintext, key)


text = b"1234567890123456"
key = bytes([
    0x88,
    0x99,
    0xAA,
    0xBB,
    0xCC,
    0xDD,
    0xEE,
    0xFF,
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0xFE,
    0xDC,
    0xBA,
    0x98,
    0x76,
    0x54,
    0x32,
    0x10,
    0x01,
    0x23,
    0x45,
    0x67,
    0x89,
    0xAB,
    0xCD,
    0xEF,
])

print("Text:", text.hex(" "))
print("Key:", key.hex(" "))

encrypted = encrypt(text, key=key)
print("Enctypted:", encrypted.hex(" "))

decrypted = decrypt(encrypted, key=key)
print("Dectypted:", decrypted.hex(" "))
