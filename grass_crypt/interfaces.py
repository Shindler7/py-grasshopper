"""
Интерфейс взаимодействия с инфраструктурой шифрования cryptor.
"""
from cryptor import do_encrypt, do_decrypt


def encrypt(plaintext: str, *, key_pass: str) -> str:
    """
    Закодировать переданную кодовую строку.

    :param plaintext: Текст для кодирования.
    :param key_pass: Ключ для кодирования.
    :returns: Закодированная строка.
    """

    return do_encrypt(plaintext, key_pass)


def decrypt(plaintext: str, *, key_pass: str) -> str:
    """
    Декодировать переданную строку.

    :param plaintext: Текс для декодирования.
    :param key_pass: Ключ для декодирования.
    :returns: Декодированный текст.
    """

    return do_decrypt(plaintext, key_pass)


text = """There were cities and distances between us. I was looking for 
travel, but you were attracted to TV series!
"""

key = 'test1234'

res = encrypt(text, key_pass=key)
print(res)

res2 = decrypt(res, key_pass=key)
print(res2)
