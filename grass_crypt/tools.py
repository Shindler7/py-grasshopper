"""
Вспомогательные утилиты.
"""
import os
from enum import Enum
from hashlib import blake2b
from typing import Optional


class EncryptMode(Enum):
    ECB = 'ECB'
    CBC = 'CBC'
    CFB = 'CFB'
    OFB = 'OFB'
    CTR = 'CTR'


def get_hash_blake2b(value: str,
                     *,
                     digest_size: int = 32,
                     salt: Optional[bytes] = None) -> (bytes, bytes):
    """ Возвращает байтовый хеш формата Blake2b для переданной строки.

    :param value: Строковое значение для хеширования.
    :param digest_size: Blake2 имеет настраиваемый размер дайджестов (длина
                        конечного хеша). Диапазон от 1 до 64 байт.
    :param salt: Опционально: соль для хеша. Если не предоставлено,
                 генерируется.
    :returns:
        Кортеж с двумя значениями: хеш переданного значения и соль.
    :raise TypeError: Если переданная строка не str или digest_size не int.
    :raise ValueError: При неверном значении digest_size.
    """

    if not isinstance(value, str) or not isinstance(digest_size, int):
        raise TypeError(value)
    if not (1 <= digest_size <= 64):
        raise ValueError(digest_size)

    if salt is None:
        salt = get_salt()

    return blake2b(value.encode('utf-8'),
                   digest_size=digest_size,
                   salt=salt
                   ).digest(), salt


def get_salt() -> bytes:
    """ Предоставить соли для хеша.

    :returns: Солёная байт-строка.
    """

    return os.urandom(blake2b.SALT_SIZE)
