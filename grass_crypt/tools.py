"""
Вспомогательные утилиты.
"""
import os
from enum import Enum
from hashlib import blake2b
from typing import Optional, Any


class EncryptMode(Enum):
    ECB = 'ECB'
    CBC = 'CBC'
    CFB = 'CFB'
    OFB = 'OFB'
    CTR = 'CTR'

    def as_bytes(self) -> bytes:
        return self.value.encode('utf-8')

    @classmethod
    def me_from_value(cls, value: str) -> 'EncryptMode':
        """ Создать экземпляр класса на основе переданного значения элемента.

        :param value: Искомое значение элемента набора.
        :returns:
            Экземпляр класса EncryptMode.
        :raises ValueError: При отсутствии запрошенного значения.
        """
        for name, v in cls.__members__.items():
            if v.value == value:
                return cls(name)
        cls._raise_unknown()

    @classmethod
    def me_from_name(cls, name: str) -> 'EncryptMode':
        """ Создать экземпляр класса на основе имени элемента.

        :param name: Имя требуемого элемента набора.
        :returns:
            Экземпляр класса EncryptMode.
        :raises ValueError: При отсутствии запрошенного элемента.
        """
        return cls(name) if name in cls.__members__ else cls._raise_unknown()

    @staticmethod
    def _raise_unknown() -> None:
        raise ValueError('Unknown encrypt mode')


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


def load_file(filepath: str,
              *,
              binary: bool = False) -> str | bytes:
    """ Обёртка для загрузки содержимого файлов.

    :param filepath: Путь к файлу.
    :param binary: Открыть как бинарный файл.
    :returns:
        Содержимое файла, строковое или бинарное.
    """

    with open(filepath, mode='rb' if binary else 'r') as file:
        return file.read()


def save_file(filepath: str, *, data: str | bytes) -> str:
    """ Сохранить предоставленное содержимое в файл.

    :param filepath: Путь к файлу для записи.
    :param data: Данные для сохранения (строковые или бинарные).
    :returns:
        Ссылка на сохранённый файл.
    """

    if not isinstance(data, (str, bytes)):
        raise TypeError(f'data must be str or bytes, not {type(data)}')

    with open(filepath, mode='wb' if isinstance(data, bytes) else 'w') as file:
        file.write(data)

    return filepath


def make_meta(*,
              plaintext_type: type[bytes | str],
              salt: bytes,
              mode: EncryptMode) -> bytes:
    """
    Создать строку метаданных для добавления к шифровке.

    Схема:

    - 3 байта — STR/BYT — тип входных данных на шифровку (str, bytes)
    - 3 байта — EncryptMode
    - 16 байтов — соль для хеша кодовой фразы

    :returns:
        Байтовая строка с основными данными.
    """

    if plaintext_type == str or plaintext_type == bytes:
        data_type = str(plaintext_type.__name__)[:3].upper()
    else:
        raise ValueError('plaintext_type must be str or bytes')

    return data_type.encode('utf-8') + mode.as_bytes() + salt


def read_meta(*,
              ciphertext: bytes
              ) -> tuple[Optional[Exception], bytes, dict[str, Any]]:
    """
    Считать и распаковать метаданные из зашифрованного текста.

    :param ciphertext: Шифрованный текст.
    :returns:
        Три элемента: экземпляр исключения, если возникли ошибки при
        декодировании метаданных или None; зашифрованный текст за вычетом
        строки метаданных; словарь с аргументами метаданных.
    """

    try:
        if len(ciphertext) < 22:
            raise ValueError('metadata string is incorrect (short line)')

        source_type = {
            'STR': str, 'BYT': bytes
        }[ciphertext[:3].decode('utf-8')]
        meta_data: dict[str, Any] = {
            'source_type': source_type,
            'mode': EncryptMode.me_from_value(
                ciphertext[3:6].decode('utf-8')),
            'salt': ciphertext[6:22],
        }

        return None, ciphertext[22:], meta_data

    except Exception as err:
        return err, b'', {}
