"""
Собственные исключения.
"""
from typing import Optional


class GrassCryptException(Exception):
    """
    Базовое исключение.
    """

    def __init__(self, message: Optional[str] = None):
        self.message = message or 'An error occurred during encryption'
        super().__init__(self.message)


class MetaStringError(GrassCryptException):
    """
    Несовпадение кодовых фраз.
    """
    message = 'The metadata string is missing or incorrect'


class KeyLengthError(GrassCryptException):
    """
    Неправильная длина ключа: должно быть 32 байта.
    """
    message = 'The key length is invalid (must be 32 bytes)'


class IVLengthError(GrassCryptException):
    """
    Неправильная длина вектора инициализации.
    """
    message = 'The IV length is invalid'


class BlockSizeError(GrassCryptException):
    """
    Неправильный размер блока.
    """
    message = 'The block size is invalid'


class DataTooShortError(GrassCryptException):
    """
    Данные слишком короткие для обработки.
    """
    message = 'The data is too short to process'


class DataNotAlignedError(GrassCryptException):
    """
    Данные не выровнены по размеру блока.
    """
    message = 'The data is not aligned to block size'


class InvalidPaddingError(GrassCryptException):
    """
    Неправильное выравнивание данных.
    """
    message = 'The padding is invalid'


class InvalidKeyFormatError(GrassCryptException):
    """
    Неправильный формат ключа.
    """
    message = 'The key format is invalid'


class InvalidModeError(GrassCryptException):
    """
    Неправильный режим шифрования/дешифрования.
    """
    message = 'The mode is invalid'
