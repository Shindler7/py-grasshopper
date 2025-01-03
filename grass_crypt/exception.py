"""
Собственные исключения.
"""
from typing import Optional


class GrassCryptException(Exception):
    """
    Базовое исключение.
    """

    def __init__(self, message: Optional[str] = None, *args, **kwargs):
        self.message = message or 'An error occurred during encryption'
        super().__init__(self.message)


class CodeMismatchError(GrassCryptException):
    """
    Несовпадение кодовых фраз.
    """

    message = 'Passphrases do not match.'
