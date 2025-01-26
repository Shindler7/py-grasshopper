"""
Основные элементы обеспечения шифрации и дешифрации.
"""
import warnings

from cryptor import do_encrypt, do_decrypt  # noqa

from .tools import EncryptMode


def encrypting_rust(plaintext: bytes,
                    *,
                    code: bytes,
                    mode: EncryptMode) -> bytes:
    """ Мост с Rust для шифрования открытого текста.

    :returns:
        Возвращает зашифрованный текст без метаданных.
    """

    return do_encrypt(plaintext, code, mode.value)


def decrypting_rust(ciphertext: bytes,
                    *,
                    code: bytes,
                    mode: EncryptMode) -> bytes:
    """ Мост с Rust для дешифрования предоставленного текста.

    :returns:
        Возвращает дешифрованный текст.
    """

    return do_decrypt(ciphertext, code, mode.value)


def _mode_warning(mode: EncryptMode):
    """ Предупреждение об ограничении использования режима ``mode`` """
    if mode != EncryptMode.ECB:
        warnings.warn(
            'The mode attribute currently supports only ECB mode.',
            RuntimeWarning,
        )
