"""
Интерфейс взаимодействия с инфраструктурой шифрования cryptor.
"""

import base64
from typing import Optional

from ._engine import encrypting_rust, decrypting_rust
from .exception import CodeMismatchError
from .tools import EncryptMode, get_hash_blake2b


def encrypt(plaintext: str,
            *,
            code: str,
            mode: EncryptMode = EncryptMode.ECB,
            ) -> bytes:
    """ Зашифровать предоставленный текст.

    :param plaintext: Открытый текст для шифрования.
    :param code: Код шифрования.
    :param mode: Режим шифрования.
    :returns:
        Зашифрованный текст bytes-строке в формате ASCII.
    :raises UnicodeEncodeErrors: При ошибках декодирования строковых значений
                                 в байт-строки.
    :raises ValueErrors: При предоставлении неверных аргументов.
    """

    validate_inputs_data(plaintext, mode)

    if not isinstance(plaintext, str) or not plaintext:
        raise ValueError('plaintext must be str and cannot be empty')

    plaintext: bytes = plaintext.encode('utf-8')
    code, salt = get_hash_blake2b(code)

    encoded = encrypting_rust(plaintext, code, mode)
    return base64.b64encode(salt + code + encoded)


def encrypt_file(*,
                 input_path: str,
                 output_path: Optional[str] = None,
                 code: str,
                 mode: EncryptMode = EncryptMode.ECB) -> str:
    """ Зашифровать предоставленный файл.

    :param input_path: Ссылка на файл для шифрования.
    :param output_path: Ссылка для сохранения зашифрованного файла. Если
                        не предоставлено, перезаписывается ``input_path``.
    :param code: Код шифрования.
    :param mode: Режим шифрования.
    :returns:
        Путь к зашифрованному файлу.
    :raises ValueErrors: При предоставлении неверных аргументов.
    :raises RuntimeError: При ошибках на чтение/запись файлов.
    """

    validate_inputs_data(code, mode)

    try:
        # Чтение
        with open(input_path, 'r', encoding='utf-8') as input_file:
            file_data = input_file.read()

    except (FileNotFoundError, OSError) as e:
        raise RuntimeError(
            f'error reading input_file {input_path}: {e}') from e

    encrypted_data = encrypt(file_data, code=code, mode=mode)

    try:
        if output_path is None:
            output_path = input_path
        with open(output_path, 'w+') as output_file:
            output_file.write(encrypted_data)
        return output_path

    except (FileNotFoundError, OSError) as e:
        raise FileNotFoundError(
            f'error writing output file {output_path}: {e}') from e


def decrypt(ciphertext: bytes,
            *,
            code: str,
            mode: EncryptMode = EncryptMode.ECB,
            ignore_mismatch_code: bool = False) -> str:
    """ Расшифровать предоставленный байт-массив.

    :param ciphertext: Текст для расшифровки.
    :param code: Код шифрования.
    :param mode: Режим шифрования.
    :param ignore_mismatch_code: По-умолчанию происходит сверка хеш-кодов, и
                                 если они не соответствует, возбуждается
                                 исключение.
    :returns:
        Строковое представление расшифрованного текста.
    :raises ValueErrors: При предоставлении неверных аргументов.
    :raises CodeMismatchError: Если предоставлен неверный код шифрования.
    """

    validate_inputs_data(code, mode)

    ciphertext = base64.b64decode(ciphertext)
    salt = ciphertext[:16]
    code_cipher = ciphertext[16:48]
    code = get_hash_blake2b(code, salt=salt)[0]
    if code == code_cipher:
        ciphertext = ciphertext[48:]
    else:
        if not ignore_mismatch_code:
            raise CodeMismatchError()

    decoded = decrypting_rust(ciphertext, code=code, mode=mode)

    return decoded.decode('utf-8')


def decrypt_file(*,
                 input_path: str,
                 output_path: Optional[str] = None,
                 code: str,
                 mode: EncryptMode = EncryptMode.ECB) -> str:
    """ Расшифровать предоставленный файл.

    :param input_path: Ссылка на файл для дешифровки.
    :param output_path: Ссылка для сохранения дешифрованного файла. Если
                        не предоставлено, перезаписывается ``input_path``.
    :param code: Код шифрования.
    :param mode: Режим шифрования.
    :returns:
         Путь к дешифрованному файлу.
    :raises ValueErrors: При предоставлении неверных аргументов.
    :raises RuntimeError: При ошибках на чтение/запись файлов.
    :raises CodeMismatchError: Если предоставлен неверный код шифрования.
    """

    validate_inputs_data(code, mode)

    try:
        with open(input_path, 'rb') as input_file:
            file_data = input_file.read()

    except (FileNotFoundError, OSError) as e:
        raise RuntimeError(
            f'error reading input_file {input_path}: {e}') from e

    decrypted_data = decrypt(file_data, code=code, mode=mode)

    try:
        if output_path is None:
            output_path = input_path

        with open(output_path, 'w+') as output_file:
            output_file.write(decrypted_data)

        return output_path

    except (FileNotFoundError, OSError) as e:
        raise FileNotFoundError(
            f'error writing output file {output_path}: {e}') from e


def validate_inputs_data(code: str, mode: EncryptMode) -> None:
    """ Проверка основных входных параметров.

    :raises ValueError: При обнаружении ошибок в данных.
    """

    if not isinstance(code, str) or not code:
        raise ValueError('code must be str and cannot be empty')
    if not isinstance(mode, EncryptMode):
        raise ValueError('mode must be an instance of EncryptMode')
