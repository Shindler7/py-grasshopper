"""
Интерфейс взаимодействия с инфраструктурой шифрования cryptor.
"""
import base64
import warnings
from typing import Optional, Any

from ._engine import encrypting_rust, decrypting_rust
from .exception import MetaStringError
from .tools import EncryptMode, get_hash_blake2b, load_file, save_file


def encrypt(plaintext: str | bytes,
            *,
            code: str,
            mode: EncryptMode = EncryptMode.ECB,
            ) -> bytes:
    """
    Зашифровать предоставленные данные.

    :param plaintext: Данные для шифрования, текст или bytes-объект.
    :param code: Код шифрования.
    :param mode: Режим шифрования.
    :returns:
        Зашифрованный текст bytes-строкой в формате ASCII.
    :raises UnicodeEncodeErrors: При ошибках декодирования строковых значений
                                 в байт-строки.
    :raises ValueError: При предоставлении неверных аргументов.
    """

    if not isinstance(plaintext, (str, bytes)) or not plaintext:
        raise ValueError('plaintext must be str, bytes and cannot be empty')
    else:
        validate_inputs_data(code, mode)

    hash_code, salt = get_hash_blake2b(code)
    plaintext_type = type(plaintext)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    encoded_data = encrypting_rust(plaintext, code=hash_code, mode=mode)
    # make metadata
    meta = make_meta(plaintext_type=plaintext_type,
                     hash_code=hash_code,
                     salt=salt,
                     mode=mode)

    return base64.b64encode(meta + encoded_data)


def decrypt(ciphertext: bytes, *, code: str) -> str | bytes:
    """
    Расшифровать предоставленный байт-массив.

    :param ciphertext: Данные для расшифровки.
    :param code: Код шифрования.
    :returns:
        Строковое или байтовое представление расшифрованного текста.
    :raises ValueError: При предоставлении неверных аргументов.
    :raises MetaStringError: Если предоставлен неверный код шифрования.
    """

    if not isinstance(ciphertext, bytes) or not ciphertext:
        raise ValueError('ciphertext must be bytes and cannot be empty')

    ciphertext = base64.b64decode(ciphertext)
    error, ciphertext, meta_data = read_meta(ciphertext=ciphertext)
    if error is not None:
        raise MetaStringError(str(error)) from error
    hash_code = get_hash_blake2b(code, salt=meta_data['salt'])[0]
    if hash_code != meta_data['hash_code']:
        raise MetaStringError('passphrases do not match')

    decoded = decrypting_rust(
        ciphertext, code=hash_code, mode=meta_data['mode'])
    if meta_data['source_type'] == bytes:
        return decoded

    return decoded.decode('utf-8')


def _encrypt_file(*,
                  input_path: str,
                  output_path: Optional[str] = None,
                  code: str,
                  mode: EncryptMode = EncryptMode.ECB) -> str:
    """
    Зашифровать предоставленный файл.

    :param input_path: Ссылка на файл для шифрования.
    :param output_path: Ссылка для сохранения зашифрованного файла. Если
                        не предоставлено, перезаписывается ``input_path``.
    :param code: Код шифрования.
    :param mode: Режим шифрования.
    :returns:
        Путь к зашифрованному файлу.
    :raises ValueError: При предоставлении неверных аргументов.
    :raises RuntimeError: При ошибках на чтение/запись файлов.
    """

    warnings.warn(
        'The function is currently under development. '
        'The functionality is preliminary.',
        RuntimeWarning
    )

    try:
        file_data = load_file(input_path)
        encrypted_data = encrypt(file_data, code=code, mode=mode)

        if output_path is None:
            output_path = input_path

        save_file(output_path, data=encrypted_data)

        return output_path

    except Exception as err:
        msg_err = f'file encrypting error ({input_path}): {err}'
        raise RuntimeError(msg_err) from err


def _decrypt_file(*,
                  input_path: str,
                  output_path: Optional[str] = None,
                  code: str) -> str:
    """
    Расшифровать предоставленный файл.

    :param input_path: Ссылка на файл для дешифровки.
    :param output_path: Ссылка для сохранения дешифрованного файла. Если
                        не предоставлено, перезаписывается ``input_path``.
    :param code: Код шифрования.
    :returns:
         Путь к дешифрованному файлу.
    :raises ValueError: При предоставлении неверных аргументов.
    :raises RuntimeError: При ошибках на чтение/запись файлов.
    :raises MetaStringError: Если предоставлен неверный код шифрования.
    """

    warnings.warn(
        'The function is currently under development. '
        'The functionality is preliminary.',
        RuntimeWarning
    )

    try:
        file_data = load_file(input_path, binary=True)
        decrypted_data = decrypt(file_data, code=code)

        if output_path is None:
            output_path = input_path

        return save_file(output_path, data=decrypted_data)

    except Exception as err:
        msg_err = f'file decrypting error ({input_path}): {err}'
        raise RuntimeError(msg_err) from err


def validate_inputs_data(code: str, mode: EncryptMode) -> None:
    """
    Проверка основных входных параметров.

    :raises ValueError: При обнаружении ошибок в данных.
    """

    if not isinstance(code, str) or not code:
        raise ValueError('code must be str and cannot be empty')
    if not isinstance(mode, EncryptMode):
        raise ValueError('mode must be an instance of EncryptMode')


def make_meta(*,
              plaintext_type: type[bytes | str],
              hash_code: bytes,
              salt: bytes,
              mode: EncryptMode) -> bytes:
    """
    Создать строку метаданных для добавления к шифровке.

    Схема:

    - 3 байта — STR/BYT — тип входных данных на шифровку (str, bytes)
    - 3 байта — EncryptMode
    - 16 байтов — соль для хеша кодовой фразы
    - 32 байта — хеш кодовой фразы

    :returns:
        Байтовая строка с основными данными.
    """

    if plaintext_type == str or plaintext_type == bytes:
        data_type = str(plaintext_type.__name__)[:3].upper()
    else:
        raise ValueError('plaintext_type must be str or bytes')

    return data_type.encode('utf-8') + mode.as_bytes() + salt + hash_code


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
        if len(ciphertext) < 54:
            raise ValueError('metadata string is incorrect (short line)')

        source_type = {
            'STR': str, 'BYT': bytes
        }[ciphertext[:3].decode('utf-8')]
        meta_data: dict[str, Any] = {
            'source_type': source_type,
            'mode': EncryptMode.me_from_value(ciphertext[3:6].decode('utf-8')),
            'salt': ciphertext[6:22],
            'hash_code': ciphertext[22:54],
        }

        return None, ciphertext[54:], meta_data

    except Exception as err:
        return err, b'', {}
