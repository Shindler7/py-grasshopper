"""
Интерфейс взаимодействия с инфраструктурой шифрования cryptor.
"""
import base64
import os
from pathlib import Path
from typing import Optional

from ._engine import encrypting_rust, decrypting_rust
from .exceptions import MetaStringError
from .tools import EncryptMode, get_hash_blake2b, make_meta, read_meta


def encrypt(plaintext: str | bytes,
            *,
            code: str,
            mode: EncryptMode = EncryptMode.ECB,
            ) -> bytes:
    """Зашифровать предоставленные данные.

    :param plaintext: Данные для шифрования, текст или bytes-объект.
    :param code: Код шифрования.
    :param mode: Режим шифрования.
    :returns:
        Зашифрованный текст bytes-строкой в формате ASCII.
    :raises UnicodeEncodeErrors: При ошибках декодирования строковых значений
                                 в байт-строки.
    :raises ValueError: При предоставлении неверных аргументов.
    """

    def validate_inputs_data() -> None:
        """Проверка основных входных параметров.
        :raises ValueError: При обнаружении ошибок в данных.
        """
        if not isinstance(plaintext, (str, bytes)) or not plaintext:
            raise ValueError(
                'plaintext must be str, bytes and cannot be empty')
        if not isinstance(code, str) or not code:
            raise ValueError('code must be str and cannot be empty')
        if not isinstance(mode, EncryptMode):
            raise ValueError('mode must be an instance of EncryptMode')

    validate_inputs_data()

    hash_code, salt = get_hash_blake2b(code)
    plaintext_type = type(plaintext)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    encoded_data = encrypting_rust(plaintext, code=hash_code, mode=mode)
    # make metadata
    meta = make_meta(plaintext_type=plaintext_type, salt=salt, mode=mode)

    return base64.b64encode(meta + encoded_data)


def decrypt(ciphertext: bytes, *, code: str) -> str | bytes:
    """Расшифровать предоставленный байт-массив.

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

    try:
        decoded = decrypting_rust(
            ciphertext, code=hash_code, mode=meta_data['mode'])
    except Exception as err:
        err_msg = f'decryption failed: {err}'
        raise MetaStringError(err_msg) from err

    if meta_data['source_type'] == bytes:
        return decoded
    else:
        return decoded.decode('utf-8')


def encrypt_file(*,
                 input_path: str | Path,
                 output_path: Optional[str | Path] = None,
                 overwrite_output: bool = False,
                 code: str,
                 mode: EncryptMode = EncryptMode.ECB) -> Path:
    """Зашифровать предоставленный файл.

    :param input_path: Ссылка на файл для шифрования.
    :param output_path: Ссылка для сохранения зашифрованного файла. **Важно**:
                        если не предоставлено, перезаписывается ``input_path``.
    :param overwrite_output: Если ``False``, поднимется исключение, если файл
                             ``output_path`` существует.
    :param code: Код шифрования.
    :param mode: Режим шифрования.
    :returns:
        Экземпляр Path с путём к зашифрованному файлу.
    """

    input_path, output_path = _valid_path(input_path,
                                          output_path,
                                          overwrite_output)
    try:
        plaintext = input_path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        plaintext = input_path.read_bytes()

    ciphertext = encrypt(plaintext=plaintext, code=code, mode=mode)
    output_path.write_bytes(ciphertext)

    return output_path


def decrypt_file(*,
                 input_path: str | Path,
                 output_path: Optional[str | Path] = None,
                 overwrite_output: bool = False,
                 code: str) -> Path:
    """Расшифровать предоставленный файл.

    Режим шифрования извлекается из метаданных зашифрованного файла.

    :param input_path: Ссылка на файл для дешифровки.
    :param output_path: Ссылка для сохранения дешифрованного файла. Если
                        не предоставлено, перезаписывается ``input_path``.
    :param overwrite_output: Если ``False``, поднимется исключение, если файл
                             ``output_path`` существует.
    :param code: Код шифрования.
    :returns:
         Путь к дешифрованному файлу.
    """
    input_path, output_path = _valid_path(
        input_path, output_path, overwrite_output)

    decrypted = decrypt(ciphertext=input_path.read_bytes(), code=code)
    if isinstance(decrypted, bytes):
        output_path.write_bytes(decrypted)
    else:
        output_path.write_text(decrypted, encoding='utf-8')

    return output_path


def _valid_path(input_path: str | Path,
                output_path: str | Path,
                overwrite: bool) -> tuple[Path, Path]:
    """Проверка исходного и целевого путей для файла.

    Возбуждает исключения, при ошибочных путях или ограничениях на перезапись.

    :param input_path: Исходный файл.
    :param output_path: Целевой файл.
    :param overwrite: Если целевой файл существует, должна быть разрешена
                      его перезапись.
    :returns:
        Экземпляры Path с проверенными путями для чтения и сохранения файла.
    :raises FileNotFoundError: При отсутствии исходного файла.
    :raises FileExistsError: Если целевой файл существует, а перезапись
                             запрещена.
    """
    input_path = Path(input_path)
    if not input_path.is_file():
        raise FileNotFoundError('input_path does not exist or is not a file')
    if output_path is not None:
        output_path = Path(output_path)
        if not overwrite and output_path.is_file():
            raise FileExistsError('output path already exists')
    else:
        output_path = input_path

    # Попробуем создать путь, если не существует.
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    return input_path, output_path
