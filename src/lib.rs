//! Экспериментальный шифратор Python + Rust.
//!
//! ```python
//! from cryptor import do_encrypt
//!
//! p = 'test string'.encode('utf-8')
//! k = 'pass12345'.encode('utf-8')  # Ключ должен быть длиной 32 байта.
//! m = 'ECB'
//!
//! result = do_encrypt(p, k, m)
//! ```
//!
//! Подробности в README.md.

mod engine;

use block_encryption::traits::CipherError;
use block_encryption::traits::CipherError::*;
use pyo3::exceptions::PyValueError;
use pyo3::import_exception;
use pyo3::marker::*;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

import_exception!(grass_crypt.exceptions, KeyLengthError);
import_exception!(grass_crypt.exceptions, IVLengthError);
import_exception!(grass_crypt.exceptions, BlockSizeError);
import_exception!(grass_crypt.exceptions, DataTooShortError);
import_exception!(grass_crypt.exceptions, DataNotAlignedError);
import_exception!(grass_crypt.exceptions, InvalidPaddingError);
import_exception!(grass_crypt.exceptions, InvalidKeyFormatError);
import_exception!(grass_crypt.exceptions, InvalidModeError);

/// Шифратор.
///
/// - plaintext — Текст для шифрования
/// - key — Ключ для шифрования
/// - encrypt_mode — Режим шифрования
#[pyfunction]
#[pyo3(name = "do_encrypt")]
#[pyo3(signature = (plaintext, key, encrypt_mode))]
fn do_encrypt<'py>(
    plaintext: Bound<'py, PyBytes>,
    key: Bound<'py, PyBytes>,
    encrypt_mode: Bound<'py, PyString>,
) -> PyResult<Vec<u8>> {
    let (pt, k) = extract_text_and_key(&plaintext, &key)?;
    let encrypt_result = engine::encrypting(pt, k, to_string(&encrypt_mode));

    Ok(rust_to_py_err(encrypt_result)?)
}

/// Дешифратор.
///
/// - ciphertext — Зашифрованный текст для дешифровки
/// - key — Ключ для дешифровки
/// - encrypt_mode — Режим шифрования
#[pyfunction]
#[pyo3(name = "do_decrypt")]
#[pyo3(signature = (ciphertext, key, encrypt_mode))]
fn do_decrypt<'py>(
    ciphertext: Bound<'py, PyBytes>,
    key: Bound<'py, PyBytes>,
    encrypt_mode: Bound<'py, PyString>,
) -> PyResult<Vec<u8>> {
    let (ct, k) = extract_text_and_key(&ciphertext, &key)?;
    let decrypt_result = engine::decrypting(ct, k, to_string(&encrypt_mode));

    Ok(rust_to_py_err(decrypt_result)?)
}

/// Модуль, который может быть импортирован в Python.
#[pymodule]
fn cryptor(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(do_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(do_decrypt, m)?)?;
    Ok(())
}

/// Конвертер ошибок Rust-библиотеки в Python-исключения.
fn rust_to_py_err(result: Result<Vec<u8>, CipherError>) -> Result<Vec<u8>, PyErr> {
    match result {
        Ok(r) => Ok(r),
        Err(e) => match e {
            InvalidKeyLenght => Err(KeyLengthError::new_err(
                "The key length is invalid (must be 32 bytes)",
            )),
            InvalidIVLenght => Err(IVLengthError::new_err("The IV length is invalid")),
            InvalidBlockSize => Err(BlockSizeError::new_err("The block size is invalid")),
            DataTooShort => Err(DataTooShortError::new_err(
                "The data is too short to process",
            )),
            DataNotAligned => Err(DataNotAlignedError::new_err(
                "The data is not aligned to block size",
            )),
            // InvalidPadding возникает при несовпадении ключа.
            InvalidPadding => Err(InvalidPaddingError::new_err("The padding is invalid")),
            InvalidKeyFormat => Err(InvalidKeyFormatError::new_err("The key format is invalid")),
            InvalidMode => Err(InvalidModeError::new_err("The mode is invalid")),
        },
    }
}

/// Преобразователь Python-строки в &str.
fn to_string<'a>(data: &'a Bound<PyString>) -> &'a str {
    data.to_str().unwrap()
}

/// Преобразователь PyBytes для текста и ключа в Vec<u8>.
///
/// Одновременно проводятся базовые проверки.
pub fn extract_text_and_key<'py>(
    text: &Bound<'py, PyBytes>,
    key: &Bound<'py, PyBytes>,
) -> Result<(Vec<u8>, Vec<u8>), PyErr> {
    let text: Vec<u8> = text.extract()?;
    let key: Vec<u8> = key.extract()?;

    if text.is_empty() || key.is_empty() {
        return Err(PyValueError::new_err(
            "'text' and the 'key' cannot be empty",
        ));
    }

    Ok((text, key))
}
