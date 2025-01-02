pub mod cipher;
pub mod mode;
pub mod padding;
pub mod traits;

use cipher::kuznyechik::cipher::Kuznyechik;
use mode::ECB;
use padding::PKCS7;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use traits::{CipherError, Encryptor};

/// Шифратор.
///
/// - text — текст для шифрования
#[pyfunction]
#[pyo3(name = "do_encrypt")]
#[pyo3(signature = (text, key))]
fn do_encrypt(text: Bound<'_, PyBytes>, key: Bound<'_, PyBytes>) -> PyResult<Vec<u8>> {
    let tuple_data = extract_text_and_key(&text, &key)?;

    let encrypt_result = encrypting(tuple_data.0, tuple_data.1);
    Ok(encrypt_result)
}

/// # Дешифратор.
#[pyfunction]
#[pyo3(name = "do_decrypt")]
#[pyo3(signature = (text, key))]
fn do_decrypt(text: Bound<'_, PyBytes>, key: Bound<'_, PyBytes>) -> PyResult<Vec<u8>> {
    let tuple_data = extract_text_and_key(&text, &key)?;

    let decrypt_result = decrypting(tuple_data.0, tuple_data.1);
    Ok(decrypt_result)
}

/// # Модуль, который может быть импортирован в Python.
#[pymodule]
fn cryptor(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(do_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(do_decrypt, m)?)?;
    Ok(())
}

/// # Преобразователь PyBytes для текста и ключа в Vec<u8>.
///
/// Одновременно проводятся базовые проверки.
fn extract_text_and_key(
    text: &Bound<'_, PyBytes>,
    key: &Bound<'_, PyBytes>,
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

/// # Шифрование переданной строки с использованием ключа.
///
/// Ожидается, что проверки аргументов проведены до передачи функции.
///
/// - text — Текст для шифрования
/// - key — Ключ для шифрования
fn encrypting(text: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    // Шифратор работает с массивами u8 в формате HEX.
    // Требуется преобразовать строки.

    let encryptor = get_encryptor(&key).unwrap();
    encryptor.encrypt(&text).unwrap()
}

/// # Дешифровка переданной строки с использованием ключа.
fn decrypting(text: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let encryptor = get_encryptor(&key).unwrap();
    encryptor.decrypt(&text).unwrap()
}

/// # Фабрика подготовки шифровальщика.
fn get_encryptor(key_arr: &[u8]) -> Result<Encryptor, CipherError> {
    let cipher = Box::new(Kuznyechik::new(key_arr)?);
    let padding = Box::new(PKCS7);
    let mode = Box::new(ECB);

    Encryptor::new_block(cipher, mode, padding)
}
