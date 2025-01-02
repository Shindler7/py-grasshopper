pub mod cipher;
pub mod mode;
pub mod padding;
pub mod traits;

use cipher::kuznyechik::cipher::Kuznyechik;
use mode::ECB;
use padding::PKCS7;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyString;
use sha2::{Digest, Sha256};
use traits::{CipherError, Encryptor};

/// Шифратор.
///
/// - text — текст для шифрования
#[pyfunction]
#[pyo3(name = "do_encrypt")]
#[pyo3(signature = (text, key))]
fn do_encrypt(text: Bound<'_, PyString>, key: Bound<'_, PyString>) -> PyResult<String> {
    let tuple_data = extract_text_and_key(&text, &key)?;

    let encrypt_result = encrypting(tuple_data.0, tuple_data.1);
    Ok(encrypt_result)
}

/// # Дешифратор.
#[pyfunction]
#[pyo3(name = "do_decrypt")]
#[pyo3(signature = (text, key))]
fn do_decrypt(text: Bound<'_, PyString>, key: Bound<'_, PyString>) -> PyResult<String> {
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

/// # Преобразователь PyString для текста и ключа в String.
///
/// Одновременно проводятся базовые проверки.
fn extract_text_and_key(
    text: &Bound<'_, PyString>,
    key: &Bound<'_, PyString>,
) -> Result<(String, String), PyErr> {
    let text: String = text.extract()?;
    let key_pass: String = key.extract()?;

    if text.is_empty() || key_pass.is_empty() {
        return Err(PyValueError::new_err(
            "'text' and the 'key' cannot be empty",
        ));
    }

    Ok((text, key_pass))
}

/// # Шифрование переданной строки с использованием ключа.
///
/// Ожидается, что проверки аргументов проведены до передачи функции.
///
/// - text — Текст для шифрования
/// - key — Ключ для шифрования
fn encrypting(text: String, key: String) -> String {
    // Шифратор работает с массивами u8 в формате HEX.
    // Требуется преобразовать строки.

    let encryptor = get_encryptor(&string_to_hash(&key)).unwrap();

    let text_hex = text.bytes().collect::<Vec<u8>>();
    let result = encryptor.encrypt(&text_hex).unwrap();

    String::from_utf8_lossy(&result).to_string()
}

/// # Дешифровка переданной строки с использованием ключа.
fn decrypting(text: String, key: String) -> String {
    let encryptor = get_encryptor(&string_to_hash(&key)).unwrap();

    let text_hex = text.bytes().collect::<Vec<u8>>();
    let result = encryptor.decrypt(&text_hex).unwrap();

    String::from_utf8_lossy(&result).to_string()
}

/// # Фабрика подготовки шифровальщика.
fn get_encryptor(key_arr: &[u8]) -> Result<Encryptor, CipherError> {
    let cipher = Box::new(Kuznyechik::new(&key_arr)?);
    let padding = Box::new(PKCS7);
    let mode = Box::new(ECB);

    Encryptor::new_block(cipher, mode, padding)
}

/// # Создание хэша строкового ключа.
fn string_to_hash(text: &String) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let result = hasher.finalize();
    let mut key = [0; 32];
    key.copy_from_slice(&result);
    key
}
