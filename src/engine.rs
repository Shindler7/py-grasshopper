use block_encryption::cipher::kuznyechik::cipher::Kuznyechik;
use block_encryption::mode::{CBC, CFB, CTR, ECB, OFB};
use block_encryption::padding::PKCS7;
use block_encryption::traits::Mode;
use block_encryption::traits::{CipherError, Encryptor};

/// Шифрование переданной строки с использованием ключа.
///
/// Ожидается, что проверки аргументов проведены до передачи функции.
///
/// - text — Текст для шифрования
/// - key — Ключ для шифрования
/// - encrypt_mode — Режим шифрования
pub fn encrypting(
    plaintext: Vec<u8>,
    key: Vec<u8>,
    encrypt_mode: &str,
) -> Result<Vec<u8>, CipherError> {
    let encryptor = get_encryptor(&key, encrypt_mode)?;
    encryptor.encrypt(&plaintext)
}

/// Дешифровка переданной строки с использованием ключа.
pub fn decrypting(
    ciphertext: Vec<u8>,
    key: Vec<u8>,
    encrypt_mode: &str,
) -> Result<Vec<u8>, CipherError> {
    let encryptor = get_encryptor(&key, encrypt_mode)?;
    encryptor.decrypt(&ciphertext)
}

/// Фабрика подготовки шифровальщика.
fn get_encryptor(key_arr: &[u8], encrypt_mode: &str) -> Result<Encryptor, CipherError> {
    let cipher = Box::new(Kuznyechik::new(key_arr)?);
    let padding = Box::new(PKCS7);

    let iv: Vec<u8> = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08,
    ];

    let mode: Box<dyn Mode> = match encrypt_mode {
        "ECB" => Box::new(ECB),
        "CBC" => Box::new(CBC::new(iv)),
        "CFB" => Box::new(CFB::new(iv)),
        "OFB" => Box::new(OFB::new(iv)),
        "CTR" => Box::new(CTR::new(iv)),
        _ => return Err(CipherError::InvalidMode),
    };

    match encrypt_mode {
        "CFB" | "OFB" | "CTR" => Encryptor::new_stream(cipher, mode),
        _ => Encryptor::new_block(cipher, mode, padding),
    }
}
