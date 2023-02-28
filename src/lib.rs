//! Ported to Rust from [EVP_BytesToKey](https://github.com/crypto-browserify/EVP_BytesToKey)
//!
//! The insecure [key derivation algorithm from OpenSSL.](https://wiki.openssl.org/index.php/Manual:EVP_BytesToKey(3))
//!
//! **WARNING: DO NOT USE, except for compatibility reasons.**
//!
//! MD5 is insecure.
//! Use at least `scrypt` or `pbkdf2-hmac-sha256` instead.
//!
//! # Example
//!
//! ```
//! use md5::{Md5, Digest};
//!
//! fn main() {
//!     let password = "mysecretpassword";
//!     let key_bits = 256;
//!     let iv_len = 16;
//!
//!     let (key, iv) = evp_bytes_to_key(password, key_bits, iv_len).unwrap();
//!
//!     // Use the key and IV to encrypt or decrypt your data as needed
//!     // ...
//! }
//! ```


use std::error::Error;
use md5::{Md5, Digest};

/// Generates a key and initialization vector (IV) from a password using the EVP_BytesToKey algorithm.
///
/// # Arguments
///
/// * `password` - A string representing the plaintext password
/// * `key_bits` - An unsigned 32-bit integer representing the desired key size in bits.
/// * `iv_len` - An unsigned integer representing the desired IV length in bytes.
///
/// # Returns
///
/// A `Result` containing a tuple of two vectors of bytes: the derived key and initialization vector (IV).
///
pub fn evp_bytes_to_key(
    password: &str,
    key_bits: u32,
    iv_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let password = password.as_bytes();

    let mut key_len = key_bits / 8;
    let mut key = vec![0u8; key_len as usize];
    let mut iv = vec![0u8; iv_len];
    let mut iv_len = iv_len;
    let mut tmp = vec![];

    while key_len > 0 || iv_len > 0 {
        let mut hash = Md5::new();
        hash.update(&tmp);
        hash.update(password);
        tmp = hash.finalize().to_vec();

        let mut used = 0;

        if key_len > 0 {
            let key_start = key.len() - key_len as usize;
            used = std::cmp::min(key_len as usize, tmp.len());
            key[key_start..(key_start + used)].copy_from_slice(&tmp[..used]);
            key_len -= used as u32;
        }

        if used < tmp.len() && iv_len > 0 {
            let iv_start = iv.len() - iv_len;
            let length = std::cmp::min(iv_len, tmp.len() - used);
            iv[iv_start..(iv_start + length)].copy_from_slice(&tmp[used..(used + length)]);
            iv_len -= length;
        }
    }

    tmp.fill(0);
    Ok((key, iv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fun_evp_bytes_to_key() {
        let final_key = [
            160, 16, 210, 139, 221, 104, 193, 14, 107, 161, 66, 34, 189, 78, 155, 196, 57, 160,
            212, 154, 51, 145, 193, 115, 45, 115, 90, 135, 85, 14, 243, 172,
        ];
        let final_iv = [
            135, 146, 32, 125, 74, 122, 144, 195, 189, 71, 187, 208, 189, 218, 132, 150,
        ];
        let password = "56Dooe/UfcJVt696Vn3Y7+saxlZQEeXLIsSuworpv6w=32798351";

        let (key, iv) = evp_bytes_to_key(password, 256, 16).unwrap();

        assert_eq!(final_key.as_slice(), key);
        assert_eq!(final_iv.as_slice(), iv);
    }
}
