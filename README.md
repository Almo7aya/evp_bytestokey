Ported to Rust from [EVP_BytesToKey](https://github.com/crypto-browserify/EVP_BytesToKey)

The insecure [key derivation algorithm from OpenSSL.](https://wiki.openssl.org/index.php/Manual:EVP_BytesToKey(3))

**WARNING: DO NOT USE, except for compatibility reasons.**

MD5 is insecure.
Use at least `scrypt` or `pbkdf2-hmac-sha256` instead.

# Example

``` rust
use md5::{Md5, Digest};

fn main() {
    let password = "mysecretpassword";
    let key_bits = 256;
    let iv_len = 16;

    let (key, iv) = evp_bytes_to_key(password, key_bits, iv_len).unwrap();

    // Use the key and IV to encrypt or decrypt your data as needed
    // ...
}
```

