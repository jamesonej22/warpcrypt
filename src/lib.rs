//! Crate

#![allow(dead_code)]

#[cxx::bridge]
pub mod ffi {
    enum Algorithm {
        AesEcb,
        AesCtr,
    }

    enum KeySize {
        KeySize128,
        KeySize192,
        KeySize256,
    }

    enum Operation {
        Encrypt,
        Decrypt,
    }

    struct CryptoRequest {
        algorithm: Algorithm,
        operation: Operation,
        key_size: KeySize,
    }

    unsafe extern "C++" {
        include!("warpcrypt/cuda/include/warpcrypt.cuh");

        fn execute_crypto(
            request: &CryptoRequest,
            key: &[u8],
            nonce: &[u8],
            input: &[u8],
            output: &mut [u8],
        ) -> bool;
    }
}

#[cfg(test)]
mod test {
    use crate::ffi::{Algorithm, CryptoRequest, KeySize, Operation, execute_crypto};

    const AES_128_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    const AES_128_ECB_PLAINTEXT: [u8; 16] = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07,
        0x34,
    ];

    const AES_128_ECB_CIPHERTEXT: [u8; 16] = [
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b,
        0x32,
    ];

    const AES_192_KEY: [u8; 24] = [
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79,
        0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
    ];

    const AES_192_ECB_PLAINTEXT: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];

    const AES_192_ECB_CIPHERTEXT: [u8; 16] = [
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5,
        0xcc,
    ];

    const AES_256_KEY: [u8; 32] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    ];

    const AES_256_ECB_PLAINTEXT: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ];

    const AES_256_ECB_CIPHERTEXT: [u8; 16] = [
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81,
        0xf8,
    ];

    #[test]
    fn aes128ecb_encrypt() {
        let request = CryptoRequest {
            algorithm: Algorithm::AesEcb,
            operation: Operation::Encrypt,
            key_size: KeySize::KeySize128,
        };

        let mut output = [0u8; 16];
        let nonce = [0u8];

        assert!(execute_crypto(
            &request,
            &AES_128_KEY,
            &nonce,
            &AES_128_ECB_PLAINTEXT,
            &mut output
        ));
        assert_eq!(AES_128_ECB_CIPHERTEXT, output);
    }

    #[test]
    fn aes128ecb_decrypt() {
        let request = CryptoRequest {
            algorithm: Algorithm::AesEcb,
            operation: Operation::Decrypt,
            key_size: KeySize::KeySize128,
        };

        let mut output = [0u8; 16];
        let nonce = [0u8];

        assert!(execute_crypto(
            &request,
            &AES_128_KEY,
            &nonce,
            &AES_128_ECB_CIPHERTEXT,
            &mut output
        ));
        assert_eq!(AES_128_ECB_PLAINTEXT, output);
    }

    #[test]
    fn aes192ecb_encrypt() {
        let request = CryptoRequest {
            algorithm: Algorithm::AesEcb,
            operation: Operation::Encrypt,
            key_size: KeySize::KeySize192,
        };

        let mut output = [0u8; 16];
        let nonce = [0u8];

        assert!(execute_crypto(
            &request,
            &AES_192_KEY,
            &nonce,
            &AES_192_ECB_PLAINTEXT,
            &mut output
        ));
        assert_eq!(AES_192_ECB_CIPHERTEXT, output);
    }

    #[test]
    fn aes192ecb_decrypt() {
        let request = CryptoRequest {
            algorithm: Algorithm::AesEcb,
            operation: Operation::Decrypt,
            key_size: KeySize::KeySize192,
        };

        let mut output = [0u8; 16];
        let nonce = [0u8];

        assert!(execute_crypto(
            &request,
            &AES_192_KEY,
            &nonce,
            &AES_192_ECB_CIPHERTEXT,
            &mut output
        ));
        assert_eq!(AES_192_ECB_PLAINTEXT, output);
    }

    #[test]
    fn aes256ecb_encrypt() {
        let request = CryptoRequest {
            algorithm: Algorithm::AesEcb,
            operation: Operation::Encrypt,
            key_size: KeySize::KeySize256,
        };

        let mut output = [0u8; 16];
        let nonce = [0u8];

        assert!(execute_crypto(
            &request,
            &AES_256_KEY,
            &nonce,
            &AES_256_ECB_PLAINTEXT,
            &mut output
        ));
        assert_eq!(AES_256_ECB_CIPHERTEXT, output);
    }

    #[test]
    fn aes256ecb_decrypt() {
        let request = CryptoRequest {
            algorithm: Algorithm::AesEcb,
            operation: Operation::Decrypt,
            key_size: KeySize::KeySize256,
        };

        let mut output = [0u8; 16];
        let nonce = [0u8];

        assert!(execute_crypto(
            &request,
            &AES_256_KEY,
            &nonce,
            &AES_256_ECB_CIPHERTEXT,
            &mut output
        ));
        assert_eq!(AES_256_ECB_PLAINTEXT, output);
    }
}
