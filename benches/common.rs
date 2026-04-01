use cipher::{BlockEncrypt, KeyInit, KeyIvInit, StreamCipher, generic_array::GenericArray};
use rand::RngCore;
use warpcrypt::{Algorithm, CryptoRequest, KeySize, Operation, execute_crypto};

pub fn warmup_gpu() {
    let size = 1 << 20;
    let input = random_bytes(size);
    let mut output = vec![0u8; size];
    let key = random_bytes(32);
    let iv = random_bytes(16);

    let request = CryptoRequest {
        algorithm: Algorithm::AesCtr,
        operation: Operation::Encrypt,
        key_size: KeySize::KeySize256,
        num_blocks: 256,
        block_size: 256,
        num_streams: 2,
    };

    execute_crypto(&request, &key, &iv, &input, &mut output);
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

pub fn run_ecb_encrypt<C>(key: &[u8], input: &[u8], output: &mut [u8])
where
    C: BlockEncrypt + KeyInit,
{
    let cipher = C::new_from_slice(key).unwrap();

    for (i, chunk) in input.chunks(16).enumerate() {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        output[i * 16..(i + 1) * 16].copy_from_slice(&block);
    }
}

pub fn run_ctr<C>(key: &[u8], iv: &[u8], input: &[u8], output: &mut [u8])
where
    C: KeyIvInit + StreamCipher,
{
    let mut cipher = C::new_from_slices(key, iv).unwrap();
    output.copy_from_slice(input);
    cipher.apply_keystream(output);
}
