use chacha20::ChaCha20;
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use warpcrypt::{Algorithm, CryptoRequest, Operation, execute_crypto};

mod common;
use common::{random_bytes, warmup_gpu};

fn run_chacha20_cpu(key: &[u8], iv: &[u8], input: &[u8], output: &mut [u8]) {
    let counter = u32::from_le_bytes(iv[0..4].try_into().unwrap());
    let nonce = &iv[4..16];

    let mut cipher = ChaCha20::new_from_slices(key, nonce).unwrap();
    cipher.seek(counter as u64 * 64);

    output.copy_from_slice(input);
    cipher.apply_keystream(output);
}

fn bench_gpu_chacha20(c: &mut Criterion) {
    let mut group = c.benchmark_group("gpu_chacha20");

    let sizes = [1 << 20, 1 << 24, 1 << 28, 1 << 30];
    let streams = [1, 2, 4, 8];

    warmup_gpu();

    for &size in &sizes {
        let input = random_bytes(size);
        let mut output = vec![0u8; size];

        let mut iv = [0u8; 16];
        iv[0..4].copy_from_slice(&1u32.to_le_bytes()); // nonzero counter
        iv[4..].copy_from_slice(&random_bytes(12));

        let key = random_bytes(32);

        group.throughput(Throughput::Bytes(size as u64));

        for &num_streams in &streams {
            let request = CryptoRequest {
                algorithm: Algorithm::ChaCha20,
                operation: Operation::Encrypt,
                key_size: warpcrypt::KeySize::KeySize256, // fixed
                num_blocks: 256,
                block_size: 256,
                num_streams,
            };

            group.bench_with_input(
                BenchmarkId::new("config", format!("size={} streams={}", size, num_streams)),
                &size,
                |b, _| b.iter(|| execute_crypto(&request, &key, &iv, &input, &mut output)),
            );
        }
    }

    group.finish();
}

fn bench_cpu_chacha20(c: &mut Criterion) {
    let mut group = c.benchmark_group("cpu_chacha20");

    let sizes = [1 << 20, 1 << 24, 1 << 28, 1 << 30];

    for &size in &sizes {
        let input = random_bytes(size);
        let mut output = vec![0u8; size];

        let mut iv = [0u8; 16];
        iv[0..4].copy_from_slice(&1u32.to_le_bytes());
        iv[4..].copy_from_slice(&random_bytes(12));

        let key = random_bytes(32);

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("chacha20", format!("size={}", size)),
            &size,
            |b, _| b.iter(|| run_chacha20_cpu(&key, &iv, &input, &mut output)),
        );
    }

    group.finish();
}

criterion_group!(benches, bench_gpu_chacha20, bench_cpu_chacha20);

criterion_main!(benches);
