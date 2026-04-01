use aes::{Aes128, Aes192, Aes256};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use warpcrypt::{Algorithm, CryptoRequest, KeySize, Operation, execute_crypto};

mod common;

use common::{random_bytes, run_ctr, run_ecb_encrypt, warmup_gpu};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type Aes192Ctr = ctr::Ctr128BE<Aes192>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

fn bench_gpu_aes_ecb(c: &mut Criterion) {
    let mut group = c.benchmark_group("gpu_aes_ecb");

    let sizes = [1 << 20, 1 << 24, 1 << 28];
    let streams = [1, 2, 4, 8];
    let key_configs = [
        (KeySize::KeySize128, 16),
        (KeySize::KeySize192, 24),
        (KeySize::KeySize256, 32),
    ];

    warmup_gpu();
    for &size in &sizes {
        let input = random_bytes(size);
        let mut output = vec![0u8; size];
        let iv = [0u8; 16];

        for &(key_size, key_len) in &key_configs {
            let key = random_bytes(key_len);
            group.throughput(Throughput::Bytes(size as u64));

            for &num_streams in &streams {
                let request = CryptoRequest {
                    algorithm: Algorithm::AesEcb,
                    operation: Operation::Encrypt,
                    key_size,
                    num_blocks: 256,
                    block_size: 256,
                    num_streams,
                };

                group.bench_with_input(
                    BenchmarkId::new(
                        "config",
                        format!("size={} streams={} key={}", size, num_streams, key_len * 8),
                    ),
                    &size,
                    |b, _| b.iter(|| execute_crypto(&request, &key, &iv, &input, &mut output)),
                );
            }
        }
    }
    group.finish();
}

fn bench_cpu_aes_ecb(c: &mut Criterion) {
    let mut group = c.benchmark_group("cpu_aes_ecb");

    let sizes = [1 << 20, 1 << 24, 1 << 28];
    let key_configs = [(16, "128"), (24, "192"), (32, "256")];

    for &size in &sizes {
        let input = random_bytes(size);
        let mut output = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));

        for &(key_len, label) in &key_configs {
            let key = random_bytes(key_len);

            // AES
            group.bench_with_input(
                BenchmarkId::new("aes_ecb", format!("size={} key={}", size, label)),
                &size,
                |b, _| {
                    b.iter(|| match key_len {
                        16 => run_ecb_encrypt::<Aes128>(&key, &input, &mut output),
                        24 => run_ecb_encrypt::<Aes192>(&key, &input, &mut output),
                        32 => run_ecb_encrypt::<Aes256>(&key, &input, &mut output),
                        _ => unreachable!(),
                    })
                },
            );
        }
    }
    group.finish();
}

fn bench_gpu_aes_ctr(c: &mut Criterion) {
    let mut group = c.benchmark_group("gpu_aes_ctr");

    let sizes = [1 << 20, 1 << 24, 1 << 28];
    let streams = [1, 2, 4, 8];
    let key_configs = [
        (KeySize::KeySize128, 16),
        (KeySize::KeySize192, 24),
        (KeySize::KeySize256, 32),
    ];

    warmup_gpu();
    for &size in &sizes {
        let input = random_bytes(size);
        let mut output = vec![0u8; size];
        let iv = random_bytes(16);

        for &(key_size, key_len) in &key_configs {
            let key = random_bytes(key_len);
            group.throughput(Throughput::Bytes(size as u64));

            for &num_streams in &streams {
                let request = CryptoRequest {
                    algorithm: Algorithm::AesCtr,
                    operation: Operation::Encrypt,
                    key_size,
                    num_blocks: 256,
                    block_size: 256,
                    num_streams,
                };

                group.bench_with_input(
                    BenchmarkId::new(
                        "config",
                        format!("size={} streams={} key={}", size, num_streams, key_len * 8),
                    ),
                    &size,
                    |b, _| b.iter(|| execute_crypto(&request, &key, &iv, &input, &mut output)),
                );
            }
        }
    }
    group.finish();
}

fn bench_cpu_aes_ctr(c: &mut Criterion) {
    let mut group = c.benchmark_group("cpu_aes_ctr");

    let sizes = [1 << 20, 1 << 24, 1 << 28];
    let key_configs = [(16, "128"), (24, "192"), (32, "256")];

    for &size in &sizes {
        let input = random_bytes(size);
        let iv = random_bytes(16);

        group.throughput(Throughput::Bytes(size as u64));

        for &(key_len, label) in &key_configs {
            let key = random_bytes(key_len);
            let mut output = vec![0u8; size];

            // AES
            group.bench_with_input(
                BenchmarkId::new("aes_ctr", format!("size={} key={}", size, label)),
                &size,
                |b, _| {
                    b.iter(|| match key_len {
                        16 => run_ctr::<Aes128Ctr>(&key, &iv, &input, &mut output),
                        24 => run_ctr::<Aes192Ctr>(&key, &iv, &input, &mut output),
                        32 => run_ctr::<Aes256Ctr>(&key, &iv, &input, &mut output),
                        _ => unreachable!(),
                    })
                },
            );
        }
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_gpu_aes_ecb,
    bench_cpu_aes_ecb,
    bench_gpu_aes_ctr,
    bench_cpu_aes_ctr,
);

criterion_main!(benches);
