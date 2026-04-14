use std::{fs, path::PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use warpcrypt::{Algorithm, AlgorithmArg, CryptoRequest, KeySize, Operation, execute_crypto};

#[derive(Parser, Debug)]
#[command(version, about = "High-performance GPU-accelerated cryptography using CUDA", long_about = None, after_help = "EXAMPLES:\n\
  warpcrypt encrypt --algorithm chacha20 --key-hex ... --iv ... --input in --output out\n\
  warpcrypt decrypt --algorithm aes-ctr --key-file key.bin --iv ... --input in --output out")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encrypt input data
    Encrypt(CommonArgs),

    /// Decrypt input data
    Decrypt(CommonArgs),
}

#[derive(Parser, Debug)]
pub struct CommonArgs {
    /// Cryptographic algorithm to use.
    #[arg(long)]
    algorithm: AlgorithmArg,

    /// Encryption key as a hex string. Mutually exclusive with --key-file.
    #[arg(long)]
    key_hex: Option<String>,

    /// Path to file containing raw key bytes. Mutually exclusive with --key-hex.
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Key size in bits (required for AES and Camellia). Possible values: 128, 192, 256. If not
    /// provided, inferred from key length. Ignored for ChaCha20 (always 256-bit).
    #[arg(long)]
    key_size: Option<u32>,

    /// Initialization vector (IV) as a hex string (16 bytes). Required for: aes-ctr, camellia-ctr,
    /// chacha20. For AES/Camellia CTR, interpreted as a 16-byte IV. For ChaCha20, interpreted as a
    /// 4-byte counter (little-endian) and a 12-byte nonce.
    #[arg(long)]
    iv: Option<String>,

    /// Input file path.
    #[arg(long)]
    input: PathBuf,

    /// Output file path.
    #[arg(long)]
    output: PathBuf,

    /// Number of CUDA thread blocks.
    #[arg(long, default_value_t = 256)]
    num_blocks: usize,

    /// Number of CUDA threads per block.
    #[arg(long, default_value_t = 256)]
    block_size: usize,

    /// Number of CUDA streams to use.
    #[arg(long, default_value_t = 1)]
    streams: usize,

    /// Padding mode (ECB modes only). Possible values: pkcs7, none. Ignored for CTR and
    /// ChaCha20.
    #[arg(long, default_value = "pkcs7")]
    padding: String,
}

struct Config {
    request: CryptoRequest,
    key: Vec<u8>,
    iv: Vec<u8>,
    input_path: PathBuf,
    output_path: PathBuf,
    padding: String,
}

fn pkcs7_pad(input: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (input.len() % block_size);
    let mut out = input.to_vec();
    out.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    out
}

fn pkcs7_unpad(data: &mut Vec<u8>) {
    let pad = *data.last().expect("Invalid padding") as usize;
    assert!(pad > 0 && pad <= 16, "Invalid PKCS7 padding");

    let len = data.len();
    for i in 0..pad {
        assert_eq!(data[len - 1 - i], pad as u8, "Invalid PKCS7 padding");
    }

    data.truncate(len - pad);
}

fn parse_cli() -> Result<Config> {
    let cli = Cli::parse();

    let (args, operation) = match cli.command {
        Commands::Encrypt(args) => (args, Operation::Encrypt),
        Commands::Decrypt(args) => (args, Operation::Decrypt),
    };

    let algorithm: Algorithm = args.algorithm.into();

    // Load key
    let key = if let Some(hex) = args.key_hex {
        hex::decode(hex)?
    } else if let Some(path) = args.key_file {
        std::fs::read(path)?
    } else {
        anyhow::bail!("Must provide --key-hex or --key-file");
    };

    // Key size
    let key_size = if matches!(algorithm, Algorithm::ChaCha20) {
        KeySize::KeySize256
    } else if let Some(k) = args.key_size {
        KeySize::try_from(k)?
    } else {
        KeySize::try_from(key.len() as u32)?
    };

    // IV
    let iv = match algorithm {
        Algorithm::AesCtr | Algorithm::CamelliaCtr | Algorithm::ChaCha20 => {
            let iv_hex = args.iv.ok_or_else(|| anyhow::anyhow!("IV required"))?;
            let iv = hex::decode(iv_hex)?;
            if iv.len() != 16 {
                anyhow::bail!("IV must be 16 bytes");
            }
            iv
        }
        _ => vec![0u8; 16],
    };

    let request = CryptoRequest {
        algorithm,
        operation,
        key_size,
        num_blocks: args.num_blocks,
        block_size: args.block_size,
        num_streams: args.streams,
    };

    Ok(Config {
        request,
        key,
        iv,
        input_path: args.input,
        output_path: args.output,
        padding: args.padding,
    })
}

fn run(config: Config) -> Result<()> {
    let algorithm = config.request.algorithm;
    let operation = config.request.operation;

    // Load input
    let mut input = fs::read(&config.input_path)?;

    // Padding (ECB only)
    let block_size_bytes = 16;

    if matches!(algorithm, Algorithm::AesEcb | Algorithm::CamelliaEcb) {
        match operation {
            Operation::Encrypt => {
                if config.padding == "pkcs7" {
                    input = pkcs7_pad(&input, block_size_bytes);
                } else if input.len() % block_size_bytes != 0 {
                    anyhow::bail!("Input must be block-aligned if padding=none");
                }
            }
            Operation::Decrypt => {
                if input.len() % block_size_bytes != 0 {
                    anyhow::bail!("Ciphertext must be block-aligned");
                }
            }
            _ => unreachable!(),
        }
    }

    let mut output = vec![0u8; input.len()];

    // Execute CUDA
    execute_crypto(
        &config.request,
        &config.key,
        &config.iv,
        &input,
        &mut output,
    );

    // Unpadding
    if matches!(algorithm, Algorithm::AesEcb | Algorithm::CamelliaEcb)
        && matches!(operation, Operation::Decrypt)
        && config.padding == "pkcs7"
    {
        pkcs7_unpad(&mut output);
    }

    // Write output
    fs::write(&config.output_path, &output)?;

    Ok(())
}

fn main() -> Result<()> {
    let config = parse_cli()?;
    run(config)
}
