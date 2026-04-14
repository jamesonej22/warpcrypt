use std::process::Command;

fn get_cuda_arch_flags() -> Vec<String> {
    // Let the user override everything via CUDA_ARCH env var
    // e.g. CUDA_ARCH="sm_89" cargo build
    if let Ok(arch) = std::env::var("CUDA_ARCH") {
        println!("cargo:rerun-if-env-changed=CUDA_ARCH");
        return vec![format!("-arch={arch}")];
    }

    // Ask nvcc to detect the local GPU's compute capability
    let output = Command::new("nvcc")
        .args([
            "--run-compilation-phases",
            "--gpu-architecture=native",
            "--dry-run",
            "-x",
            "cu",
            "/dev/null",
        ])
        .output();

    // If native detection works (CUDA 11.6+), use it
    if output.map(|o| o.status.success()).unwrap_or(false) {
        return vec!["--gpu-architecture=native".to_string()];
    }

    // Otherwise, fall back to a safe multi-arch set with a PTX fallback
    // for forward compatibility with future architectures
    vec![
        "-gencode".to_string(),
        "arch=compute_75,code=sm_75".to_string(), // Turing  (RTX 20xx)
        "-gencode".to_string(),
        "arch=compute_86,code=sm_86".to_string(), // Ampere  (RTX 30xx)
        "-gencode".to_string(),
        "arch=compute_89,code=sm_89".to_string(), // Ada     (RTX 40xx)
        "-gencode".to_string(),
        "arch=compute_90,code=sm_90".to_string(), // Hopper  (H100)
        "-gencode".to_string(),
        "arch=compute_120,code=sm_120".to_string(), // Blackwell (RTX 50xx)
        // PTX fallback: JIT-compiled for any future arch not listed above
        "-gencode".to_string(),
        "arch=compute_120,code=compute_120".to_string(),
    ]
}

fn main() {
    let arch_flags = get_cuda_arch_flags();

    let mut build = cxx_build::bridge("src/lib.rs");
    build.cuda(true).include("cuda/include");

    for flag in &arch_flags {
        build.flag(flag);
    }

    build
        .file("cuda/src/warpcrypt.cu")
        .file("cuda/src/aes.cu")
        .file("cuda/src/camellia.cu")
        .file("cuda/src/chacha.cu")
        .compile("warpcrypt");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cuda/include/warpcrypt.cuh");
    println!("cargo:rerun-if-changed=cuda/src/warpcrypt.cu");
    println!("cargo:rerun-if-changed=cuda/include/aes.cuh");
    println!("cargo:rerun-if-changed=cuda/src/aes.cu");
    println!("cargo:rerun-if-changed=cuda/include/camellia.cuh");
    println!("cargo:rerun-if-changed=cuda/src/camellia.cu");
    println!("cargo:rerun-if-changed=cuda/include/chacha.cuh");
    println!("cargo:rerun-if-changed=cuda/src/chacha.cu");
    println!("cargo:rerun-if-changed=cuda/include/utils.cuh");
}
