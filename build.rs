fn main() {
    cxx_build::bridge("src/lib.rs")
        .cuda(true)
        .include("cuda/include")
        .file("cuda/src/warpcrypt.cu")
        .file("cuda/src/aes.cu")
        .file("cuda/src/camellia.cu")
        .compile("warpcrypt");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cuda/include/warpcrypt.cuh");
    println!("cargo:rerun-if-changed=cuda/src/warpcrypt.cu");
    println!("cargo:rerun-if-changed=cuda/include/aes.cuh");
    println!("cargo:rerun-if-changed=cuda/src/aes.cu");
    println!("cargo:rerun-if-changed=cuda/include/camellia.cuh");
    println!("cargo:rerun-if-changed=cuda/src/camellia.cu");
    println!("cargo:rerun-if-changed=cuda/include/utils.cuh");
}
