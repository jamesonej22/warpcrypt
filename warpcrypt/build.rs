fn main() {
    cxx_build::bridge("src/lib.rs")
        .cuda(true)
        .file("cuda/aes.cu")
        .compile("warpcrypt");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cuda/aes.cu");
}
