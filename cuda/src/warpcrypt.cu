#include "aes.cuh"
#include "warpcrypt.cuh"

bool execute_crypto(const CryptoRequest& request, rust::Slice<const uint8_t> key,
                    rust::Slice<const uint8_t> nonce, rust::Slice<const uint8_t> input,
                    rust::Slice<uint8_t> output) {
    switch (request.algorithm) {
        case Algorithm::AesEcb:
            return launch_aes_ecb(request, key.data(), input.data(), output.data(), input.length());
        case Algorithm::AesCtr:
            return launch_aes_ctr(request, key.data(), nonce.data(), input.data(), output.data(),
                                  input.length());
        default:
            return false;
    }
}