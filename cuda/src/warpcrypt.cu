#include "aes.cuh"
#include "camellia.cuh"
#include "warpcrypt.cuh"

bool execute_crypto(const CryptoRequest& request, rust::Slice<const uint8_t> key,
                    rust::Slice<const uint8_t> iv, rust::Slice<const uint8_t> input,
                    rust::Slice<uint8_t> output) {
    switch (request.algorithm) {
        case Algorithm::AesEcb:
            return launch_aes_ecb(request, key.data(), input.data(), output.data(), input.length());
        case Algorithm::AesCtr:
            return launch_aes_ctr(request, key.data(), iv.data(), input.data(), output.data(),
                                  input.length());
        case Algorithm::CamelliaEcb:
            return launch_camellia_ecb(request, key.data(), input.data(), output.data(),
                                       input.length());
        case Algorithm::CamelliaCtr:
            return launch_camellia_ctr(request, key.data(), iv.data(), input.data(), output.data(),
                                       input.length());
        default:
            return false;
    }
}
