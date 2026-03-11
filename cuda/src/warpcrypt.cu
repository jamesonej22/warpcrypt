#include "aes.cuh"
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
        default:
            return false;
    }
}

__device__ __forceinline__ uint64_t load_be64_device(const uint8_t* p) {
    return (uint64_t)p[0] << 56 | (uint64_t)p[1] << 48 | (uint64_t)p[2] << 40 |
           (uint64_t)p[3] << 32 | (uint64_t)p[4] << 24 | (uint64_t)p[5] << 16 |
           (uint64_t)p[6] << 8 | (uint64_t)p[7];
}

__device__ __forceinline__ void store_be64_device(uint8_t* p, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        p[i] = v & 0xff;
        v >>= 8;
    }
}