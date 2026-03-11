

#include <cstdint>
#include <cstring>

#include "camellia.cuh"
#include "utils.cuh"

CamelliaParameters::CamelliaParameters(const CryptoRequest& request) {
    switch (request.key_size) {
        case KeySize::KeySize128:
            key_size = CAMELLIA_KEY_SIZE_128;
            num_rounds = CAMELLIA_NUM_ROUNDS_128;
            break;
        case KeySize::KeySize192:
            key_size = CAMELLIA_KEY_SIZE_192;
            break;
        case KeySize::KeySize256:
            key_size = CAMELLIA_KEY_SIZE_256;
            break;
        default:
            break;
    }
}

void camellia_generate_keys(const uint8_t* key, CamelliaParameters parameters) {
    // Separate the keys into 64-bit pieces
    uint64_t kl[2] = {load_be64(key), load_be64(key + 8)};
    uint64_t kr[2] = {0};

    if (parameters.key_size == CAMELLIA_KEY_SIZE_192) {
    } else if (parameters.key_size == CAMELLIA_KEY_SIZE_256) {
    }

    // Generate ka and kb
    uint64_t d1 = kl[0] ^ kr[0];
    uint64_t d2 = kl[1] ^ kr[1];
    d2 ^= camellia_f(d1, camellia_sigma[0]);
    d1 ^= camellia_f(d2, camellia_sigma[1]);
    d1 ^= kl[0];
    d2 ^= kl[1];
    d2 ^= camellia_f(d1, camellia_sigma[2]);
    d1 ^= camellia_f(d2, camellia_sigma[3]);
    uint64_t ka[2] = {d1, d2};
    uint64_t kb[2] = {0};

    if (parameters.key_size != CAMELLIA_KEY_SIZE_128) {
        d1 = ka[0] ^ kr[0];
        d2 = ka[1] ^ kr[1];
        d2 ^= camellia_f(d1, camellia_sigma[4]);
        d1 ^= camellia_f(d2, camellia_sigma[5]);
        kb[0] = d1;
        kb[1] = d2;
    }

    camellia_expand_keys(ka, kb, kl, kr, parameters);
}

void camellia_expand_keys(const uint64_t ka[2], const uint64_t kb[2], const uint64_t kl[2],
                          const uint64_t kr[2], CamelliaParameters parameters) {
    auto rotl128 = [](const uint64_t in[2], int n, uint64_t out[2]) {
        n %= 128;
        if (n == 0) {
            out[0] = in[0];
            out[1] = in[1];
        } else if (n < 64) {
            out[0] = (in[0] << n) | (in[1] >> (64 - n));
            out[1] = (in[1] << n) | (in[0] >> (64 - n));
        } else {
            n -= 64;
            out[0] = (in[1] << n) | (in[0] >> (64 - n));
            out[1] = (in[0] << n) | (in[1] >> (64 - n));
        }
    };

    if (parameters.key_size = CAMELLIA_KEY_SIZE_128) {
    } else {
    }
}

__host__ __device__ uint64_t camellia_f(uint64_t a, uint64_t b) {}