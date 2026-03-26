#ifndef __WARPCRYPT_UTILS_CUH
#define __WARPCRYPT_UTILS_CUH

#include <cstdint>

__host__ __device__ __forceinline__ uint64_t load_be64(const uint8_t* p) {
    return (uint64_t)p[0] << 56 | (uint64_t)p[1] << 48 | (uint64_t)p[2] << 40 |
           (uint64_t)p[3] << 32 | (uint64_t)p[4] << 24 | (uint64_t)p[5] << 16 |
           (uint64_t)p[6] << 8 | (uint64_t)p[7];
}

__host__ __device__ __forceinline__ void store_be64(uint8_t* p, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        p[i] = v & 0xff;
        v >>= 8;
    }
}

__host__ __device__ __forceinline__ void rotl128(const uint64_t in[2], int n, uint64_t out[2]) {
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

#endif