/** @file chacha.cu
 * @author Eric Jameson
 * @brief Implementation of functions used in ChaCha20. All functions are described in the ChaCha20
 * RFC: https://www.rfc-editor.org/rfc/rfc8439
 */

#include <cstdint>

#include "chacha.cuh"
#include "utils.cuh"
#include "warpcrypt.cuh"

__device__ __forceinline__ void quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b;
    *d ^= *a;
    *d = rotl32(*d, 16);
    *c += *d;
    *b ^= *c;
    *b = rotl32(*b, 12);
    *a += *b;
    *d ^= *a;
    *d = rotl32(*d, 8);
    *c += *d;
    *b ^= *c;
    *b = rotl32(*b, 7);
}

__device__ __forceinline__ void initialize_state(uint32_t* state, const uint8_t* key,
                                                 const uint8_t* nonce, uint32_t counter) {
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key (little-endian)
    state[4] = load_le32(key + 0);
    state[5] = load_le32(key + 4);
    state[6] = load_le32(key + 8);
    state[7] = load_le32(key + 12);
    state[8] = load_le32(key + 16);
    state[9] = load_le32(key + 20);
    state[10] = load_le32(key + 24);
    state[11] = load_le32(key + 28);

    // Counter + nonce
    state[12] = counter;
    state[13] = load_le32(nonce + 0);
    state[14] = load_le32(nonce + 4);
    state[15] = load_le32(nonce + 8);
}

__global__ void chacha_kernel(const uint8_t* input, uint8_t* output, const uint8_t* key,
                              const uint8_t* nonce, uint32_t base_counter, uint32_t input_size) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t block_start = tid * 64;

    if (block_start >= input_size) return;

    uint32_t counter = base_counter + tid;

    uint32_t state[16];
    uint32_t working[16];

    initialize_state(state, key, nonce, counter);

#pragma unroll
    for (int i = 0; i < 16; i++) working[i] = state[i];

    for (int i = 0; i < 10; i++) {
        quarter_round(&working[0], &working[4], &working[8], &working[12]);
        quarter_round(&working[1], &working[5], &working[9], &working[13]);
        quarter_round(&working[2], &working[6], &working[10], &working[14]);
        quarter_round(&working[3], &working[7], &working[11], &working[15]);

        quarter_round(&working[0], &working[5], &working[10], &working[15]);
        quarter_round(&working[1], &working[6], &working[11], &working[12]);
        quarter_round(&working[2], &working[7], &working[8], &working[13]);
        quarter_round(&working[3], &working[4], &working[9], &working[14]);
    }

#pragma unroll
    for (int i = 0; i < 16; i++) working[i] += state[i];

    uint8_t keystream[64];

#pragma unroll
    for (int i = 0; i < 16; i++) {
        uint32_t v = working[i];
        keystream[4 * i + 0] = (v >> 0) & 0xff;
        keystream[4 * i + 1] = (v >> 8) & 0xff;
        keystream[4 * i + 2] = (v >> 16) & 0xff;
        keystream[4 * i + 3] = (v >> 24) & 0xff;
    }

#pragma unroll
    for (int i = 0; i < 64; i++) {
        if (block_start + i < input_size) {
            output[block_start + i] = input[block_start + i] ^ keystream[i];
        }
    }
}

void launch_chacha(const CryptoRequest& request, const uint8_t* key, const uint8_t* iv,
                   const uint8_t* input, uint8_t* output, size_t input_length) {
    uint32_t initial_counter = load_le32(iv);

    uint8_t* device_key;
    uint8_t* device_nonce;

    cudaMalloc(&device_key, CHACHA_KEY_SIZE);
    cudaMalloc(&device_nonce, CHACHA_NONCE_SIZE);

    cudaMemcpy(device_key, key, CHACHA_KEY_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(device_nonce, iv + 4, CHACHA_NONCE_SIZE, cudaMemcpyHostToDevice);

    launch_with_streams(
        request.num_streams, input_length, input, output,
        [&request, device_key, device_nonce, initial_counter](
            cudaStream_t stream, uint8_t* d_in, uint8_t* d_out, size_t size, size_t offset) {
            uint32_t block_offset = offset / CHACHA_BLOCK_SIZE;
            uint32_t counter = initial_counter + block_offset;

            int threads = request.block_size;

            int total_threads = (size + 63) / CHACHA_BLOCK_SIZE;
            int blocks = (total_threads + threads - 1) / threads;

            chacha_kernel<<<blocks, threads, 0, stream>>>(d_in, d_out, device_key, device_nonce,
                                                          counter, size);
        });

    cudaFree(device_key);
    cudaFree(device_nonce);
}