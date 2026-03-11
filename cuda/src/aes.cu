/**
 * @file aes.cu
 * @author Eric Jameson
 * @brief Implementation of functions used in the Advanced Encryption Standard (AES). All functions
 * are described on Wikipedia: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 */

#include <cstdint>
#include <cstring>

#include "aes.cuh"
#include "rust/cxx.h"
#include "utils.cuh"
#include "warpcrypt/src/lib.rs.h"

AesParameters::AesParameters(const CryptoRequest& request) {
    switch (request.key_size) {
        case KeySize::KeySize128:
            key_size = AES_KEY_SIZE_128;
            num_rounds = AES_NUM_ROUNDS_128;
            break;
        case KeySize::KeySize192:
            key_size = AES_KEY_SIZE_192;
            num_rounds = AES_NUM_ROUNDS_192;
            break;
        case KeySize::KeySize256:
            key_size = AES_KEY_SIZE_256;
            num_rounds = AES_NUM_ROUNDS_256;
            break;
        default:
            break;
    }
    total_key_size = AES_STATE_SIZE * (num_rounds + 1);
}

/** @brief Host memory location to store the expanded round keys. */
uint8_t round_keys[AES_MAX_TOTAL_KEY_SIZE];

void aes_expand_key(uint8_t* round_keys, const uint8_t* key, AesParameters parameters) {
    size_t current_key_size = parameters.key_size;
    uint8_t temp_word[WORD_SIZE];
    int rcon_idx = 1;
    int key_size = parameters.key_size;

    for (int i = 0; i < key_size; i++) {
        round_keys[i] = key[i];
    }

    while (current_key_size < parameters.total_key_size) {
        for (int i = 0; i < WORD_SIZE; i++) {
            temp_word[i] = round_keys[current_key_size - WORD_SIZE + i];
        }

        if (current_key_size % key_size == 0) {
            uint8_t temp = temp_word[0];
            temp_word[0] = temp_word[1];
            temp_word[1] = temp_word[2];
            temp_word[2] = temp_word[3];
            temp_word[3] = temp;

            for (int i = 0; i < WORD_SIZE; i++) {
                temp_word[i] = sbox[temp_word[i]];
            }

            temp_word[0] ^= round_constants[rcon_idx];
            rcon_idx++;
        }

        if (key_size == AES_KEY_SIZE_256 && (current_key_size % key_size) == AES_STATE_SIZE) {
            for (size_t i = 0; i < WORD_SIZE; i++) {
                temp_word[i] = sbox[temp_word[i]];
            }
        }

        for (int i = 0; i < WORD_SIZE; i++) {
            round_keys[current_key_size] = round_keys[current_key_size - key_size] ^ temp_word[i];
            current_key_size++;
        }
    }
}

__device__ void aes_load_shared_memory(uint8_t* shared_sbox, uint8_t* shared_round_keys,
                                       const uint8_t* sbox, const uint8_t* round_keys,
                                       AesParameters parameters) {
    for (int i = threadIdx.x; i < AES_SBOX_SIZE; i += blockDim.x) {
        shared_sbox[i] = sbox[i];
    }

    for (int i = threadIdx.x; i < parameters.total_key_size; i += blockDim.x) {
        shared_round_keys[i] = round_keys[i];
    }
}

__device__ void aes_sub_bytes(uint8_t* state, const uint8_t* sbox) {
    for (int i = 0; i < AES_STATE_SIZE; i++) {
        state[i] = sbox[state[i]];
    }
}

__device__ void aes_shift_rows(uint8_t* state) {
    // Row 1: Shift left by 1
    uint8_t temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 2: Shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;

    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 3: Shift left by 3 (equivalently, right by 1)
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

__device__ void aes_inverse_shift_rows(uint8_t* state) {
    // Row 1: Shift right by 1
    uint8_t temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // Row 2: Shift right by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;

    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Row 3: Shift right by 3 (equivalently, left by 1)
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

__device__ uint8_t aes_galois_multiplication(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < BITS_PER_BYTE; i++) {
        if ((b & 1) != 0) {
            p ^= a;
        }

        bool high_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if (high_bit_set) {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    return p;
}

__device__ void aes_mix_columns(uint8_t* state) {
    for (int i = 0; i < AES_STATE_DIMENSION; i++) {
        int start_idx = i * AES_STATE_DIMENSION;
        uint8_t s0 = state[start_idx];
        uint8_t s1 = state[start_idx + 1];
        uint8_t s2 = state[start_idx + 2];
        uint8_t s3 = state[start_idx + 3];

        state[start_idx] =
            aes_galois_multiplication(0x02, s0) ^ aes_galois_multiplication(0x03, s1) ^ s2 ^ s3;
        state[start_idx + 1] =
            s0 ^ aes_galois_multiplication(0x02, s1) ^ aes_galois_multiplication(0x03, s2) ^ s3;
        state[start_idx + 2] =
            s0 ^ s1 ^ aes_galois_multiplication(0x02, s2) ^ aes_galois_multiplication(0x03, s3);
        state[start_idx + 3] =
            aes_galois_multiplication(0x03, s0) ^ s1 ^ s2 ^ aes_galois_multiplication(0x02, s3);
    }
}

__device__ void aes_inverse_mix_columns(uint8_t* state) {
    for (int i = 0; i < AES_STATE_DIMENSION; i++) {
        int start_idx = i * AES_STATE_DIMENSION;
        uint8_t s0 = state[start_idx];
        uint8_t s1 = state[start_idx + 1];
        uint8_t s2 = state[start_idx + 2];
        uint8_t s3 = state[start_idx + 3];

        state[start_idx] =
            aes_galois_multiplication(0x0e, s0) ^ aes_galois_multiplication(0x0b, s1) ^
            aes_galois_multiplication(0x0d, s2) ^ aes_galois_multiplication(0x09, s3);
        state[start_idx + 1] =
            aes_galois_multiplication(0x09, s0) ^ aes_galois_multiplication(0x0e, s1) ^
            aes_galois_multiplication(0x0b, s2) ^ aes_galois_multiplication(0x0d, s3);
        state[start_idx + 2] =
            aes_galois_multiplication(0x0d, s0) ^ aes_galois_multiplication(0x09, s1) ^
            aes_galois_multiplication(0x0e, s2) ^ aes_galois_multiplication(0x0b, s3);
        state[start_idx + 3] =
            aes_galois_multiplication(0x0b, s0) ^ aes_galois_multiplication(0x0d, s1) ^
            aes_galois_multiplication(0x09, s2) ^ aes_galois_multiplication(0x0e, s3);
    }
}

__device__ void aes_add_round_key(uint8_t* state, const uint8_t* round_keys, int round) {
    for (int i = 0; i < AES_STATE_SIZE; i++) {
        state[i] ^= round_keys[round * AES_STATE_SIZE + i];
    }
}

__device__ void aes_gcm_multiplication(const uint8_t* x, const uint8_t* y, uint8_t* output) {
    uint8_t z[AES_STATE_SIZE] = {0};
    uint8_t v[AES_STATE_SIZE];
    std::memcpy(v, y, AES_STATE_SIZE);

    for (int i = 0; i < AES_STATE_SIZE; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            if ((x[i] >> bit) & 1) {
                for (int j = 0; j < AES_STATE_SIZE; j++) {
                    z[j] ^= v[j];
                }
            }

            bool lsb_set = v[AES_STATE_SIZE - 1] & 1;
            for (int j = AES_STATE_SIZE - 1; j > 0; j--) {
                v[j] = (v[j] >> 1) | (v[j - 1] << 7);
            }
            v[0] >>= 1;

            if (lsb_set) {
                v[0] ^= 0xe1;
            }
        }
    }
    std::memcpy(output, z, AES_STATE_SIZE);
}

__device__ void aes_ghash(const uint8_t* h, const uint8_t* x, size_t len, uint8_t* output) {
    uint8_t y[AES_STATE_SIZE] = {0};
    uint8_t tmp[AES_STATE_SIZE];

    size_t num_blocks = len / AES_STATE_SIZE;
    for (size_t i = 0; i < num_blocks; i++) {
        for (int j = 0; j < AES_STATE_SIZE; j++) {
            y[j] ^= x[i * AES_STATE_SIZE + j];
        }
        aes_gcm_multiplication(y, h, tmp);
        std::memcpy(y, tmp, AES_STATE_SIZE);
    }
    std::memcpy(output, y, AES_STATE_SIZE);
}

__device__ void aes_encrypt(const uint8_t* input, uint8_t* output, const uint8_t* sbox,
                            const uint8_t* round_keys, size_t thread_idx,
                            AesParameters parameters) {
    uint8_t state[AES_STATE_SIZE];
    for (int i = 0; i < AES_STATE_SIZE; i++) {
        state[i] = input[thread_idx * AES_STATE_SIZE + i];
    }

    int num_rounds = parameters.num_rounds;
    aes_add_round_key(state, round_keys, 0);

    for (int round = 1; round < num_rounds; round++) {
        aes_sub_bytes(state, sbox);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, round_keys, round);
    }

    aes_sub_bytes(state, sbox);
    aes_shift_rows(state);
    aes_add_round_key(state, round_keys, num_rounds);

    for (int i = 0; i < AES_STATE_SIZE; i++) {
        output[thread_idx * AES_STATE_SIZE + i] = state[i];
    }
}

__device__ void aes_decrypt(const uint8_t* input, uint8_t* output, const uint8_t* sbox,
                            const uint8_t* round_keys, size_t thread_idx,
                            AesParameters parameters) {
    uint8_t state[AES_STATE_SIZE];
    for (int i = 0; i < AES_STATE_SIZE; i++) {
        state[i] = input[thread_idx * AES_STATE_SIZE + i];
    }

    int num_rounds = parameters.num_rounds;
    aes_add_round_key(state, round_keys, num_rounds);

    for (int round = num_rounds - 1; round >= 1; round--) {
        aes_inverse_shift_rows(state);
        aes_sub_bytes(state, sbox);
        aes_add_round_key(state, round_keys, round);
        aes_inverse_mix_columns(state);
    }

    aes_inverse_shift_rows(state);
    aes_sub_bytes(state, sbox);
    aes_add_round_key(state, round_keys, 0);

    for (int i = 0; i < AES_STATE_SIZE; i++) {
        output[thread_idx * AES_STATE_SIZE + i] = state[i];
    }
}

__device__ void aes_ctr(const uint8_t* input, uint8_t* output, const uint8_t* sbox,
                        const uint8_t* round_keys, uint64_t nonce, uint64_t counter,
                        AesParameters parameters) {
    uint8_t state[AES_STATE_SIZE];

    // Construct counter block
    store_be64(state, nonce);
    store_be64(state + 8, counter);

    int num_rounds = parameters.num_rounds;
    aes_add_round_key(state, round_keys, 0);

    for (int round = 1; round < num_rounds; round++) {
        aes_sub_bytes(state, sbox);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, round_keys, round);
    }

    aes_sub_bytes(state, sbox);
    aes_shift_rows(state);
    aes_add_round_key(state, round_keys, num_rounds);

    for (int i = 0; i < AES_STATE_SIZE; i++) {
        output[i] = input[i] ^ state[i];
    }
}

__global__ void aes_encrypt_ecb_kernel(const uint8_t* input, uint8_t* output, size_t input_size,
                                       const uint8_t* sbox, const uint8_t* round_keys,
                                       AesParameters parameters) {
    __shared__ uint8_t shared_sbox[AES_SBOX_SIZE];
    __shared__ uint8_t shared_round_keys[AES_MAX_TOTAL_KEY_SIZE];

    aes_load_shared_memory(shared_sbox, shared_round_keys, sbox, round_keys, parameters);
    __syncthreads();

    size_t grid_size = blockDim.x * gridDim.x;
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    size_t blocks_to_encrypt = input_size / AES_STATE_SIZE;

    for (; idx < blocks_to_encrypt; idx += grid_size) {
        aes_encrypt(input, output, shared_sbox, shared_round_keys, idx, parameters);
    }
}

__global__ void aes_decrypt_ecb_kernel(const uint8_t* input, uint8_t* output, size_t input_size,
                                       const uint8_t* sbox, const uint8_t* round_keys,
                                       AesParameters parameters) {
    __shared__ uint8_t shared_sbox[AES_SBOX_SIZE];
    __shared__ uint8_t shared_round_keys[AES_MAX_TOTAL_KEY_SIZE];

    aes_load_shared_memory(shared_sbox, shared_round_keys, sbox, round_keys, parameters);
    __syncthreads();

    size_t grid_size = blockDim.x * gridDim.x;
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    size_t blocks_to_encrypt = input_size / AES_STATE_SIZE;

    for (; idx < blocks_to_encrypt; idx += grid_size) {
        aes_decrypt(input, output, shared_sbox, shared_round_keys, idx, parameters);
    }
}

__global__ void aes_ctr_kernel(const uint8_t* input, uint8_t* output, size_t input_size,
                               const uint8_t* sbox, const uint8_t* round_keys, uint64_t nonce,
                               uint64_t ctr_start, AesParameters parameters) {
    __shared__ uint8_t shared_sbox[AES_SBOX_SIZE];
    __shared__ uint8_t shared_round_keys[AES_MAX_TOTAL_KEY_SIZE];

    aes_load_shared_memory(shared_sbox, shared_round_keys, sbox, round_keys, parameters);
    __syncthreads();

    size_t grid_size = blockDim.x * gridDim.x;
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    size_t blocks_to_encrypt = input_size / AES_STATE_SIZE;

    for (; idx < blocks_to_encrypt; idx += grid_size) {
        uint64_t counter = idx + ctr_start;
        aes_ctr(input + idx * AES_STATE_SIZE, output + idx * AES_STATE_SIZE, shared_sbox,
                shared_round_keys, nonce, counter, parameters);
    }
}

__device__ void aes_gcm_encrypt(const uint8_t* plaintext, uint8_t* ciphertext, size_t length,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* nonce,  // 12 bytes standard
                                uint8_t* tag, const uint8_t* sbox, const uint8_t* round_keys,
                                AesParameters parameters) {}

bool launch_aes_ecb(const CryptoRequest& request, const uint8_t* key, const uint8_t* input,
                    uint8_t* output, size_t input_length) {
    AesParameters parameters(request);

    uint8_t round_keys[AES_MAX_TOTAL_KEY_SIZE];
    aes_expand_key(round_keys, key, parameters);

    uint8_t* device_input;
    uint8_t* device_output;
    uint8_t* device_round_keys;
    uint8_t* device_sbox;

    cudaMalloc(&device_input, input_length);
    cudaMalloc(&device_output, input_length);
    cudaMalloc(&device_round_keys, parameters.total_key_size);
    cudaMalloc(&device_sbox, AES_SBOX_SIZE);

    cudaMemcpy(device_round_keys, round_keys, parameters.total_key_size, cudaMemcpyHostToDevice);

    switch (request.operation) {
        case Operation::Encrypt:
            cudaMemcpy(device_sbox, sbox, AES_SBOX_SIZE, cudaMemcpyHostToDevice);
            cudaMemcpy(device_input, input, input_length, cudaMemcpyHostToDevice);
            aes_encrypt_ecb_kernel<<<1, 1>>>(device_input, device_output, input_length, device_sbox,
                                             device_round_keys, parameters);
            break;
        case Operation::Decrypt:
            cudaMemcpy(device_sbox, inverse_sbox, AES_SBOX_SIZE, cudaMemcpyHostToDevice);
            cudaMemcpy(device_input, input, input_length, cudaMemcpyHostToDevice);
            aes_decrypt_ecb_kernel<<<1, 1>>>(device_input, device_output, input_length, device_sbox,
                                             device_round_keys, parameters);
            break;
    }

    cudaDeviceSynchronize();
    cudaMemcpy(output, device_output, input_length, cudaMemcpyDeviceToHost);

    cudaFree(device_sbox);
    cudaFree(device_round_keys);
    cudaFree(device_output);
    cudaFree(device_input);
    return true;
}

bool launch_aes_ctr(const CryptoRequest& request, const uint8_t* key, const uint8_t* iv,
                    const uint8_t* input, uint8_t* output, size_t input_length) {
    AesParameters parameters(request);

    uint8_t round_keys[AES_MAX_TOTAL_KEY_SIZE];
    aes_expand_key(round_keys, key, parameters);

    // Extract nonce and counter start from IV
    uint64_t nonce = load_be64(iv);
    uint64_t ctr_start = load_be64(iv + 8);

    uint8_t* device_input;
    uint8_t* device_output;
    uint8_t* device_round_keys;
    uint8_t* device_sbox;

    cudaMalloc(&device_input, input_length);
    cudaMalloc(&device_output, input_length);
    cudaMalloc(&device_round_keys, parameters.total_key_size);
    cudaMalloc(&device_sbox, AES_SBOX_SIZE);

    cudaMemcpy(device_round_keys, round_keys, parameters.total_key_size, cudaMemcpyHostToDevice);

    cudaMemcpy(device_sbox, sbox, AES_SBOX_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(device_input, input, input_length, cudaMemcpyHostToDevice);
    aes_ctr_kernel<<<1, 1>>>(device_input, device_output, input_length, device_sbox,
                             device_round_keys, nonce, ctr_start, parameters);

    cudaDeviceSynchronize();
    cudaMemcpy(output, device_output, input_length, cudaMemcpyDeviceToHost);

    cudaFree(device_sbox);
    cudaFree(device_round_keys);
    cudaFree(device_output);
    cudaFree(device_input);
    return true;
}