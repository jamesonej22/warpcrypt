/**
 * @file aes.cu
 * @author Eric Jameson
 * @brief Implementation of functions used in the Advanced Encryption Standard (AES). All functions
 * are described on Wikipedia: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 */

#include <cstdint>

/** @brief Number of elements in the state operated on during encryption. */
#define AES_STATE_SIZE 16
/** @brief Number of rows and columns in the state, used only for loop iteration. */
#define AES_STATE_DIMENSION 4
/** @brief Number of elements in the Rijndael S-box. */
#define AES_SBOX_SIZE 256
/** @brief Constant number of bits per byte, used for multiplication in GF(2^8). */
#define BITS_PER_BYTE 8
/** @brief Number of bytes in a 32-bit word, used in key expansion. */
#define WORD_SIZE 4
#define AES_MAX_KEY_SIZE 32
#define AES_MAX_ROUNDS 14
#define AES_MAX_TOTAL_KEY_SIZE (AES_MAX_KEY_SIZE * AES_MAX_ROUNDS) + AES_MAX_KEY_SIZE

struct AESParameters {
    size_t key_size;
    size_t total_key_size;
    int num_rounds;
};

/** @brief Rijndael S-box used for byte substitution in the SubBytes step of encryption. */
static uint8_t sbox[AES_SBOX_SIZE] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

/** @brief Round constants used in key expansion. */
const uint32_t round_constants[AES_MAX_ROUNDS] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                                                  0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D};

/** @brief Global device memory location to store the Rijndael S-Box. */
__constant__ uint8_t device_sbox[AES_SBOX_SIZE];

/** @brief Host memory location to store the expanded round keys. */
uint8_t round_keys[AES_MAX_TOTAL_KEY_SIZE];

/** @brief Round constants used in key expansion. */
__constant__ uint8_t device_round_keys[AES_MAX_TOTAL_KEY_SIZE];

/**
 * @brief Perform key expansion on the provided key. For more information, see:
 * https://en.wikipedia.org/wiki/AES_key_schedule
 *
 * @param[out] round_keys Expanded key to be used for encryption.
 * @param key Provided key before expansion.
 */
void aes_expand_key(uint8_t* round_keys, const uint8_t* key, AESParameters& parameters) {
    size_t current_key_size = parameters.key_size;
    uint8_t temp_word[WORD_SIZE];

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

            temp_word[0] ^= round_constants[current_key_size / key_size - 1];
        }

        for (int i = 0; i < WORD_SIZE; i++) {
            round_keys[current_key_size] = round_keys[current_key_size - key_size] ^ temp_word[i];
            current_key_size++;
        }
    }
}

/**
 * @brief Helper to copy the global memory sbox and round keys into shared memory.
 *
 * @param[out] sbox Shared memory location to store the sbox.
 * @param[out] round_keys Shared memory location to store the round keys.
 *
 */
__device__ void aes_load_shared_memory(uint8_t* shared_sbox, uint8_t* shared_round_keys,
                                       AESParameters& parameters) {
    for (int i = threadIdx.x; i < AES_SBOX_SIZE; i += blockDim.x) {
        shared_sbox[i] = device_sbox[i];
    }

    for (int i = threadIdx.x; i < parameters.total_key_size; i += blockDim.x) {
        shared_round_keys[i] = device_round_keys[i];
    }
}

/**
 * @brief Perform the SubBytes step of encryption. For more information, see:
 * https://en.wikipedia.org/wiki/Rijndael_S-box
 *
 * @param[in,out] state The current state to operate on.
 * @param sbox Substitution table to use for SubBytes.
 */
__device__ void aes_sub_bytes(uint8_t* state, const uint8_t* sbox) {
    for (int i = 0; i < AES_STATE_SIZE; i++) {
        state[i] = sbox[state[i]];
    }
}

/**
 * @brief Perform the ShiftRows step of encryption. For more information, see:
 * https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step
 *
 * @param[in,out] state The current state to operate on.
 */
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

/**
 * @brief Multiply two elements of GF(2^8). Adapted from
 * https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example
 *
 * @param a The first multiplicand.
 * @param b The second multiplicand.
 * @return The product of \p a and \p b in GF(2^8).
 */
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

/**
 * @brief Perform the MixColumns step of encryption. For more information, see:
 * https://en.wikipedia.org/wiki/Rijndael_MixColumns
 *
 * @param[in,out] state The current state to operate on.
 */
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

/**
 * @brief Perform the AddRoundKey step of encryption. For more information, see:
 * https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_AddRoundKey
 *
 * @param[in,out] state The current state to operate on.
 * @param round_keys The expanded round keys used for encryption.
 * @param round The round of encryption that we are on.
 *
 */
__device__ void aes_add_round_key(uint8_t* state, const uint8_t* round_keys, int round,
                                  AESParameters& parameters) {
    for (int i = 0; i < AES_STATE_SIZE; i++) {
        state[i] ^= round_keys[round * parameters.key_size + i];
    }
}

/**
 * @brief Perform the standard AES encryption on the input data corresponding to this thread index
 * using the provided sbox and round keys.
 *
 * @param input Plaintext to encrypt.
 * @param[out] output Location to store the encrypted ciphertext.
 * @param sbox Rijndael S-Box to use for SubBytes.
 * @param round_keys Expanded keys to use during encryption.
 * @param thread_idx Index of the thread that calls this function, used for indexing into the input
 * and output arrays.
 *
 */
__device__ void aes_encrypt(const uint8_t* input, uint8_t* output, const uint8_t* sbox,
                            const uint8_t* round_keys, size_t thread_idx,
                            AESParameters& parameters) {
    uint8_t state[AES_STATE_SIZE];
    for (int i = 0; i < AES_STATE_SIZE; i++) {
        state[i] = input[thread_idx * AES_STATE_SIZE + i];
    }

    int num_rounds = parameters.num_rounds;
    aes_add_round_key(state, round_keys, 0, parameters);

    for (int round = 1; round < num_rounds; round++) {
        aes_sub_bytes(state, sbox);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, round_keys, round, parameters);
    }

    aes_sub_bytes(state, sbox);
    aes_shift_rows(state);
    aes_add_round_key(state, round_keys, num_rounds, parameters);

    for (int i = 0; i < AES_STATE_SIZE; i++) {
        output[thread_idx * AES_STATE_SIZE + i] = state[i];
    }
}

/**
 * @brief Perform AES-CTR encryption on the input data using the provided sbox, round keys, and
 * CTR-specific information.
 *
 * @param input Plaintext to encrypt.
 * @param[out] output Location to store the encrypted ciphertext.
 * @param sbox Rijndael S-Box to use for SubBytes.
 * @param round_keys Expanded keys to use during encryption.
 * @param nonce Nonce to use as input to the AES encryption for this block.
 * @param counter Counter to use as input to the AES encryption for this block.
 *
 */
__device__ void aes_encrypt_ctr(const uint8_t* input, uint8_t* output, const uint8_t* sbox,
                                const uint8_t* round_keys, uint64_t nonce, uint64_t counter,
                                AESParameters& parameters) {
    uint8_t state[AES_STATE_SIZE];

    // Construct counter block
    for (int i = 0; i < 8; i++) {
        state[i] = (nonce >> (56 - 8 * i)) & 0xff;
        state[8 + i] = (counter >> (56 - 8 * i)) & 0xff;
    }

    int num_rounds = parameters.num_rounds;
    aes_add_round_key(state, round_keys, 0, parameters);

    for (int round = 1; round < num_rounds; round++) {
        aes_sub_bytes(state, sbox);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, round_keys, round, parameters);
    }

    aes_sub_bytes(state, sbox);
    aes_shift_rows(state);
    aes_add_round_key(state, round_keys, num_rounds, parameters);

    for (int i = 0; i < AES_STATE_SIZE; i++) {
        output[i] = input[i] ^ state[i];
    }
}

/**
 * @brief Perform the entirety of AES-ECB encryption on the input data using shared memory arrays,
 * copied from global memory.
 *
 * @param input Plaintext to encrypt.
 * @param[out] output Location to store the encrypted ciphertext.
 * @param input_size Length of the plaintext in bytes.
 *
 */
__global__ void aes_encrypt_ecb_kernel(const uint8_t* input, uint8_t* output, size_t input_size,
                                       AESParameters& parameters) {
    __shared__ uint8_t shared_sbox[AES_SBOX_SIZE];
    __shared__ uint8_t shared_round_keys[AES_MAX_TOTAL_KEY_SIZE];

    aes_load_shared_memory(shared_sbox, shared_round_keys, parameters);
    __syncthreads();

    size_t grid_size = blockDim.x * gridDim.x;
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    size_t blocks_to_encrypt = input_size / AES_STATE_SIZE;

    for (; idx < blocks_to_encrypt; idx += grid_size) {
        aes_encrypt(input, output, shared_sbox, shared_round_keys, idx, parameters);
    }
}

/**
 * @brief Perform the entirety of AES-CTR encryption on the input data using shared memory arrays,
 * copied from constant memory.
 *
 * @param input Plaintext to encrypt.
 * @param[out] output Location to store the encrypted ciphertext.
 * @param input_size Length of the plaintext in bytes.
 * @param ctr_start The counter starting value for this input.
 *
 */
__global__ void aes_encrypt_ctr_kernel(const uint8_t* input, uint8_t* output, size_t input_size,
                                       uint64_t nonce, size_t ctr_start,
                                       AESParameters& parameters) {
    __shared__ uint8_t shared_sbox[AES_SBOX_SIZE];
    __shared__ uint8_t shared_round_keys[AES_MAX_TOTAL_KEY_SIZE];

    aes_load_shared_memory(shared_sbox, shared_round_keys, parameters);
    __syncthreads();

    size_t grid_size = blockDim.x * gridDim.x;
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    size_t blocks_to_encrypt = input_size / AES_STATE_SIZE;

    for (; idx < blocks_to_encrypt; idx += grid_size) {
        uint64_t counter = idx + ctr_start;
        aes_encrypt_ctr(input + idx * AES_STATE_SIZE, output + idx * AES_STATE_SIZE, shared_sbox,
                        shared_round_keys, nonce, counter, parameters);
    }
}