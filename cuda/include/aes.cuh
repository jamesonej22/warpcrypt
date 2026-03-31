/** @file aes.cuh
 * @author Eric Jameson
 * @brief Declaration of constants and functions used in the Advanced Encryption
 * Standard (AES). All constants and functions are described on Wikipedia:
 * https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 */

#ifndef __WARPCRYPT_AES_CUH
#define __WARPCRYPT_AES_CUH

#include <cstdint>

#include "warpcrypt.cuh"

/** @brief Number of elements in the state operated on during encryption and decryption. */
#define AES_STATE_SIZE 16
/** @brief Number of rows and columns in the state, used only for loop iteration. */
#define AES_STATE_DIMENSION 4
/** @brief Number of elements in the Rijndael S-box. */
#define AES_SBOX_SIZE 256
/** @brief Constant number of bits per byte, used for multiplication in GF(2^8). */
#define BITS_PER_BYTE 8
/** @brief Number of bytes in a 32-bit word, used in key expansion. */
#define WORD_SIZE 4
/** @brief Constant number of bytes in a 128-bit AES key. */
#define AES_KEY_SIZE_128 16
/** @brief Number of rounds in 128-bit encryption and decryption. */
#define AES_NUM_ROUNDS_128 10
/** @brief Constant number of bytes in a 192-bit AES key. */
#define AES_KEY_SIZE_192 24
/** @brief Number of rounds in 192-bit encryption and decryption. */
#define AES_NUM_ROUNDS_192 12
/** @brief Constant number of bytes in a 256-bit AES key. */
#define AES_KEY_SIZE_256 32
/** @brief Number of rounds in 256-bit encryption and decryption. */
#define AES_NUM_ROUNDS_256 14
/** @brief Maximum key size amongst all implemented key sizes. */
#define AES_MAX_KEY_SIZE AES_KEY_SIZE_256
/** @brief Maximum number of rounds amongst all implemented key sizes. */
#define AES_MAX_ROUNDS AES_NUM_ROUNDS_256
/** @brief Maximum possible expanded key size amongst all implemented key sizes. */
#define AES_MAX_TOTAL_KEY_SIZE (AES_STATE_SIZE * AES_MAX_ROUNDS) + AES_STATE_SIZE

/** @brief Rijndael S-box used for byte substitution in the SubBytes step of encryption. */
const uint8_t AES_SBOX[AES_SBOX_SIZE] = {
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
const uint32_t AES_ROUND_CONSTANTS[AES_MAX_ROUNDS + 1] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d};

/** @brief Inverse Rijndael S-box used for byte substitution in the InverseSubBytes step of
 * decryption.
 */
const uint8_t AES_INVERSE_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

/** @brief Struct used to contain all relevant AES parameters for a particular request. */
struct AesParameters {
    /** @brief Key size in bytes. */
    uint32_t key_size;
    /** @brief Expanded key size in bytes. */
    uint32_t total_key_size;
    /** @brief Number of rounds to use in encryption or decryption. */
    int num_rounds;

    /** @brief Constructor of an AesParameters object from a given CryptoRequest. */
    AesParameters(const CryptoRequest& request);
};

/** @brief Perform key expansion on the provided key. For more information, see:
 * https://en.wikipedia.org/wiki/AES_key_schedule
 *
 * @param[out] round_keys Expanded key to be used for encryption.
 * @param key Provided key before expansion.
 * @param parameters Parameters for this run of AES.
 */
void aes_expand_key(uint8_t* round_keys, const uint8_t* key, AesParameters parameters);

/** @brief Helper to copy the S-box and round keys into shared memory.
 *
 * @param[out] shared_sbox Shared memory location to store the S-box.
 * @param[out] shared_round_keys Shared memory location to store the round keys.
 * @param sbox Location to read the S-box from.
 * @param round_keys Location to read the round keys from.
 * @param parameters Parameters for this run of AES.
 */
__device__ void aes_load_shared_memory(uint8_t* shared_sbox, uint8_t* shared_round_keys,
                                       const uint8_t* sbox, const uint8_t* round_keys,
                                       AesParameters parameters);

/** @brief Perform the SubBytes step of encryption. For more information, see:
 * https://en.wikipedia.org/wiki/Rijndael_S-box
 *
 * @param[in,out] state The current state to operate on.
 * @param sbox Substitution table to use for SubBytes.
 */
__device__ void aes_sub_bytes(uint8_t* state, const uint8_t* sbox);

/** @brief Perform the ShiftRows step of encryption. For more information, see:
 * https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step
 *
 * @param[in,out] state The current state to operate on.
 */
__device__ void aes_shift_rows(uint8_t* state);

/** @brief Perform the InverseShiftRows step of decryption. This is the inverse of ShiftRows.
 *
 * @param[in,out] state The current state to operate on.
 */
__device__ void aes_inverse_shift_rows(uint8_t* state);

/** @brief Multiply two elements of GF(2^8). Adapted from
 * https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example
 *
 * @param a The first multiplicand.
 * @param b The second multiplicand.
 * @return The product of \p a and \p b in GF(2^8).
 */
__device__ uint8_t aes_galois_multiplication(uint8_t a, uint8_t b);

/** @brief Perform the MixColumns step of encryption. For more information, see:
 * https://en.wikipedia.org/wiki/Rijndael_MixColumns
 *
 * @param[in,out] state The current state to operate on.
 */
__device__ void aes_mix_columns(uint8_t* state);

/** @brief Perform the InverseMixColumns step of decryption. This is the inverse of MixColumns.
 *
 * @param[in,out] state The current state to operate on.
 */
__device__ void aes_inverse_mix_columns(uint8_t* state);

/** @brief Perform the AddRoundKey step of encryption. For more information, see:
 * https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_AddRoundKey
 *
 * @param[in,out] state The current state to operate on.
 * @param round_keys The expanded round keys used for encryption.
 * @param round The round of encryption that we are on.
 */
__device__ void aes_add_round_key(uint8_t* state, const uint8_t* round_keys, int round);

/** @brief Perform standard AES encryption on the input data corresponding to this thread index
 * using the provided S-box and round keys.
 *
 * @param input Plaintext to encrypt.
 * @param[out] output Location to store the encrypted ciphertext.
 * @param sbox Rijndael S-box to use for SubBytes.
 * @param round_keys Expanded keys to use during encryption.
 * @param thread_idx Index of the thread that calls this function, used for indexing into the input
 * and output arrays.
 * @param parameters Parameters for this run of AES encryption.
 */
__device__ void aes_encrypt(const uint8_t* input, uint8_t* output, const uint8_t* sbox,
                            const uint8_t* round_keys, size_t thread_idx, AesParameters parameters);

/** @brief Perform standard AES decryption on the input data corresponding to this thread index
 * using the provided S-box and round keys.
 *
 * @param input Ciphertext to decrypt.
 * @param[out] output Location to store the decrypted plaintext.
 * @param sbox Rijndael Inverse S-box to use for SubBytes.
 * @param round_keys Expanded keys to use during decryption.
 * @param thread_idx Index of the thread that calls this function, used for indexing into the input
 * and output arrays.
 * @param parameters Parameters for this run of AES decryption.
 */
__device__ void aes_decrypt(const uint8_t* input, uint8_t* output, const uint8_t* sbox,
                            const uint8_t* round_keys, size_t thread_idx, AesParameters parameters);

/** @brief Perform AES-CTR encryption/decryption on the input data using the provided S-box, round
 * keys, and CTR-specific information.
 *
 * @param input Plaintext to encrypt or ciphertext to decrypt.
 * @param[out] output Location to store the encrypted ciphertext or decrypted plaintext.
 * @param sbox Rijndael S-box to use for SubBytes.
 * @param round_keys Expanded keys to use during encryption/decryption.
 * @param nonce Nonce to use as input to the AES encryption/decryption for this block.
 * @param counter Counter to use as input to the AES encryption/decryption for this block.
 * @param parameters Parameters for this run of AES-CTR encryption/decryption.
 */
__device__ void aes_ctr(const uint8_t* input, uint8_t* output, const uint8_t* sbox,
                        const uint8_t* round_keys, uint64_t nonce, uint64_t counter,
                        AesParameters parameters);

/** @brief Perform the entirety of AES-ECB encryption on the input data using shared memory arrays.
 *
 * @param input Plaintext to encrypt.
 * @param[out] output Location to store the encrypted ciphertext.
 * @param input_size Length of the plaintext in bytes.
 * @param sbox Rijndael S-box to use for SubBytes.
 * @param round_keys Expanded keys to use during encryption.
 * @param parameters Parameters for this run of AES-ECB encryption.
 */
__global__ void aes_encrypt_ecb_kernel(const uint8_t* input, uint8_t* output, size_t input_size,
                                       const uint8_t* sbox, const uint8_t* round_keys,
                                       AesParameters parameters);

/** @brief Perform the entirety of AES-ECB decryption on the input data using shared memory arrays.
 *
 * @param input Ciphertext to decrypt.
 * @param[out] output Location to store the decrypted plaintext.
 * @param input_size Length of the ciphertext in bytes.
 * @param sbox Inverse Rijndael S-box to use for SubBytes.
 * @param round_keys Expanded keys to use during decryption.
 * @param parameters Parameters for this run of AES-ECB decryption.
 */
__global__ void aes_decrypt_ecb_kernel(const uint8_t* input, uint8_t* output, size_t input_size,
                                       const uint8_t* sbox, const uint8_t* round_keys,
                                       AesParameters parameters);

/** @brief Perform the entirety of AES-CTR encryption or decryption on the input data using shared
 * memory arrays.
 *
 * @param input Plaintext to encrypt or ciphertext to decrypt.
 * @param[out] output Location to store the encrypted ciphertext or decrpyted plaintext.
 * @param input_size Length of the input plaintext/ciphertext in bytes.
 * @param sbox Rijndael S-box to use for SubBytes.
 * @param round_keys Expanded keys to use during encryption/decryption.
 * @param nonce Nonce to use as input to the cipher.
 * @param ctr_start The counter starting value for this input.
 * @param parameters Parameters for this run of AES-CTR encryption/decryption.
 */
__global__ void aes_ctr_kernel(const uint8_t* input, uint8_t* output, size_t input_size,
                               const uint8_t* sbox, const uint8_t* round_keys, uint64_t nonce,
                               uint64_t ctr_start, AesParameters parameters);

/** @brief Launch the AES-ECB kernel corresponding to this request. Handles all CUDA parameters as
 * well as AES-specific parameters.
 *
 * @param request The packaged CryptoRequest containing all parsed command-line arguments.
 * @param key The encryption key for this run of AES-ECB.
 * @param input The plaintext to encrypt or ciphertext to decrypt.
 * @param[out] output The encrypted ciphertext or decrypted plaintext.
 * @param input_length The length of the input in bytes.
 */
void launch_aes_ecb(const CryptoRequest& request, const uint8_t* key, const uint8_t* input,
                    uint8_t* output, size_t input_length);

/** @brief Launch the AES-CTR kernel corresponding to this request. Handles all CUDA parameters as
 * well as AES-specific parameters.
 *
 * @param request The packaged CryptoRequest containing all parsed command-line arguments.
 * @param key The encryption key for this run of AES-CTR.
 * @param iv The packaged nonce + counter for the first block to encrypt or decrypt.
 * @param input The plaintext to encrypt or ciphertext to decrypt.
 * @param[out] output The encrypted ciphertext or decrypted plaintext.
 * @param input_length The length of the input in bytes.
 */
void launch_aes_ctr(const CryptoRequest& request, const uint8_t* key, const uint8_t* iv,
                    const uint8_t* input, uint8_t* output, size_t input_length);

#endif