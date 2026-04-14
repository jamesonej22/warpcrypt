/** @file chacha.cuh
 * @author Eric Jameson
 * @brief Declaration of constants and functions used in ChaCha20. All constants and functions are
 * described in the ChaCha20 RFC: https://www.rfc-editor.org/rfc/rfc8439
 */

#ifndef __WARPCRYPT_CHACHA_CUH
#define __WARPCRYPT_CHACHA_CUH

#include "warpcrypt.cuh"

/** @brief The size of the ChaCha20 key in bytes. */
#define CHACHA_KEY_SIZE 32
/** @brief The size of the ChaCha20 nonce in bytes. */
#define CHACHA_NONCE_SIZE 12
/** @brief The size of the ChaCha20 state in bytes. */
#define CHACHA_BLOCK_SIZE 64

/** @brief Implementation of a ChaCha quarter-round operation. Note that all input values are
 * modified in this function.
 *
 * @param[in,out] a The first integer.
 * @param[in,out] b The second integer.
 * @param[in,out] c The third integer.
 * @param[in,out] d The fourth integer.
 */
__device__ __forceinline__ void quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d);

/** @brief Helper function to initialize the state for this block of ChaCha, based on the key,
 * nonce, counter, and ID of this block.
 *
 * @param[out] state The initialized state.
 * @param key The encryption key in bytes.
 * @param nonce The nonce in bytes.
 * @param counter The initial counter for the overall encryption.
 * @param id The ID of this block.
 */
__device__ __forceinline__ void initialize_state(uint32_t* state, const uint8_t* key,
                                                 const uint8_t* nonce, uint32_t counter);

/** @brief CUDA Kernel to perform ChaCha20 encryption/decryption.
 *
 * @param input The plaintext to encrypt or ciphertext to decrypt.
 * @param[out] output The encrypted ciphertext/decrypted plaintext.
 * @param key The encryption key for this run of ChaCha20.
 * @param nonce The nonce for this run of ChaCha20.
 * @param counter The counter for the first block to encrypt/decrypt.
 * @param input_size The length of the input in bytes.
 */
__global__ void chacha_kernel(const uint8_t* input, uint8_t* output, const uint8_t* key,
                              const uint8_t* nonce, uint32_t counter, uint32_t input_size);

/** @brief Launch the ChaCha20 kernel corresponding to this request. Handles all CUDA parameters as
 * well as ChaCha20-specific parameters.
 *
 * @param request The packaged CryptoRequest containing all parsed command-line arguments.
 * @param key The encryption key for this run of ChaCha20.
 * @param iv The packaged nonce + counter for the first block to encrypt or decrypt.
 * @param input The plaintext to encrypt or ciphertext to decrypt.
 * @param[out] output The encrypted ciphertext or decrypted plaintext.
 * @param input_length The length of the input in bytes.
 */
void launch_chacha(const CryptoRequest& request, const uint8_t* key, const uint8_t* iv,
                   const uint8_t* input, uint8_t* output, size_t input_length);

#endif