/** @file camellia.cuh
 * @author Eric Jameson
 * @brief Declaration of constants and functions used in Camellia. All constants and functions are
 * described in the Camellia RFC: https://www.rfc-editor.org/rfc/rfc3713
 */

#ifndef __WARPCRYPT_CAMELLIA_CUH
#define __WARPCRYPT_CAMELLIA_CUH

#include "warpcrypt.cuh"

/** @brief Number of elements in the state operated on during encryption and decryption. */
#define CAMELLIA_STATE_SIZE 16
/** @brief Constant number of bytes in a 128-bit Camellia key. */
#define CAMELLIA_KEY_SIZE_128 16
/** @brief Constant number of bytes in a 192-bit Camellia key. */
#define CAMELLIA_KEY_SIZE_192 24
/** @brief Constant number of bytes in a 256-bit Camellia key. */
#define CAMELLIA_KEY_SIZE_256 32
/** @brief Maximum number of rounds in Camellia encryption and decryption. */
#define CAMELLIA_MAX_ROUNDS 24
/** @brief Number of elements in the sigma array. */
#define CAMELLIA_SIGMA_SIZE 6
/** @brief Number of elements in each of the Camellia S-boxes. */
#define CAMELLIA_SBOX_SIZE 256
/** @brief Number of `kw` elements in the Camellia key schedule. */
#define CAMELLIA_KW_SIZE 4
/** @brief Maximum number of `ke` elements in the Camellia key schedule. */
#define CAMELLIA_KE_MAX_SIZE 6
/** @brief Total size of the Camellia key schedule. */
#define CAMELLIA_SCHEDULE_SIZE CAMELLIA_MAX_ROUNDS + CAMELLIA_KW_SIZE + CAMELLIA_KE_MAX_SIZE

/** @brief  Sigma values used during key expansion. */
const uint64_t CAMELLIA_SIGMA[CAMELLIA_SIGMA_SIZE] = {0xa09e667f3bcc908b, 0xb67ae8584caa73b2,
                                                      0xc6ef372fe94f82be, 0x54ff53a5f1d36f1c,
                                                      0x10e527fade682d1d, 0xb05688c2b3e6c1fd};

/** @brief Struct containing all S-boxes used during key expansion, encryption and decryption. */
struct CamelliaSboxes {
    /** @brief The first S-box. */
    uint8_t sbox1[CAMELLIA_SBOX_SIZE];
    /** @brief The second S-box. */
    uint8_t sbox2[CAMELLIA_SBOX_SIZE];
    /** @brief The third S-box. */
    uint8_t sbox3[CAMELLIA_SBOX_SIZE];
    /** @brief The fourth S-box. */
    uint8_t sbox4[CAMELLIA_SBOX_SIZE];
};

const CamelliaSboxes CAMELLIA_HOST_SBOXES = {
    .sbox1 = {0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5, 0xe4, 0x85, 0x57, 0x35, 0xea, 0x0c,
              0xae, 0x41, 0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21, 0xed, 0x0e, 0x4f, 0x4e,
              0x1d, 0x65, 0x92, 0xbd, 0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce, 0x3e, 0x30,
              0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a, 0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d,
              0xd9, 0x01, 0x5a, 0xd6, 0x51, 0x56, 0x6c, 0x4d, 0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc,
              0xb0, 0x2d, 0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99, 0xdf, 0x4c, 0xcb, 0xc2,
              0x34, 0x7e, 0x76, 0x05, 0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7, 0x14, 0x58,
              0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c, 0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 0xf2, 0x22,
              0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91, 0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc,
              0x69, 0x50, 0xaa, 0xd0, 0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97, 0x54, 0x5b, 0x1e, 0x95,
              0xe0, 0xff, 0x64, 0xd2, 0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb, 0x8a, 0x03,
              0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94, 0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33,
              0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2, 0x52, 0x9b, 0xd8, 0x26, 0xc8, 0x37,
              0xc6, 0x3b, 0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e, 0xe9, 0x79, 0xa7, 0x8c,
              0x9f, 0x6e, 0xbc, 0x8e, 0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59, 0x78, 0x98,
              0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba, 0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa,
              0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 0xac, 0x0a, 0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38,
              0xf1, 0xa4, 0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1, 0x15, 0xe3, 0xad, 0xf4,
              0x77, 0xc7, 0x80, 0x9e},

    .sbox2 = {0xe0, 0x05, 0x58, 0xd9, 0x67, 0x4e, 0x81, 0xcb, 0xc9, 0x0b, 0xae, 0x6a, 0xd5, 0x18,
              0x5d, 0x82, 0x46, 0xdf, 0xd6, 0x27, 0x8a, 0x32, 0x4b, 0x42, 0xdb, 0x1c, 0x9e, 0x9c,
              0x3a, 0xca, 0x25, 0x7b, 0x0d, 0x71, 0x5f, 0x1f, 0xf8, 0xd7, 0x3e, 0x9d, 0x7c, 0x60,
              0xb9, 0xbe, 0xbc, 0x8b, 0x16, 0x34, 0x4d, 0xc3, 0x72, 0x95, 0xab, 0x8e, 0xba, 0x7a,
              0xb3, 0x02, 0xb4, 0xad, 0xa2, 0xac, 0xd8, 0x9a, 0x17, 0x1a, 0x35, 0xcc, 0xf7, 0x99,
              0x61, 0x5a, 0xe8, 0x24, 0x56, 0x40, 0xe1, 0x63, 0x09, 0x33, 0xbf, 0x98, 0x97, 0x85,
              0x68, 0xfc, 0xec, 0x0a, 0xda, 0x6f, 0x53, 0x62, 0xa3, 0x2e, 0x08, 0xaf, 0x28, 0xb0,
              0x74, 0xc2, 0xbd, 0x36, 0x22, 0x38, 0x64, 0x1e, 0x39, 0x2c, 0xa6, 0x30, 0xe5, 0x44,
              0xfd, 0x88, 0x9f, 0x65, 0x87, 0x6b, 0xf4, 0x23, 0x48, 0x10, 0xd1, 0x51, 0xc0, 0xf9,
              0xd2, 0xa0, 0x55, 0xa1, 0x41, 0xfa, 0x43, 0x13, 0xc4, 0x2f, 0xa8, 0xb6, 0x3c, 0x2b,
              0xc1, 0xff, 0xc8, 0xa5, 0x20, 0x89, 0x00, 0x90, 0x47, 0xef, 0xea, 0xb7, 0x15, 0x06,
              0xcd, 0xb5, 0x12, 0x7e, 0xbb, 0x29, 0x0f, 0xb8, 0x07, 0x04, 0x9b, 0x94, 0x21, 0x66,
              0xe6, 0xce, 0xed, 0xe7, 0x3b, 0xfe, 0x7f, 0xc5, 0xa4, 0x37, 0xb1, 0x4c, 0x91, 0x6e,
              0x8d, 0x76, 0x03, 0x2d, 0xde, 0x96, 0x26, 0x7d, 0xc6, 0x5c, 0xd3, 0xf2, 0x4f, 0x19,
              0x3f, 0xdc, 0x79, 0x1d, 0x52, 0xeb, 0xf3, 0x6d, 0x5e, 0xfb, 0x69, 0xb2, 0xf0, 0x31,
              0x0c, 0xd4, 0xcf, 0x8c, 0xe2, 0x75, 0xa9, 0x4a, 0x57, 0x84, 0x11, 0x45, 0x1b, 0xf5,
              0xe4, 0x0e, 0x73, 0xaa, 0xf1, 0xdd, 0x59, 0x14, 0x6c, 0x92, 0x54, 0xd0, 0x78, 0x70,
              0xe3, 0x49, 0x80, 0x50, 0xa7, 0xf6, 0x77, 0x93, 0x86, 0x83, 0x2a, 0xc7, 0x5b, 0xe9,
              0xee, 0x8f, 0x01, 0x3d},

    .sbox3 = {0x38, 0x41, 0x16, 0x76, 0xd9, 0x93, 0x60, 0xf2, 0x72, 0xc2, 0xab, 0x9a, 0x75, 0x06,
              0x57, 0xa0, 0x91, 0xf7, 0xb5, 0xc9, 0xa2, 0x8c, 0xd2, 0x90, 0xf6, 0x07, 0xa7, 0x27,
              0x8e, 0xb2, 0x49, 0xde, 0x43, 0x5c, 0xd7, 0xc7, 0x3e, 0xf5, 0x8f, 0x67, 0x1f, 0x18,
              0x6e, 0xaf, 0x2f, 0xe2, 0x85, 0x0d, 0x53, 0xf0, 0x9c, 0x65, 0xea, 0xa3, 0xae, 0x9e,
              0xec, 0x80, 0x2d, 0x6b, 0xa8, 0x2b, 0x36, 0xa6, 0xc5, 0x86, 0x4d, 0x33, 0xfd, 0x66,
              0x58, 0x96, 0x3a, 0x09, 0x95, 0x10, 0x78, 0xd8, 0x42, 0xcc, 0xef, 0x26, 0xe5, 0x61,
              0x1a, 0x3f, 0x3b, 0x82, 0xb6, 0xdb, 0xd4, 0x98, 0xe8, 0x8b, 0x02, 0xeb, 0x0a, 0x2c,
              0x1d, 0xb0, 0x6f, 0x8d, 0x88, 0x0e, 0x19, 0x87, 0x4e, 0x0b, 0xa9, 0x0c, 0x79, 0x11,
              0x7f, 0x22, 0xe7, 0x59, 0xe1, 0xda, 0x3d, 0xc8, 0x12, 0x04, 0x74, 0x54, 0x30, 0x7e,
              0xb4, 0x28, 0x55, 0x68, 0x50, 0xbe, 0xd0, 0xc4, 0x31, 0xcb, 0x2a, 0xad, 0x0f, 0xca,
              0x70, 0xff, 0x32, 0x69, 0x08, 0x62, 0x00, 0x24, 0xd1, 0xfb, 0xba, 0xed, 0x45, 0x81,
              0x73, 0x6d, 0x84, 0x9f, 0xee, 0x4a, 0xc3, 0x2e, 0xc1, 0x01, 0xe6, 0x25, 0x48, 0x99,
              0xb9, 0xb3, 0x7b, 0xf9, 0xce, 0xbf, 0xdf, 0x71, 0x29, 0xcd, 0x6c, 0x13, 0x64, 0x9b,
              0x63, 0x9d, 0xc0, 0x4b, 0xb7, 0xa5, 0x89, 0x5f, 0xb1, 0x17, 0xf4, 0xbc, 0xd3, 0x46,
              0xcf, 0x37, 0x5e, 0x47, 0x94, 0xfa, 0xfc, 0x5b, 0x97, 0xfe, 0x5a, 0xac, 0x3c, 0x4c,
              0x03, 0x35, 0xf3, 0x23, 0xb8, 0x5d, 0x6a, 0x92, 0xd5, 0x21, 0x44, 0x51, 0xc6, 0x7d,
              0x39, 0x83, 0xdc, 0xaa, 0x7c, 0x77, 0x56, 0x05, 0x1b, 0xa4, 0x15, 0x34, 0x1e, 0x1c,
              0xf8, 0x52, 0x20, 0x14, 0xe9, 0xbd, 0xdd, 0xe4, 0xa1, 0xe0, 0x8a, 0xf1, 0xd6, 0x7a,
              0xbb, 0xe3, 0x40, 0x4f},

    .sbox4 = {0x70, 0x2c, 0xb3, 0xc0, 0xe4, 0x57, 0xea, 0xae, 0x23, 0x6b, 0x45, 0xa5, 0xed, 0x4f,
              0x1d, 0x92, 0x86, 0xaf, 0x7c, 0x1f, 0x3e, 0xdc, 0x5e, 0x0b, 0xa6, 0x39, 0xd5, 0x5d,
              0xd9, 0x5a, 0x51, 0x6c, 0x8b, 0x9a, 0xfb, 0xb0, 0x74, 0x2b, 0xf0, 0x84, 0xdf, 0xcb,
              0x34, 0x76, 0x6d, 0xa9, 0xd1, 0x04, 0x14, 0x3a, 0xde, 0x11, 0x32, 0x9c, 0x53, 0xf2,
              0xfe, 0xcf, 0xc3, 0x7a, 0x24, 0xe8, 0x60, 0x69, 0xaa, 0xa0, 0xa1, 0x62, 0x54, 0x1e,
              0xe0, 0x64, 0x10, 0x00, 0xa3, 0x75, 0x8a, 0xe6, 0x09, 0xdd, 0x87, 0x83, 0xcd, 0x90,
              0x73, 0xf6, 0x9d, 0xbf, 0x52, 0xd8, 0xc8, 0xc6, 0x81, 0x6f, 0x13, 0x63, 0xe9, 0xa7,
              0x9f, 0xbc, 0x29, 0xf9, 0x2f, 0xb4, 0x78, 0x06, 0xe7, 0x71, 0xd4, 0xab, 0x88, 0x8d,
              0x72, 0xb9, 0xf8, 0xac, 0x36, 0x2a, 0x3c, 0xf1, 0x40, 0xd3, 0xbb, 0x43, 0x15, 0xad,
              0x77, 0x80, 0x82, 0xec, 0x27, 0xe5, 0x85, 0x35, 0x0c, 0x41, 0xef, 0x93, 0x19, 0x21,
              0x0e, 0x4e, 0x65, 0xbd, 0xb8, 0x8f, 0xeb, 0xce, 0x30, 0x5f, 0xc5, 0x1a, 0xe1, 0xca,
              0x47, 0x3d, 0x01, 0xd6, 0x56, 0x4d, 0x0d, 0x66, 0xcc, 0x2d, 0x12, 0x20, 0xb1, 0x99,
              0x4c, 0xc2, 0x7e, 0x05, 0xb7, 0x31, 0x17, 0xd7, 0x58, 0x61, 0x1b, 0x1c, 0x0f, 0x16,
              0x18, 0x22, 0x44, 0xb2, 0xb5, 0x91, 0x08, 0xa8, 0xfc, 0x50, 0xd0, 0x7d, 0x89, 0x97,
              0x5b, 0x95, 0xff, 0xd2, 0xc4, 0x48, 0xf7, 0xdb, 0x03, 0xda, 0x3f, 0x94, 0x5c, 0x02,
              0x4a, 0x33, 0x67, 0xf3, 0x7f, 0xe2, 0x9b, 0x26, 0x37, 0x3b, 0x96, 0x4b, 0xbe, 0x2e,
              0x79, 0x8c, 0x6e, 0x8e, 0xf5, 0xb6, 0xfd, 0x59, 0x98, 0x6a, 0x46, 0xba, 0x25, 0x42,
              0xa2, 0xfa, 0x07, 0x55, 0xee, 0x0a, 0x49, 0x68, 0x38, 0xa4, 0x28, 0x7b, 0xc9, 0xc1,
              0xe3, 0xf4, 0xc7, 0x9e}};

/** @brief Struct used to store the entirety of the Camellia key schedule. */
struct CamelliaKeySchedule {
    /** @brief The Camellia `k` array. */
    uint64_t k[CAMELLIA_MAX_ROUNDS];
    /** @brief The Camellia `kw` array. */
    uint64_t kw[CAMELLIA_KW_SIZE];
    /** @brief The Camellia `ke` array. */
    uint64_t ke[CAMELLIA_KE_MAX_SIZE];
};

/** @brief Struct used to contain all relevant Camellia parameters for a particular request. */
struct CamelliaParameters {
    /** @brief Key size in bytes. */
    size_t key_size;

    /** @brief Constructor of a CamelliaParameters object from a given CryptoRequest. */
    CamelliaParameters(const CryptoRequest& request);
};

/** @brief Generate the KA and KB subkeys, which are used to then generate the full key schedule.
 * For more information, see RFC 3713 Section 2.2.
 *
 * @param key Provided key before expansion.
 * @param[out] schedule Location to store the expanded key schedule.
 * @param sboxes Memory location of the S-boxes to use for key generation.
 * @param parameters Parameters for this run of Camellia.
 */
void camellia_generate_keys(const uint8_t* key, CamelliaKeySchedule* schedule,
                            const CamelliaSboxes* sboxes, CamelliaParameters parameters);

/** @brief From the KA and KB subkeys, generate the full key schedule for this run. For more
 * information, see RFC 3713 Section 2.2.
 *
 * @param ka KA subkey generated for this key expansion.
 * @param kb KB subkey generated for this key expansion.
 * @param kl The left 128 bits of the key as defined by the specification.
 * @param kr The right 128 bits of the key as defined by the specification. Only used with 192- and
 * 256-bit key sizes.
 * @param[out] schedule Location to store the expanded key schedule.
 * @param parameters Parameters for this run of Camellia.
 */
void camellia_expand_keys(const uint64_t ka[2], const uint64_t kb[2], const uint64_t kl[2],
                          const uint64_t kr[2], CamelliaKeySchedule* schedule,
                          CamelliaParameters parameters);

/** @brief Helper to copy the S-boxes and expanded key schedule into shared memory.
 *
 * @param[out] shared_sboxes Shared memory location to store the S-boxes.
 * @param[out] shared_schedule Shared memory location to store the expanded key schedule.
 * @param sboxes Location to read the S-boxes from.
 * @param schedule Location to read the expanded key schedule from.
 * @param parameters Parameters for this run of Camellia.
 */
__device__ void camellia_load_shared_memory(CamelliaSboxes* shared_sboxes,
                                            CamelliaKeySchedule* shared_schedule,
                                            const CamelliaSboxes* sboxes,
                                            const CamelliaKeySchedule* schedule,
                                            CamelliaParameters parameters);

/** @brief Implementation of the Camellia F-function, accessible from both host and device. For
 * more information, see RFC 3713 Section 2.4.1.
 *
 * @param f_in 64-bit input data for the function.
 * @param ke 64-bit subkey.
 * @param sboxes Memory location of S-boxes to use for substitution.
 * @return 64-bit output data.
 */
__host__ __device__ uint64_t camellia_f(uint64_t f_in, uint64_t ke, const CamelliaSboxes* sboxes);

/** @brief Implementation of the Camellia FL-function. For more information, see RFC 3713
 * Section 2.4.2.
 *
 * @param fl_in 64-bit input data for the function.
 * @param ke 64-bit subkey.
 * @return 64-bit output data.
 */
__device__ uint64_t camellia_fl(uint64_t fl_in, uint64_t ke);

/** @brief Implementation of the FLINV-function, which is the inverse of the FL-function. For more
 * information, see RFC 3713 Section 2.4.2.
 *
 * @param flinv_in 64-bit input data for the function.
 * @param ke 64-bit subkey.
 * @return 64-bit output data.
 */
__device__ uint64_t camellia_flinv(uint64_t flinv_in, uint64_t ke);

/** @brief Perform standard Camellia encryption on the input data corresponding to this thread index
 * using the provided S-boxes and key schedule. For more information, see RFC 3713 Sections 2.3.1
 * & 2.3.2.
 *
 * @param input Plaintext to encrypt.
 * @param[out] output Location to store the encrypted ciphertext.
 * @param sboxes S-boxes to use for substitution.
 * @param schedule Expanded key schedule to use during encryption.
 * @param thread_idx Index of the thread that calls this function, used for indexing into the input
 * and output arrays.
 * @param parameters Parameters for this run of Camellia encryption.
 */
__device__ void camellia_encrypt(const uint8_t* input, uint8_t* output,
                                 const CamelliaSboxes* sboxes, const CamelliaKeySchedule* schedule,
                                 size_t thread_idx, CamelliaParameters parameters);

/** @brief Perform standard 128-bit Camellia decryption on the input data corresponding to this
 * thread index using the provided S-boxes and key schedule. For more information, see RFC 3713
 * Section 2.3.3.
 *
 * @param input Ciphertext to decrypt.
 * @param[out] output Location to store the decrypted plaintext.
 * @param sboxes S-boxes to use for substitution.
 * @param schedule Expanded key schedule to use during decryption.
 * @param thread_idx Index of the thread that calls this function, used for indexing into the input
 * and output arrays.
 */
__device__ void camellia_decrypt_128(const uint8_t* input, uint8_t* output,
                                     const CamelliaSboxes* sboxes,
                                     const CamelliaKeySchedule* schedule, size_t thread_idx);

/** @brief Perform standard 192- or 256-bit Camellia decryption on the input data corresponding to
 * this thread index using the provided S-boxes and key schedule. For more information, see RFC 3713
 * Section 2.3.3.
 *
 * @param input Ciphertext to decrypt.
 * @param[out] output Location to store the decrypted plaintext.
 * @param sboxes S-boxes to use for substitution.
 * @param schedule Expanded key schedule to use during decryption.
 * @param thread_idx Index of the thread that calls this function, used for indexing into the input
 * and output arrays.
 */
__device__ void camellia_decrypt(const uint8_t* input, uint8_t* output,
                                 const CamelliaSboxes* sboxes, const CamelliaKeySchedule* schedule,
                                 size_t thread_idx);

/** @brief Perform Camellia-CTR encryption/decryption on the input data using the provided S-boxes,
 * key schedule, and CTR-specific information.
 *
 * @param input Plaintext to encrypt or ciphertext to decrypt.
 * @param[out] output Location to store the encrypted ciphertext or decrypted plaintext.
 * @param sboxes S-boxes to use for substitution.
 * @param schedule Expanded key schedule to use during encryption/decryption.
 * @param nonce Nonce to use as input to the Camellia encryption/decryption for this block.
 * @param counter Counter to use as input to the Camellia encryption/decryption for this block.
 * @param parameters Parameters for this run of Camellia-CTR encryption/decryption.
 */
__device__ void camellia_ctr(const uint8_t* input, uint8_t* output, const CamelliaSboxes* sboxes,
                             const CamelliaKeySchedule* schedule, uint64_t nonce, uint64_t counter,
                             CamelliaParameters parameters);

/** @brief Perform the entirety of Camellia-ECB encryption on the input data using shared memory
 * arrays.
 *
 * @param input Plaintext to encrypt.
 * @param[out] output Location to store the encrypted ciphertext.
 * @param input_size Length of the plaintext in bytes.
 * @param sbox S-boxes to use for substitution.
 * @param round_keys Expanded key schedule to use during encryption.
 * @param parameters Parameters for this run of Camellia-ECB encryption.
 */
__global__ void camellia_encrypt_ecb_kernel(const uint8_t* input, uint8_t* output,
                                            size_t input_size, const CamelliaSboxes* sboxes,
                                            const CamelliaKeySchedule* round_keys,
                                            CamelliaParameters parameters);

/** @brief Perform the entirety of Camellia-ECB decryption on the input data using shared memory
 * arrays.
 *
 * @param input Ciphertext to decrypt.
 * @param[out] output Location to store the decrypted plaintext.
 * @param input_size Length of the plaintext in bytes.
 * @param sbox S-boxes to use for substitution.
 * @param round_keys Expanded key schedule to use during decryption.
 * @param parameters Parameters for this run of Camellia-ECB decryption.
 */
__global__ void camellia_decrypt_ecb_kernel(const uint8_t* input, uint8_t* output,
                                            size_t input_size, const CamelliaSboxes* sboxes,
                                            const CamelliaKeySchedule* round_keys,
                                            CamelliaParameters parameters);

/** @brief Perform the entirety of Camellia-CTR encryption or decryption on the input data using
 * shared memory arrays.
 *
 * @param input Plaintext to encrypt or ciphertext to decrypt.
 * @param[out] output Location to store the encrypted ciphertext or decrpyted plaintext.
 * @param input_size Length of the input plaintext/ciphertext in bytes.
 * @param sboxes S-boxes to use for substitution.
 * @param schedule Expanded key schedule to use during encryption/decryption.
 * @param nonce Nonce to use as input to the cipher.
 * @param ctr_start The counter starting value for this input.
 * @param parameters Parameters for this run of Camellia-CTR encryption/decryption.
 */
__global__ void camellia_ctr_kernel(const uint8_t* input, uint8_t* output, size_t input_size,
                                    const CamelliaSboxes* sboxes,
                                    const CamelliaKeySchedule* schedule, uint64_t nonce,
                                    uint64_t ctr_start, CamelliaParameters parameters);

/** @brief Launch the Camellia-ECB kernel corresponding to this request. Handles all CUDA parameters
 * as well as Camellia-specific parameters.
 *
 * @param request The packaged CryptoRequest containing all parsed command-line arguments.
 * @param key The encryption key for this run of Camellia-ECB.
 * @param input The plaintext to encrypt or ciphertext to decrypt.
 * @param[out] output The encrypted ciphertext or decrypted plaintext.
 * @param input_length The length of the input in bytes.
 */
void launch_camellia_ecb(const CryptoRequest& request, const uint8_t* key, const uint8_t* input,
                         uint8_t* output, size_t input_length);

/** @brief Launch the Camellia-CTR kernel corresponding to this request. Handles all CUDA parameters
 * as well as Camellia-specific parameters.
 *
 * @param request The packaged CryptoRequest containing all parsed command-line arguments.
 * @param key The encryption key for this run of Camellia-CTR.
 * @param iv The packaged nonce + counter for the first block to encrypt or decrypt.
 * @param input The plaintext to encrypt or ciphertext to decrypt.
 * @param[out] output The encrypted ciphertext or decrypted plaintext.
 * @param input_length The length of the input in bytes.
 */
void launch_camellia_ctr(const CryptoRequest& request, const uint8_t* key, const uint8_t* iv,
                         const uint8_t* input, uint8_t* output, size_t input_length);

#endif