#ifndef __WARPCRYPT_CAMELLIA_CUH
#define __WARPCRYPT_CAMELLIA_CUH

#include "warpcrypt.cuh"

#define CAMELLIA_STATE_SIZE 16
#define CAMELLIA_KEY_SIZE_128 16
#define CAMELLIA_NUM_ROUNDS_128 18
#define CAMELLIA_KEY_SIZE_192 24
#define CAMELLIA_KEY_SIZE_256 32
#define CAMELLIA_MAX_ROUNDS 24
#define CAMELLIA_SIGMA_SIZE 6
#define CAMELLIA_KW_SIZE 4
#define CAMELLIA_KE_MAX_SIZE 6

static const uint64_t camellia_sigma[CAMELLIA_SIGMA_SIZE] = {
    0xa09e667f3bcc908b, 0xb67ae8584caa73b2, 0xc6ef372fe94f82be,
    0x54ff53a5f1d36f1c, 0x10e527fade682d1d, 0xb05688c2b3e6c1fd};

static uint64_t camellia_kw[CAMELLIA_KW_SIZE];
static uint64_t camellia_key[CAMELLIA_MAX_ROUNDS];
static uint64_t camellia_ke[CAMELLIA_KE_MAX_SIZE];

struct CamelliaParameters {
    size_t key_size;
    int num_rounds;

    CamelliaParameters(const CryptoRequest& request);
};

void camellia_generate_keys(const uint8_t* key, uint8_t* ka, uint8_t* kb,
                            CamelliaParameters parameters);

void camellia_expand_keys(const uint64_t ka[2], const uint64_t kb[2], const uint64_t kl[2],
                          const uint64_t kr[2], CamelliaParameters parameters);

__host__ __device__ uint64_t camellia_f(uint64_t a, uint64_t b);

#endif