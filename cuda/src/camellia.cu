/** @file camellia.cu
 * @author Eric Jameson
 * @brief Implementation of functions used in Camellia. All functions are described in the Camellia
 * RFC: https://www.rfc-editor.org/rfc/rfc3713
 */

#include <cstdint>
#include <cstring>

#include "camellia.cuh"
#include "utils.cuh"

CamelliaParameters::CamelliaParameters(const CryptoRequest& request) {
    switch (request.key_size) {
        case KeySize::KeySize128:
            key_size = CAMELLIA_KEY_SIZE_128;
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

void camellia_generate_keys(const uint8_t* key, CamelliaKeySchedule* schedule,
                            const CamelliaSboxes* sboxes, CamelliaParameters parameters) {
    uint64_t kl[2] = {load_be64(key), load_be64(key + 8)};
    uint64_t kr[2] = {0};

    if (parameters.key_size == CAMELLIA_KEY_SIZE_192) {
        kr[0] = load_be64(key + 16);
        kr[1] = ~kr[0];
    } else if (parameters.key_size == CAMELLIA_KEY_SIZE_256) {
        kr[0] = load_be64(key + 16);
        kr[1] = load_be64(key + 24);
    }

    // Generate ka and kb
    uint64_t d1 = kl[0] ^ kr[0];
    uint64_t d2 = kl[1] ^ kr[1];
    d2 ^= camellia_f(d1, CAMELLIA_SIGMA[0], sboxes);
    d1 ^= camellia_f(d2, CAMELLIA_SIGMA[1], sboxes);
    d1 ^= kl[0];
    d2 ^= kl[1];
    d2 ^= camellia_f(d1, CAMELLIA_SIGMA[2], sboxes);
    d1 ^= camellia_f(d2, CAMELLIA_SIGMA[3], sboxes);
    uint64_t ka[2] = {d1, d2};
    uint64_t kb[2] = {0};

    if (parameters.key_size != CAMELLIA_KEY_SIZE_128) {
        d1 = ka[0] ^ kr[0];
        d2 = ka[1] ^ kr[1];
        d2 ^= camellia_f(d1, CAMELLIA_SIGMA[4], sboxes);
        d1 ^= camellia_f(d2, CAMELLIA_SIGMA[5], sboxes);
        kb[0] = d1;
        kb[1] = d2;
    }

    camellia_expand_keys(ka, kb, kl, kr, schedule, parameters);
}

void camellia_expand_keys(const uint64_t ka[2], const uint64_t kb[2], const uint64_t kl[2],
                          const uint64_t kr[2], CamelliaKeySchedule* schedule,
                          CamelliaParameters parameters) {
    uint64_t tmp[2];
    std::memcpy(schedule->kw, kl, 2 * sizeof(uint64_t));

    if (parameters.key_size == CAMELLIA_KEY_SIZE_128) {
        rotl128(ka, 0, schedule->k);
        rotl128(kl, 15, schedule->k + 2);
        rotl128(ka, 15, schedule->k + 4);
        rotl128(ka, 30, schedule->ke);
        rotl128(kl, 45, schedule->k + 6);
        rotl128(ka, 45, tmp);
        schedule->k[8] = tmp[0];
        rotl128(kl, 60, tmp);
        schedule->k[9] = tmp[1];
        rotl128(ka, 60, schedule->k + 10);
        rotl128(kl, 77, schedule->ke + 2);
        rotl128(kl, 94, schedule->k + 12);
        rotl128(ka, 94, schedule->k + 14);
        rotl128(kl, 111, schedule->k + 16);
        rotl128(ka, 111, schedule->kw + 2);
    } else {
        rotl128(kb, 0, schedule->k);
        rotl128(kr, 15, schedule->k + 2);
        rotl128(ka, 15, schedule->k + 4);
        rotl128(kr, 30, schedule->ke);
        rotl128(kb, 30, schedule->k + 6);
        rotl128(kl, 45, schedule->k + 8);
        rotl128(ka, 45, schedule->k + 10);
        rotl128(kl, 60, schedule->ke + 2);
        rotl128(kr, 60, schedule->k + 12);
        rotl128(kb, 60, schedule->k + 14);
        rotl128(kl, 77, schedule->k + 16);
        rotl128(ka, 77, schedule->ke + 4);
        rotl128(kr, 94, schedule->k + 18);
        rotl128(ka, 94, schedule->k + 20);
        rotl128(kl, 111, schedule->k + 22);
        rotl128(kb, 111, schedule->kw + 2);
    }
}

__device__ void camellia_load_shared_memory(CamelliaSboxes* shared_sboxes,
                                            CamelliaKeySchedule* shared_schedule,
                                            const CamelliaSboxes* sboxes,
                                            const CamelliaKeySchedule* schedule,
                                            CamelliaParameters parameters) {
    for (int i = threadIdx.x; i < CAMELLIA_SBOX_SIZE; i += blockDim.x) {
        shared_sboxes->sbox1[i] = sboxes->sbox1[i];
        shared_sboxes->sbox2[i] = sboxes->sbox2[i];
        shared_sboxes->sbox3[i] = sboxes->sbox3[i];
        shared_sboxes->sbox4[i] = sboxes->sbox4[i];
    }

    uint64_t* shared_schedule_ptr = (uint64_t*)shared_schedule;
    const uint64_t* src_schedule_ptr = (const uint64_t*)schedule;
    for (int i = threadIdx.x; i < CAMELLIA_SCHEDULE_SIZE; i += blockDim.x) {
        shared_schedule_ptr[i] = src_schedule_ptr[i];
    }
}

__host__ __device__ uint64_t camellia_f(uint64_t f_in, uint64_t ke, const CamelliaSboxes* sboxes) {
    uint8_t t[8];
    uint8_t y[8];
    uint64_t x = f_in ^ ke;

    store_be64(t, x);

    t[0] = sboxes->sbox1[t[0]];
    t[1] = sboxes->sbox2[t[1]];
    t[2] = sboxes->sbox3[t[2]];
    t[3] = sboxes->sbox4[t[3]];
    t[4] = sboxes->sbox2[t[4]];
    t[5] = sboxes->sbox3[t[5]];
    t[6] = sboxes->sbox4[t[6]];
    t[7] = sboxes->sbox1[t[7]];

    y[0] = t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7];
    y[1] = t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7];
    y[2] = t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7];
    y[3] = t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
    y[4] = t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7];
    y[5] = t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7];
    y[6] = t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7];
    y[7] = t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6];

    return load_be64(y);
}

__device__ uint64_t camellia_fl(uint64_t fl_in, uint64_t ke) {
    uint32_t x1 = fl_in >> 32;
    uint32_t x2 = fl_in & 0xffffffff;
    uint32_t k1 = ke >> 32;
    uint32_t k2 = ke & 0xffffffff;

    x2 ^= ((x1 & k1) << 1) | ((x1 & k1) >> 31);
    x1 ^= (x2 | k2);

    return ((uint64_t)x1 << 32) | x2;
}

__device__ uint64_t camellia_flinv(uint64_t flinv_in, uint64_t ke) {
    uint32_t y1 = flinv_in >> 32;
    uint32_t y2 = flinv_in & 0xffffffff;
    uint32_t k1 = ke >> 32;
    uint32_t k2 = ke & 0xffffffff;

    y1 ^= (y2 | k2);
    y2 ^= ((y1 & k1) << 1) | ((y1 & k1) >> 31);

    return ((uint64_t)y1 << 32) | y2;
}

__device__ void camellia_encrypt(const uint8_t* input, uint8_t* output,
                                 const CamelliaSboxes* sboxes, const CamelliaKeySchedule* schedule,
                                 size_t thread_idx, CamelliaParameters parameters) {
    uint64_t d1 = load_be64(input + thread_idx * CAMELLIA_STATE_SIZE);
    uint64_t d2 = load_be64(input + thread_idx * CAMELLIA_STATE_SIZE + 8);

    d1 ^= schedule->kw[0];
    d2 ^= schedule->kw[1];

    d2 ^= camellia_f(d1, schedule->k[0], sboxes);
    d1 ^= camellia_f(d2, schedule->k[1], sboxes);
    d2 ^= camellia_f(d1, schedule->k[2], sboxes);
    d1 ^= camellia_f(d2, schedule->k[3], sboxes);
    d2 ^= camellia_f(d1, schedule->k[4], sboxes);
    d1 ^= camellia_f(d2, schedule->k[5], sboxes);

    d1 = camellia_fl(d1, schedule->ke[0]);
    d2 = camellia_flinv(d2, schedule->ke[1]);

    d2 ^= camellia_f(d1, schedule->k[6], sboxes);
    d1 ^= camellia_f(d2, schedule->k[7], sboxes);
    d2 ^= camellia_f(d1, schedule->k[8], sboxes);
    d1 ^= camellia_f(d2, schedule->k[9], sboxes);
    d2 ^= camellia_f(d1, schedule->k[10], sboxes);
    d1 ^= camellia_f(d2, schedule->k[11], sboxes);

    d1 = camellia_fl(d1, schedule->ke[2]);
    d2 = camellia_flinv(d2, schedule->ke[3]);

    d2 ^= camellia_f(d1, schedule->k[12], sboxes);
    d1 ^= camellia_f(d2, schedule->k[13], sboxes);
    d2 ^= camellia_f(d1, schedule->k[14], sboxes);
    d1 ^= camellia_f(d2, schedule->k[15], sboxes);
    d2 ^= camellia_f(d1, schedule->k[16], sboxes);
    d1 ^= camellia_f(d2, schedule->k[17], sboxes);

    if (parameters.key_size != CAMELLIA_KEY_SIZE_128) {
        d1 = camellia_fl(d1, schedule->ke[4]);
        d2 = camellia_flinv(d2, schedule->ke[5]);

        d2 ^= camellia_f(d1, schedule->k[18], sboxes);
        d1 ^= camellia_f(d2, schedule->k[19], sboxes);
        d2 ^= camellia_f(d1, schedule->k[20], sboxes);
        d1 ^= camellia_f(d2, schedule->k[21], sboxes);
        d2 ^= camellia_f(d1, schedule->k[22], sboxes);
        d1 ^= camellia_f(d2, schedule->k[23], sboxes);
    }

    d2 ^= schedule->kw[2];
    d1 ^= schedule->kw[3];

    store_be64(output + thread_idx * CAMELLIA_STATE_SIZE, d2);
    store_be64(output + thread_idx * CAMELLIA_STATE_SIZE + 8, d1);
}

__device__ void camellia_decrypt_128(const uint8_t* input, uint8_t* output,
                                     const CamelliaSboxes* sboxes,
                                     const CamelliaKeySchedule* schedule, size_t thread_idx) {
    uint64_t d1 = load_be64(input + thread_idx * CAMELLIA_STATE_SIZE);
    uint64_t d2 = load_be64(input + thread_idx * CAMELLIA_STATE_SIZE + 8);

    d1 ^= schedule->kw[2];
    d2 ^= schedule->kw[3];

    d2 ^= camellia_f(d1, schedule->k[17], sboxes);
    d1 ^= camellia_f(d2, schedule->k[16], sboxes);
    d2 ^= camellia_f(d1, schedule->k[15], sboxes);
    d1 ^= camellia_f(d2, schedule->k[14], sboxes);
    d2 ^= camellia_f(d1, schedule->k[13], sboxes);
    d1 ^= camellia_f(d2, schedule->k[12], sboxes);

    d1 = camellia_fl(d1, schedule->ke[3]);
    d2 = camellia_flinv(d2, schedule->ke[2]);

    d2 ^= camellia_f(d1, schedule->k[11], sboxes);
    d1 ^= camellia_f(d2, schedule->k[10], sboxes);
    d2 ^= camellia_f(d1, schedule->k[9], sboxes);
    d1 ^= camellia_f(d2, schedule->k[8], sboxes);
    d2 ^= camellia_f(d1, schedule->k[7], sboxes);
    d1 ^= camellia_f(d2, schedule->k[6], sboxes);

    d1 = camellia_fl(d1, schedule->ke[1]);
    d2 = camellia_flinv(d2, schedule->ke[0]);

    d2 ^= camellia_f(d1, schedule->k[5], sboxes);
    d1 ^= camellia_f(d2, schedule->k[4], sboxes);
    d2 ^= camellia_f(d1, schedule->k[3], sboxes);
    d1 ^= camellia_f(d2, schedule->k[2], sboxes);
    d2 ^= camellia_f(d1, schedule->k[1], sboxes);
    d1 ^= camellia_f(d2, schedule->k[0], sboxes);

    d2 ^= schedule->kw[0];
    d1 ^= schedule->kw[1];

    store_be64(output + thread_idx * CAMELLIA_STATE_SIZE, d2);
    store_be64(output + thread_idx * CAMELLIA_STATE_SIZE + 8, d1);
}

__device__ void camellia_decrypt(const uint8_t* input, uint8_t* output,
                                 const CamelliaSboxes* sboxes, const CamelliaKeySchedule* schedule,
                                 size_t thread_idx) {
    uint64_t d1 = load_be64(input + thread_idx * CAMELLIA_STATE_SIZE);
    uint64_t d2 = load_be64(input + thread_idx * CAMELLIA_STATE_SIZE + 8);

    d1 ^= schedule->kw[2];
    d2 ^= schedule->kw[3];

    d2 ^= camellia_f(d1, schedule->k[23], sboxes);
    d1 ^= camellia_f(d2, schedule->k[22], sboxes);
    d2 ^= camellia_f(d1, schedule->k[21], sboxes);
    d1 ^= camellia_f(d2, schedule->k[20], sboxes);
    d2 ^= camellia_f(d1, schedule->k[19], sboxes);
    d1 ^= camellia_f(d2, schedule->k[18], sboxes);

    d1 = camellia_fl(d1, schedule->ke[5]);
    d2 = camellia_flinv(d2, schedule->ke[4]);

    d2 ^= camellia_f(d1, schedule->k[17], sboxes);
    d1 ^= camellia_f(d2, schedule->k[16], sboxes);
    d2 ^= camellia_f(d1, schedule->k[15], sboxes);
    d1 ^= camellia_f(d2, schedule->k[14], sboxes);
    d2 ^= camellia_f(d1, schedule->k[13], sboxes);
    d1 ^= camellia_f(d2, schedule->k[12], sboxes);

    d1 = camellia_fl(d1, schedule->ke[3]);
    d2 = camellia_flinv(d2, schedule->ke[2]);

    d2 ^= camellia_f(d1, schedule->k[11], sboxes);
    d1 ^= camellia_f(d2, schedule->k[10], sboxes);
    d2 ^= camellia_f(d1, schedule->k[9], sboxes);
    d1 ^= camellia_f(d2, schedule->k[8], sboxes);
    d2 ^= camellia_f(d1, schedule->k[7], sboxes);
    d1 ^= camellia_f(d2, schedule->k[6], sboxes);

    d1 = camellia_fl(d1, schedule->ke[1]);
    d2 = camellia_flinv(d2, schedule->ke[0]);

    d2 ^= camellia_f(d1, schedule->k[5], sboxes);
    d1 ^= camellia_f(d2, schedule->k[4], sboxes);
    d2 ^= camellia_f(d1, schedule->k[3], sboxes);
    d1 ^= camellia_f(d2, schedule->k[2], sboxes);
    d2 ^= camellia_f(d1, schedule->k[1], sboxes);
    d1 ^= camellia_f(d2, schedule->k[0], sboxes);

    d2 ^= schedule->kw[0];
    d1 ^= schedule->kw[1];

    store_be64(output + thread_idx * CAMELLIA_STATE_SIZE, d2);
    store_be64(output + thread_idx * CAMELLIA_STATE_SIZE + 8, d1);
}

__device__ void camellia_ctr(const uint8_t* input, uint8_t* output, const CamelliaSboxes* sboxes,
                             const CamelliaKeySchedule* schedule, uint64_t nonce, uint64_t counter,
                             CamelliaParameters parameters) {
    uint64_t d1 = nonce;
    uint64_t d2 = counter;

    d1 ^= schedule->kw[0];
    d2 ^= schedule->kw[1];

    d2 ^= camellia_f(d1, schedule->k[0], sboxes);
    d1 ^= camellia_f(d2, schedule->k[1], sboxes);
    d2 ^= camellia_f(d1, schedule->k[2], sboxes);
    d1 ^= camellia_f(d2, schedule->k[3], sboxes);
    d2 ^= camellia_f(d1, schedule->k[4], sboxes);
    d1 ^= camellia_f(d2, schedule->k[5], sboxes);

    d1 = camellia_fl(d1, schedule->ke[0]);
    d2 = camellia_flinv(d2, schedule->ke[1]);

    d2 ^= camellia_f(d1, schedule->k[6], sboxes);
    d1 ^= camellia_f(d2, schedule->k[7], sboxes);
    d2 ^= camellia_f(d1, schedule->k[8], sboxes);
    d1 ^= camellia_f(d2, schedule->k[9], sboxes);
    d2 ^= camellia_f(d1, schedule->k[10], sboxes);
    d1 ^= camellia_f(d2, schedule->k[11], sboxes);

    d1 = camellia_fl(d1, schedule->ke[2]);
    d2 = camellia_flinv(d2, schedule->ke[3]);

    d2 ^= camellia_f(d1, schedule->k[12], sboxes);
    d1 ^= camellia_f(d2, schedule->k[13], sboxes);
    d2 ^= camellia_f(d1, schedule->k[14], sboxes);
    d1 ^= camellia_f(d2, schedule->k[15], sboxes);
    d2 ^= camellia_f(d1, schedule->k[16], sboxes);
    d1 ^= camellia_f(d2, schedule->k[17], sboxes);

    if (parameters.key_size != CAMELLIA_KEY_SIZE_128) {
        d1 = camellia_fl(d1, schedule->ke[4]);
        d2 = camellia_flinv(d2, schedule->ke[5]);

        d2 ^= camellia_f(d1, schedule->k[18], sboxes);
        d1 ^= camellia_f(d2, schedule->k[19], sboxes);
        d2 ^= camellia_f(d1, schedule->k[20], sboxes);
        d1 ^= camellia_f(d2, schedule->k[21], sboxes);
        d2 ^= camellia_f(d1, schedule->k[22], sboxes);
        d1 ^= camellia_f(d2, schedule->k[23], sboxes);
    }

    d2 ^= schedule->kw[2];
    d1 ^= schedule->kw[3];

    uint64_t in1 = load_be64(input);
    uint64_t in2 = load_be64(input + 8);
    store_be64(output, d2 ^ in1);
    store_be64(output + 8, d1 ^ in2);
}

__global__ void camellia_encrypt_ecb_kernel(const uint8_t* input, uint8_t* output,
                                            size_t input_size, const CamelliaSboxes* sboxes,
                                            const CamelliaKeySchedule* schedule,
                                            CamelliaParameters parameters) {
    __shared__ CamelliaSboxes shared_sboxes;
    __shared__ CamelliaKeySchedule shared_schedule;

    camellia_load_shared_memory(&shared_sboxes, &shared_schedule, sboxes, schedule, parameters);
    __syncthreads();

    size_t grid_size = blockDim.x * gridDim.x;
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    size_t blocks_to_encrypt = input_size / CAMELLIA_STATE_SIZE;

    for (; idx < blocks_to_encrypt; idx += grid_size) {
        camellia_encrypt(input, output, &shared_sboxes, &shared_schedule, idx, parameters);
    }
}

__global__ void camellia_decrypt_ecb_kernel(const uint8_t* input, uint8_t* output,
                                            size_t input_size, const CamelliaSboxes* sboxes,
                                            const CamelliaKeySchedule* schedule,
                                            CamelliaParameters parameters) {
    __shared__ CamelliaSboxes shared_sboxes;
    __shared__ CamelliaKeySchedule shared_schedule;

    camellia_load_shared_memory(&shared_sboxes, &shared_schedule, sboxes, schedule, parameters);
    __syncthreads();

    size_t grid_size = blockDim.x * gridDim.x;
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    size_t blocks_to_encrypt = input_size / CAMELLIA_STATE_SIZE;

    if (parameters.key_size == CAMELLIA_KEY_SIZE_128) {
        for (; idx < blocks_to_encrypt; idx += grid_size) {
            camellia_decrypt_128(input, output, &shared_sboxes, &shared_schedule, idx);
        }
    } else {
        for (; idx < blocks_to_encrypt; idx += grid_size) {
            camellia_decrypt(input, output, &shared_sboxes, &shared_schedule, idx);
        }
    }
}

__global__ void camellia_ctr_kernel(const uint8_t* input, uint8_t* output, size_t input_size,
                                    const CamelliaSboxes* sboxes,
                                    const CamelliaKeySchedule* schedule, uint64_t nonce,
                                    uint64_t ctr_start, CamelliaParameters parameters) {
    __shared__ CamelliaSboxes shared_sboxes;
    __shared__ CamelliaKeySchedule shared_schedule;

    camellia_load_shared_memory(&shared_sboxes, &shared_schedule, sboxes, schedule, parameters);
    __syncthreads();

    size_t grid_size = blockDim.x * gridDim.x;
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    size_t blocks_to_encrypt = input_size / CAMELLIA_STATE_SIZE;

    for (; idx < blocks_to_encrypt; idx += grid_size) {
        uint64_t counter = idx + ctr_start;
        camellia_ctr(input + idx * CAMELLIA_STATE_SIZE, output + idx * CAMELLIA_STATE_SIZE,
                     &shared_sboxes, &shared_schedule, nonce, counter, parameters);
    }
}

void launch_camellia_ecb(const CryptoRequest& request, const uint8_t* key, const uint8_t* input,
                         uint8_t* output, size_t input_length) {
    CamelliaParameters parameters(request);
    CamelliaKeySchedule schedule;
    camellia_generate_keys(key, &schedule, &CAMELLIA_HOST_SBOXES, parameters);

    CamelliaSboxes* device_sboxes;
    CamelliaKeySchedule* device_schedule;
    cudaMalloc(&device_sboxes, sizeof(CamelliaSboxes));
    cudaMalloc(&device_schedule, sizeof(CamelliaKeySchedule));
    cudaMemcpy(device_schedule, &schedule, sizeof(CamelliaKeySchedule), cudaMemcpyHostToDevice);
    cudaMemcpy(device_sboxes, &CAMELLIA_HOST_SBOXES, sizeof(CamelliaSboxes),
               cudaMemcpyHostToDevice);

    launch_with_streams(
        request.num_streams, input_length, input, output,
        [&](cudaStream_t stream, uint8_t* device_in, uint8_t* device_out, size_t size,
            size_t /*offset*/) {
            if (request.operation == Operation::Encrypt) {
                camellia_encrypt_ecb_kernel<<<request.num_blocks, request.block_size, 0, stream>>>(
                    device_in, device_out, size, device_sboxes, device_schedule, parameters);
            } else {
                camellia_decrypt_ecb_kernel<<<request.num_blocks, request.block_size, 0, stream>>>(
                    device_in, device_out, size, device_sboxes, device_schedule, parameters);
            }
        });

    cudaFree(device_schedule);
    cudaFree(device_sboxes);
}

void launch_camellia_ctr(const CryptoRequest& request, const uint8_t* key, const uint8_t* iv,
                         const uint8_t* input, uint8_t* output, size_t input_length) {
    CamelliaParameters parameters(request);
    CamelliaKeySchedule schedule;
    camellia_generate_keys(key, &schedule, &CAMELLIA_HOST_SBOXES, parameters);

    // Extract nonce and counter start from IV
    uint64_t nonce = load_be64(iv);
    uint64_t ctr_start = load_be64(iv + 8);

    CamelliaSboxes* device_sboxes;
    CamelliaKeySchedule* device_schedule;
    cudaMalloc(&device_sboxes, sizeof(CamelliaSboxes));
    cudaMalloc(&device_schedule, sizeof(CamelliaKeySchedule));
    cudaMemcpy(device_schedule, &schedule, sizeof(CamelliaKeySchedule), cudaMemcpyHostToDevice);
    cudaMemcpy(device_sboxes, &CAMELLIA_HOST_SBOXES, sizeof(CamelliaSboxes),
               cudaMemcpyHostToDevice);

    launch_with_streams(
        request.num_streams, input_length, input, output,
        [&](cudaStream_t stream, uint8_t* device_in, uint8_t* device_out, size_t size,
            size_t offset) {
            size_t block_offset = offset / 16;

            camellia_ctr_kernel<<<request.num_blocks, request.block_size, 0, stream>>>(
                device_in, device_out, size, device_sboxes, device_schedule, nonce,
                ctr_start + block_offset, parameters);
        });

    cudaFree(device_schedule);
    cudaFree(device_sboxes);
}