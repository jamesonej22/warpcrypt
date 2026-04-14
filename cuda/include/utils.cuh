/** @file utils.cuh
 * @author Eric Jameson
 * @brief Implementations of utility functions used across the various algorithms.
 */

#ifndef __WARPCRYPT_UTILS_CUH
#define __WARPCRYPT_UTILS_CUH

#include <cstdint>
#include <vector>

/** @brief Utility to load an array of bytes into a little-endian unsigned 32-bit integer.
 *
 * @param p The array of bytes to load.
 * @return The packed 32-bit integer.
 */
__host__ __device__ __forceinline__ uint32_t load_le32(const uint8_t* p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/** @brief Utility to load an array of bytes into a big-endian unsigned 64-bit integer.
 *
 * @param p The array of bytes to load.
 * @return The packed 64-bit integer.
 */
__host__ __device__ __forceinline__ uint64_t load_be64(const uint8_t* p) {
    return (uint64_t)p[0] << 56 | (uint64_t)p[1] << 48 | (uint64_t)p[2] << 40 |
           (uint64_t)p[3] << 32 | (uint64_t)p[4] << 24 | (uint64_t)p[5] << 16 |
           (uint64_t)p[6] << 8 | (uint64_t)p[7];
}

/** @brief Utility to store a big-endian unsigned 64-bit integer into an array of bytes.
 *
 * @param[out] p The location to store the array of bytes.
 * @param v The packed 64-bit integer to store.
 */
__host__ __device__ __forceinline__ void store_be64(uint8_t* p, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        p[i] = v & 0xff;
        v >>= 8;
    }
}

/** @brief Utility to perform bitwise left rotation of a unsigned 32-bit integer.
 *
 * @param in Input integer to rotate.
 * @param n Number of bits to rotate.
 * @return The rotated integer.
 */
__host__ __device__ __forceinline__ uint32_t rotl32(uint32_t in, int n) {
    return (in << n) | (in >> (32 - n));
};

/** @brief Utility to perform bitwise left rotation of a unsigned 128-bit integer, stored as 2
 * 64-bit halves.
 *
 * @param in Input 64-bit halves to rotate.
 * @param n Number of bits to rotate.
 * @param[out] out Location to store the rotated halves.
 */
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

/** @brief Templated helper to run any cryptographic operation with CUDA streams.
 *
 * @tparam F Functional form of the cryptographic operation.
 * @param num_streams The requested number of streams.
 * @param input_length The length of the full input in bytes.
 * @param input The input to this cryptographic operation.
 * @param[out] output The location to store the output of this cryptographic operation.
 * @param stream_function The per-stream function to run.
 */
template <typename F>
void launch_with_streams(size_t num_streams, size_t input_length, const uint8_t* input,
                         uint8_t* output, F&& stream_function) {
    num_streams = std::max<size_t>(1, num_streams);

    if (num_streams == 1) {
        uint8_t* device_in;
        uint8_t* device_out;
        cudaMalloc(&device_in, input_length);
        cudaMalloc(&device_out, input_length);

        cudaMemcpy(device_in, input, input_length, cudaMemcpyHostToDevice);
        stream_function(0, device_in, device_out, input_length, 0);
        cudaDeviceSynchronize();
        cudaMemcpy(output, device_out, input_length, cudaMemcpyDeviceToHost);

        cudaFree(device_in);
        cudaFree(device_out);
        return;
    }

    cudaHostRegister((void*)input, input_length, cudaHostRegisterDefault);
    cudaHostRegister(output, input_length, cudaHostRegisterDefault);

    size_t min_chunk = 1 << 20;
    size_t chunk_size = std::max(min_chunk, (input_length + num_streams - 1) / num_streams);
    std::vector<cudaStream_t> streams(num_streams);
    std::vector<uint8_t*> device_inputs(num_streams);
    std::vector<uint8_t*> device_outputs(num_streams);

    for (size_t i = 0; i < num_streams; i++) {
        cudaStreamCreate(&streams[i]);
        cudaMalloc(&device_inputs[i], chunk_size);
        cudaMalloc(&device_outputs[i], chunk_size);
    }

    for (size_t i = 0; i < num_streams; i++) {
        size_t offset = i * chunk_size;
        size_t current_size = std::min(chunk_size, input_length - offset);
        if (current_size == 0) break;
        cudaMemcpyAsync(device_inputs[i], input + offset, current_size, cudaMemcpyHostToDevice,
                        streams[i]);
        stream_function(streams[i], device_inputs[i], device_outputs[i], current_size, offset);
        cudaMemcpyAsync(output + offset, device_outputs[i], current_size, cudaMemcpyDeviceToHost,
                        streams[i]);
    }

    for (size_t i = 0; i < num_streams; i++) {
        cudaStreamSynchronize(streams[i]);
        cudaStreamDestroy(streams[i]);
        cudaFree(device_inputs[i]);
        cudaFree(device_outputs[i]);
    }

    cudaHostUnregister((void*)input);
    cudaHostUnregister(output);
}

#endif