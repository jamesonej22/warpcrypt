/** @file warpcrypt.cuh
 * @author Eric Jameson
 * @brief Declaration of Rust FFI-based structures and functions, to serve as an entry point into
 * the actual CUDA implementations for WarpCrypt.
 */

#ifndef __WARPCRYPT_CUH
#define __WARPCRYPT_CUH

#include "rust/cxx.h"
#include "warpcrypt/src/lib.rs.h"

/** @brief Fully packaged request for a cryptographic operation. */
struct CryptoRequest;

/** @brief Main CUDA driver function for performing a cryptographic operation. All necessary
 * parameters to complete the operation are passed in here.
 *
 * @param request
 * @param key
 * @param iv
 * @param input
 * @param[out] output
 */
void execute_crypto(const CryptoRequest& request, rust::Slice<const uint8_t> key,
                    rust::Slice<const uint8_t> iv, rust::Slice<const uint8_t> input,
                    rust::Slice<uint8_t> output);

#endif