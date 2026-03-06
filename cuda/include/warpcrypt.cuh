#ifndef __WARPCRYPT_CUH
#define __WARPCRYPT_CUH

#include "rust/cxx.h"
#include "warpcrypt/src/lib.rs.h"

struct CryptoRequest;

bool execute_crypto(const CryptoRequest &request,
                    rust::Slice<const uint8_t> key,
                    rust::Slice<const uint8_t> nonce,
                    rust::Slice<const uint8_t> input,
                    rust::Slice<uint8_t> output);
#endif