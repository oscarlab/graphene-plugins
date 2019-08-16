#ifndef _SGX_PROXY_RAND_H_
#define _SGX_PROXY_RAND_H_

#include "sgx_error.h"
#include "stddef.h"
#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t sgx_read_rand(unsigned char* rand, size_t length_in_bytes);

#ifdef __cplusplus
}
#endif

#endif
