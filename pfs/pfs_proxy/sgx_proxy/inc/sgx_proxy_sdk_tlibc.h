#ifndef _SGX_PROXY_SDK_TLIBC_H_
#define _SGX_PROXY_SDK_TLIBC_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int memcpy_s(void* dest, size_t numberOfElements, const void* src, size_t count);

#ifdef __cplusplus
}
#endif

// Note: these 2 apis..get invoked from C++ code, can be outside of extern "C".
int memset_s(void* s, size_t smax, int c, size_t n);

int consttime_memequal(const void* b1, const void* b2, size_t len);

#endif /* _SGX_PROXY_SDK_TLIBC_H_ */
