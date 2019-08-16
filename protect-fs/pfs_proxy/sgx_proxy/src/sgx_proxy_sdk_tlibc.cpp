#include "sgx_proxy_sdk_tlibc.h"
#include <string.h>

// Note: This function below->consttime_memequal, is being used by Intel SGX
// SDK.
/* $NetBSD: consttime_memequal.c,v 1.6 2015/03/18 20:11:35 riastradh Exp $ */

/*
 * Written by Matthias Drochner <drochner@NetBSD.org>.
 * Public domain.
 */
int consttime_memequal(const void* b1, const void* b2, size_t len) {
    const unsigned char* c1 = (const unsigned char*)b1;
    const unsigned char* c2 = (const unsigned char*)b2;

    unsigned int res = 0;

    while (len--) res |= *c1++ ^ *c2++;

    /*
     * Map 0 to 1 and [1, 256) to 0 using only constant-time
     * arithmetic.
     *
     * This is not simply `!res' because although many CPUs support
     * branchless conditional moves and many compilers will take
     * advantage of them, certain compilers generate branches on
     * certain CPUs for `!res'.
     */
    return (1 & ((res - 1) >> 8));
}
