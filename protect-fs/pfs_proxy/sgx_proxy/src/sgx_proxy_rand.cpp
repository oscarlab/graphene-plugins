/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "protfs_debug.h"
#include "string.h"

#include "sgx_error.h"
//#include "sgx_proxy_memory.h"
#include "sgx_proxy_sdk_tlibc.h"

//#include "sgx_proxy_trts_inst.h"
#include "trts_inst.h"

// Note: sgx_trts.h has sgx_read_rand defn.
#include "sgx_proxy_rand.h"
//#include "sgx_trts.h"

// Note: taken from trts.cpp in SGX SDK
sgx_status_t sgx_read_rand(unsigned char* rand, size_t length_in_bytes) {
    uint32_t rand_num;
    size_t size;
    size_t bytes_left       = length_in_bytes;
    unsigned char* byte_ptr = rand;

    // check parameters
    //
    // rand can be within or outside the enclave
    if (!rand || !length_in_bytes) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    // loop to rdrand
    rand_num = 0;
    while (bytes_left > 0) {
        if (0 == do_rdrand(&rand_num)) {
            DBG_PRINT("error, do_rdrand");
            return SGX_ERROR_UNEXPECTED;
        }

        size = (bytes_left < sizeof(rand_num)) ? bytes_left : sizeof(rand_num);
        memcpy(byte_ptr, &rand_num, size);

        byte_ptr += size;
        bytes_left -= size;
    }

    // Note: temp fix to resolve linker issue.
    // memset_s(&rand_num, sizeof(rand_num), 0, sizeof(rand_num));
    memset(&rand_num, 0, sizeof(rand_num));

#ifdef PROTFS_DEBUG
    PRINT_BUF("rand_buff=", rand, length_in_bytes);
#endif

    return SGX_SUCCESS;
}
