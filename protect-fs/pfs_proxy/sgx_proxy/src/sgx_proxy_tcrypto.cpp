/*
 * License: BSD 3-Clause "New" or "Revised" License
 *
 * Other web pages for this license
 * http://www.opensource.org/licenses/BSD-3-Clause
 *
 * Copyright (C) 2018 Intel Corporation. All rights reserved.
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

//#include "sgx_proxy_tcrypto.h"
#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"
#include "mbedtls/gcm.h"
#include "sgx_tcrypto.h"

#include <errno.h>
#include <stdio.h>

#include "protfs_debug.h"

#define SGX_AESGCM_KEY_SIZE_IN_BITS (SGX_AESGCM_KEY_SIZE * 8)

sgx_status_t /*SGXAPI*/ sgx_rijndael128GCM_encrypt(const sgx_aes_gcm_128bit_key_t* p_key,
                                                   const uint8_t* p_src, uint32_t src_len,
                                                   uint8_t* p_dst, const uint8_t* p_iv,
                                                   uint32_t iv_len, const uint8_t* p_aad,
                                                   uint32_t aad_len,
                                                   sgx_aes_gcm_128bit_tag_t* p_out_mac) {
    int ret_val = 0;
    mbedtls_gcm_context gcm;

    if (!p_key || !p_src || !src_len || !p_dst || !p_iv || !p_out_mac) {
        DBG_PRINT("Invalid params, %s\n", __func__);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    mbedtls_gcm_init(&gcm);

    ret_val = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)p_key,
                                 SGX_AESGCM_KEY_SIZE_IN_BITS);

    DBG_PRINT("after setkey, ret_val = %d\n", ret_val);

    ret_val += mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, src_len, p_iv, iv_len, p_aad,
                                         aad_len, p_src, p_dst, sizeof(sgx_aes_gcm_128bit_tag_t),
                                         (unsigned char*)p_out_mac);

    DBG_PRINT("after encrypt, ret = %d\n", ret_val);

    mbedtls_gcm_free(&gcm);

    return sgx_status_t(ret_val);
}

sgx_status_t /*SGXAPI*/ sgx_rijndael128GCM_decrypt(const sgx_aes_gcm_128bit_key_t* p_key,
                                                   const uint8_t* p_src, uint32_t src_len,
                                                   uint8_t* p_dst, const uint8_t* p_iv,
                                                   uint32_t iv_len, const uint8_t* p_aad,
                                                   uint32_t aad_len,
                                                   const sgx_aes_gcm_128bit_tag_t* p_in_mac) {
    int ret_val = 0;
    mbedtls_gcm_context gcm;

    if (!p_key || !p_src || !src_len || !p_dst || !p_iv || !p_in_mac) {
        DBG_PRINT("Invalid params, %s\n", __func__);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    mbedtls_gcm_init(&gcm);

    ret_val = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)p_key,
                                 SGX_AESGCM_KEY_SIZE_IN_BITS);

    ret_val += mbedtls_gcm_auth_decrypt(&gcm, src_len, p_iv, iv_len, p_aad, aad_len,
                                        (const unsigned char*)p_in_mac,
                                        sizeof(sgx_aes_gcm_128bit_tag_t), p_src, p_dst);

    DBG_PRINT("after decrypt, ret = %d\n", ret_val);

    mbedtls_gcm_free(&gcm);

    return sgx_status_t(ret_val);
}

sgx_status_t sgx_rijndael128_cmac_msg(const sgx_cmac_128bit_key_t* p_key, const uint8_t* p_src,
                                      uint32_t src_len, sgx_cmac_128bit_tag_t* p_mac) {
    int ret_val = 0;

    const mbedtls_cipher_info_t* cipher_info = NULL;
    mbedtls_cipher_type_t cipher_type;

    if (!p_key || !p_src || !p_mac || !src_len) {
        DBG_PRINT("Invalid params, %s\n", __func__);
        return SGX_ERROR_INVALID_PARAMETER;
    }

    cipher_type = MBEDTLS_CIPHER_AES_128_ECB;

    cipher_info = mbedtls_cipher_info_from_type(cipher_type);

    if (cipher_info == NULL) {
        DBG_PRINT("mbedtls_cipher_info_from_type() returned NULL\n");
        ret_val = SGX_ERROR_UNEXPECTED;
        goto exit;
    }

    // key_length in bits
    ret_val =
        mbedtls_cipher_cmac(cipher_info, (unsigned char*)p_key, (sizeof(sgx_cmac_128bit_key_t) * 8),
                            p_src, src_len, (unsigned char*)p_mac);

    if (ret_val != 0) {
        DBG_PRINT("mbedtls_cipher_cmac, error=0x%x\n", ret_val);
        goto exit;
    }

exit:

    DBG_PRINT("after cmac_msg, ret = %d\n", ret_val);

    return sgx_status_t(ret_val);
}
