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

// Note: Code below taken from SGX SDK.

#include <stdlib.h>
#include <string.h>

#include "stdio.h"
#include "util.h"

#include "pfs_debug.h"

//#include "sgx_proxy_memory.h"
#include "sgx_proxy_sdk_tlibc.h"

//#include "sgx_proxy_tseal.h"
//#include "sgx_proxy_misc.h"
//#include "sgx_proxy_trts_inst.h"
//#include "sgx_proxy_utils.h"

#include "sgx_tseal.h"
#include "sgx_utils.h"
#include "trts_inst.h"

// Note: sgx_trts.h has sgx_read_rand defn.
#include "sgx_proxy_rand.h"
//#include "sgx_trts.h"

// Macros below from tseal_migration_attr.h
/* Set the bits which have no security implications to 0 for sealed data
 * migration */
/* Bits which have no security implications in attributes.flags:
 *    Reserved bit[55:6]  - 0xFFFFFFFFFFFFC0ULL
 *    SGX_FLAGS_MODE64BIT
 *    SGX_FLAGS_PROVISION_KEY
 *    SGX_FLAGS_EINITTOKEN_KEY */
#define FLAGS_NON_SECURITY_BITS \
    (0xFFFFFFFFFFFFC0ULL | SGX_FLAGS_MODE64BIT | SGX_FLAGS_PROVISION_KEY | SGX_FLAGS_EINITTOKEN_KEY)
#define TSEAL_DEFAULT_FLAGSMASK (~FLAGS_NON_SECURITY_BITS)
#define MISC_NON_SECURITY_BITS 0x0FFFFFFF /* bit[27:0]: have no security implications */
#define TSEAL_DEFAULT_MISCMASK (~MISC_NON_SECURITY_BITS)

// Below code from SGX SDK lib, path: linux-sgx-sgx_1.9/sdk/tseal

#ifndef UINT32_MAX
#define UINT32_MAX 0xffffffffU
#endif

uint32_t sgx_calc_sealed_data_size(const uint32_t add_mac_txt_size,
                                   const uint32_t txt_encrypt_size) {
    if (add_mac_txt_size > UINT32_MAX - txt_encrypt_size)
        return UINT32_MAX;
    uint32_t payload_size = add_mac_txt_size + txt_encrypt_size;  // Calculate the payload size

    if (payload_size > UINT32_MAX - sizeof(sgx_sealed_data_t))
        return UINT32_MAX;
    return (uint32_t)(sizeof(sgx_sealed_data_t) + payload_size);
}

uint32_t sgx_get_add_mac_txt_len(const sgx_sealed_data_t* p_sealed_data) {
    if (p_sealed_data == NULL)
        return UINT32_MAX;

    uint32_t data_size = p_sealed_data->aes_data.payload_size - p_sealed_data->plain_text_offset;
    if (data_size > p_sealed_data->aes_data.payload_size)
        return UINT32_MAX;
    return data_size;
}

uint32_t sgx_get_encrypt_txt_len(const sgx_sealed_data_t* p_sealed_data) {
    return ((p_sealed_data == NULL) ? UINT32_MAX : p_sealed_data->plain_text_offset);
}

// sgx_seal_data_iv
//
// Parameters:
//      additional_MACtext_length - [IN] length of the plaintext data stream in
//      bytes
//      p_additional_MACtext - [IN] pointer to the plaintext data stream to be
//      GCM protected
//      text2encrypt_length - [IN] length of the data stream to encrypt in bytes
//      p_text2encrypt - [IN] pointer to data stream to encrypt
//      p_payload_iv - [IN] Pointer to Initialization Vector to be used during
//      AES GCM encryption
//      p_key_request - [IN] Pointer to the key request structure to be utilized
//      to obtain the SEAL key
//      p_sealed_data - [OUT] pointer to the sealed data structure containing
//      protected data
//
// Return Value:
//      sgx_status_t - SGX Error code
sgx_status_t sgx_seal_data_iv(const uint32_t additional_MACtext_length,
                              const uint8_t* p_additional_MACtext,
                              const uint32_t text2encrypt_length, const uint8_t* p_text2encrypt,
                              const uint8_t* p_payload_iv, const sgx_key_request_t* p_key_request,
                              sgx_sealed_data_t* p_sealed_data) {
    sgx_status_t err = SGX_ERROR_UNEXPECTED;

    // Parameter checking performed in sgx_seal_data

    // Generate the seal key
    // The random p_key_request->key_id guarantees the generated seal key is
    // random
    sgx_key_128bit_t seal_key;
    memset(&seal_key, 0, sizeof(sgx_key_128bit_t));
    err = sgx_get_key(p_key_request, &seal_key);
    if (err != SGX_SUCCESS) {
        // Clear temp state
        /*memset_s(&seal_key, sizeof(sgx_key_128bit_t), 0,
                 sizeof(sgx_key_128bit_t));*/
        memset(&seal_key, 0, sizeof(sgx_key_128bit_t));

        if (err != SGX_ERROR_OUT_OF_MEMORY)
            err = SGX_ERROR_UNEXPECTED;
        return err;
    }

    // Encrypt the content with the random seal key and the static payload_iv
    err = sgx_rijndael128GCM_encrypt(
        &seal_key, p_text2encrypt, text2encrypt_length,
        /*reinterpret_cast<uint8_t *>*/ (uint8_t*)(&(p_sealed_data->aes_data.payload)),
        p_payload_iv, SGX_SEAL_IV_SIZE, p_additional_MACtext, additional_MACtext_length,
        &(p_sealed_data->aes_data.payload_tag));

    if (err == SGX_SUCCESS) {
        // Copy additional MAC text
        uint8_t* p_aad = NULL;
        if (additional_MACtext_length > 0) {
            p_aad = &(p_sealed_data->aes_data.payload[text2encrypt_length]);
            memcpy(p_aad, p_additional_MACtext, additional_MACtext_length);
        }

        // populate the plain_text_offset, payload_size in the data_blob
        p_sealed_data->plain_text_offset     = text2encrypt_length;
        p_sealed_data->aes_data.payload_size = additional_MACtext_length + text2encrypt_length;
    }
    // Clear temp state
    // memset_s(&seal_key, sizeof(sgx_key_128bit_t), 0, sizeof(sgx_key_128bit_t));
    memset(&seal_key, 0, sizeof(sgx_key_128bit_t));

    return err;
}

// sgx_unseal_data_helper
//
// Parameters:
//      p_sealed_data - [IN] pointer to the sealed data structure containing
//      protected data
//      p_additional_MACtext - [OUT] pointer to the plaintext data stream which
//      was GCM protected
//      additional_MACtext_length - [IN] length of the plaintext data stream in
//      bytes
//      p_decrypted_text - [OUT] pointer to decrypted data stream
//      decrypted_text_length - [IN] length of the decrypted data stream to
//      encrypt in bytes
//
// Return Value:
//      sgx_status_t - SGX Error code
sgx_status_t sgx_unseal_data_helper(const sgx_sealed_data_t* p_sealed_data,
                                    uint8_t* p_additional_MACtext,
                                    uint32_t additional_MACtext_length, uint8_t* p_decrypted_text,
                                    uint32_t decrypted_text_length) {
    sgx_status_t err = SGX_ERROR_UNEXPECTED;
    sgx_key_128bit_t seal_key;
    memset(&seal_key, 0, sizeof(sgx_key_128bit_t));
    uint8_t payload_iv[SGX_SEAL_IV_SIZE];
    memset(&payload_iv, 0, SGX_SEAL_IV_SIZE);

    if (decrypted_text_length > 0)
        memset(p_decrypted_text, 0, decrypted_text_length);

    if (additional_MACtext_length > 0)
        memset(p_additional_MACtext, 0, additional_MACtext_length);

    // Get the seal key
    err = sgx_get_key(&p_sealed_data->key_request, &seal_key);
    if (err != SGX_SUCCESS) {
        // Clear temp state
        // memset_s(&seal_key, sizeof(sgx_key_128bit_t), 0, sizeof(sgx_key_128bit_t));
        memset(&seal_key, 0, sizeof(sgx_key_128bit_t));

        // Provide only error codes that the calling code could act on
        if ((err == SGX_ERROR_INVALID_CPUSVN) || (err == SGX_ERROR_INVALID_ISVSVN) ||
            (err == SGX_ERROR_OUT_OF_MEMORY))
            return err;
        // Return error indicating the blob is corrupted
        return SGX_ERROR_MAC_MISMATCH;
    }

    //
    // code that calls sgx_unseal_data commonly does some sanity checks
    // related to plain_text_offset.  We add fence here since we don't
    // know what crypto code does and if plain_text_offset-related
    // checks mispredict the crypto code could operate on unintended data
    //
    // sgx_lfence();

    err = sgx_rijndael128GCM_decrypt(
        &seal_key, /*const_cast<uint8_t *>*/ (p_sealed_data->aes_data.payload),
        decrypted_text_length, p_decrypted_text, &payload_iv[0], SGX_SEAL_IV_SIZE,
        /*const_cast<uint8_t *>*/ (&(p_sealed_data->aes_data.payload[decrypted_text_length])),
        additional_MACtext_length,
        /*const_cast<sgx_aes_gcm_128bit_tag_t *>*/ (&p_sealed_data->aes_data.payload_tag));

    if (err != SGX_SUCCESS) {
        // Clear temp state
        // memset_s(&seal_key, sizeof(sgx_key_128bit_t), 0, sizeof(sgx_key_128bit_t));
        memset(&seal_key, 0, sizeof(sgx_key_128bit_t));
        return err;
    }

    if (additional_MACtext_length > 0) {
        memcpy(p_additional_MACtext, &(p_sealed_data->aes_data.payload[decrypted_text_length]),
               additional_MACtext_length);
    }
    // Clear temp state
    // memset_s(&seal_key, sizeof(sgx_key_128bit_t), 0, sizeof(sgx_key_128bit_t));
    memset(&seal_key, 0, sizeof(sgx_key_128bit_t));

    return SGX_SUCCESS;
}

sgx_status_t sgx_seal_data_ex(const uint16_t key_policy, const sgx_attributes_t attribute_mask,
                              const sgx_misc_select_t misc_mask,
                              const uint32_t additional_MACtext_length,
                              const uint8_t* p_additional_MACtext,
                              const uint32_t text2encrypt_length, const uint8_t* p_text2encrypt,
                              const uint32_t sealed_data_size, sgx_sealed_data_t* p_sealed_data) {
    sgx_status_t err = SGX_ERROR_UNEXPECTED;
    sgx_report_t report;
    sgx_key_id_t keyID;
    sgx_key_request_t tmp_key_request;
    uint8_t payload_iv[SGX_SEAL_IV_SIZE];
    memset(&payload_iv, 0, sizeof(payload_iv));

    uint32_t sealedDataSize =
        sgx_calc_sealed_data_size(additional_MACtext_length, text2encrypt_length);
    // Check for overflow
    if (sealedDataSize == UINT32_MAX) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    //
    // Check parameters
    //
    // check key_request->key_policy reserved bits are not set and one of policy
    // bits are set
    if ((key_policy & ~(SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER)) ||
        ((key_policy & (SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER)) == 0)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (!(attribute_mask.flags & SGX_FLAGS_INITTED) || !(attribute_mask.flags & SGX_FLAGS_DEBUG)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if ((additional_MACtext_length > 0) && (p_additional_MACtext == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if ((text2encrypt_length == 0) ||
        (p_text2encrypt ==
         NULL) /*|| (!sgx_is_within_enclave(p_text2encrypt,text2encrypt_length))*/) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    // Ensure sealed data blob is within an enclave during the sealing process
    if ((p_sealed_data == NULL) /*|| (!sgx_is_within_enclave(p_sealed_data,sealed_data_size))*/) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    // Ensure aad data does not cross enclave boundary
    if ((additional_MACtext_length > 0) /*&&
        (!(sgx_is_within_enclave(p_additional_MACtext,additional_MACtext_length)
        || sgx_is_outside_enclave(p_additional_MACtext, additional_MACtext_length))*/) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (sealedDataSize != sealed_data_size) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    memset(&report, 0, sizeof(sgx_report_t));
    memset(p_sealed_data, 0, sealedDataSize);
    memset(&keyID, 0, sizeof(sgx_key_id_t));
    memset(&tmp_key_request, 0, sizeof(sgx_key_request_t));

    // Get the report to obtain isv_svn and cpu_svn
    err = sgx_create_report(NULL, NULL, &report);
    if (err != SGX_SUCCESS) {
        goto clear_return;
    }

    // Get a random number to populate the key_id of the key_request
    err = sgx_read_rand(/*reinterpret_cast<uint8_t *>*/ (uint8_t*)(&keyID), sizeof(sgx_key_id_t));
    if (err != SGX_SUCCESS) {
        goto clear_return;
    }

    memcpy(&(tmp_key_request.cpu_svn), &(report.body.cpu_svn), sizeof(sgx_cpu_svn_t));
    memcpy(&(tmp_key_request.isv_svn), &(report.body.isv_svn), sizeof(sgx_isv_svn_t));
    tmp_key_request.key_name             = SGX_KEYSELECT_SEAL;
    tmp_key_request.key_policy           = key_policy;
    tmp_key_request.attribute_mask.flags = attribute_mask.flags;
    tmp_key_request.attribute_mask.xfrm  = attribute_mask.xfrm;
    memcpy(&(tmp_key_request.key_id), &keyID, sizeof(sgx_key_id_t));
    tmp_key_request.misc_mask = misc_mask;

    err = sgx_seal_data_iv(additional_MACtext_length, p_additional_MACtext, text2encrypt_length,
                           p_text2encrypt, payload_iv, &tmp_key_request, p_sealed_data);

    if (err == SGX_SUCCESS) {
        // Copy data from the temporary key request buffer to the sealed data
        // blob
        memcpy(&(p_sealed_data->key_request), &tmp_key_request, sizeof(sgx_key_request_t));
    }
clear_return:
    // Clear temp state
    // memset_s(&report, sizeof(sgx_report_t), 0, sizeof(sgx_report_t));
    // memset_s(&keyID, sizeof(sgx_key_id_t), 0, sizeof(sgx_key_id_t));
    memset(&report, 0, sizeof(sgx_report_t));
    memset(&keyID, 0, sizeof(sgx_key_id_t));

    return err;
}

sgx_status_t sgx_seal_data(const uint32_t additional_MACtext_length,
                           const uint8_t* p_additional_MACtext, const uint32_t text2encrypt_length,
                           const uint8_t* p_text2encrypt, const uint32_t sealed_data_size,
                           sgx_sealed_data_t* p_sealed_data) {
    sgx_status_t err = SGX_ERROR_UNEXPECTED;
    sgx_attributes_t attribute_mask;
    attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
    attribute_mask.xfrm  = 0x0;

    err = sgx_seal_data_ex(SGX_KEYPOLICY_MRSIGNER, attribute_mask, TSEAL_DEFAULT_MISCMASK,
                           additional_MACtext_length, p_additional_MACtext, text2encrypt_length,
                           p_text2encrypt, sealed_data_size, p_sealed_data);
    return err;
}

sgx_status_t sgx_unseal_data(const sgx_sealed_data_t* p_sealed_data, uint8_t* p_additional_MACtext,
                             uint32_t* p_additional_MACtext_length, uint8_t* p_decrypted_text,
                             uint32_t* p_decrypted_text_length) {
    sgx_status_t err = SGX_ERROR_UNEXPECTED;
    // Ensure the the sgx_sealed_data_t members are all inside enclave before
    // using them.
    if ((p_sealed_data ==
         NULL) /*|| (!sgx_is_within_enclave(p_sealed_data,sizeof(sgx_sealed_data_t))*/) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    uint32_t encrypt_text_length = sgx_get_encrypt_txt_len(p_sealed_data);
    if (encrypt_text_length == UINT32_MAX) {
        return SGX_ERROR_MAC_MISMATCH;  // Return error indicating the blob is
                                        // corrupted
    }
    uint32_t add_text_length = sgx_get_add_mac_txt_len(p_sealed_data);
    if (add_text_length == UINT32_MAX) {
        return SGX_ERROR_MAC_MISMATCH;  // Return error indicating the blob is
                                        // corrupted
    }
    uint32_t sealedDataSize = sgx_calc_sealed_data_size(add_text_length, encrypt_text_length);
    if (sealedDataSize == UINT32_MAX) {
        return SGX_ERROR_MAC_MISMATCH;  // Return error indicating the blob is
                                        // corrupted
    }

    //
    // Check parameters
    //
    /* Ensure sealed data blob is within an enclave during the sealing process
    if (!sgx_is_within_enclave(p_sealed_data,sealedDataSize))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    */

    if ((add_text_length > 0) &&
        ((p_additional_MACtext == NULL) || (p_additional_MACtext_length == NULL))) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if ((encrypt_text_length < 1) || (p_decrypted_text == NULL) ||
        (p_decrypted_text_length == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    /*
    if (!sgx_is_within_enclave(p_decrypted_text,encrypt_text_length))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if
    (!sgx_is_within_enclave(p_decrypted_text_length,sizeof(p_decrypted_text_length)))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    */

    // Ensure aad data does not cross enclave boundary
    if ((add_text_length > 0) /*&&
        (!(sgx_is_within_enclave(p_additional_MACtext,add_text_length)
        || sgx_is_outside_enclave(p_additional_MACtext, add_text_length)))*/) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if ((*p_decrypted_text_length) < encrypt_text_length) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    uint32_t additional_MACtext_length =
        (NULL != p_additional_MACtext_length) ? *p_additional_MACtext_length : 0;
    if (additional_MACtext_length < add_text_length) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    err = sgx_unseal_data_helper(p_sealed_data, p_additional_MACtext, add_text_length,
                                 p_decrypted_text, encrypt_text_length);
    if (err == SGX_SUCCESS) {
        *p_decrypted_text_length = encrypt_text_length;
        if (p_additional_MACtext_length != NULL)
            *p_additional_MACtext_length = add_text_length;
    }
    return err;
}
