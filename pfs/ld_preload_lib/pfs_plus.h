/*
 * License: BSD 3-Clause "New" or "Revised" License
 *
 * Other web pages for this license
 * http://www.opensource.org/licenses/BSD-3-Clause
 *
 * Copyright (C) 2019 Intel Corporation. All rights reserved.
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

#ifndef _PFS_PLUS_H_
#define _PFS_PLUS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/types.h>
#include <unistd.h>

#include <errno.h>

#include "sgx_key.h"
#include "sgx_report.h"
#include "sgx_tcrypto.h"

#include "fileops_typedefs.h"

#define PFS_PLUS_ENABLED

#define MBEDTLS_CMAC_USED

#define SIXTEEN_BYTES (16)
#define THIRTY_TWO_BYTES (32)

#define VCK_LEN (SIXTEEN_BYTES)
#define VNK_LEN (THIRTY_TWO_BYTES)
#define VMK_LEN (SIXTEEN_BYTES)

#define MAX_LABEL_LEN 64

#define PFS_MOUNT_POINT_ENV "PFS_MOUNT_POINT"
#define PFS_USE_CUSTOM_KEY_ENV "PFS_USE_CUSTOM_KEY"
#define YES_STRING "yes"
#define NO_STRING "no"
#define LENGTH_OF_CUSTOM_KEY (16)
// Note: Expected to be present at the CWD of the graphene application.
#define SEALED_BLOB "sealed_custom_key"

#define PFS_VOL_MD ".protectfs_vol_md.bin"

// length based on base64-encoded max length of 246, and accounting for null
// string.
#define PFS_FILENAME_MAX_LENGTH ((PFS_ENCODED_FILENAME_MAX_LENGTH * 3) / 4 - 4)
#define PFS_ENCODED_FILENAME_MAX_LENGTH (246)

#define DOT_STRING "."
#define FWD_SLASH_STRING "/"

//#define FILENAME_LENGTH_FLEXIBLE_PADDING

#ifdef FILENAME_LENGTH_FLEXIBLE_PADDING

#define FILENAME_LENGTH_ALIGN (16)

#define PADDED_LENGTH(orig_len, align_to) \
    (orig_len = (((orig_len + align_to) / align_to) * align_to))

#endif

#define DERIVE_VCK_KEY_ID(key_buf) DERIVE_KEY_ID(key_buf, 0x1)
#define DERIVE_VNK_KEY_ID(key_buf) DERIVE_KEY_ID(key_buf, 0x2)
#define DERIVE_VMK_KEY_ID(key_buf) DERIVE_KEY_ID(key_buf, 0x3)

#define DERIVE_KEY_ID(key_buf, key_index) key_buf[0] = (key_buf[0] & (~3)) | key_index;

typedef uint8_t vol_id_t[VMK_LEN];

typedef uint8_t vck_t[VCK_LEN];
typedef uint8_t vnk_t[VNK_LEN];
typedef uint8_t vmk_t[VMK_LEN];

typedef uint8_t key_id_t[THIRTY_TWO_BYTES];
typedef uint8_t key_gen_t[SIXTEEN_BYTES];

typedef unsigned char mac_output_t[SIXTEEN_BYTES];
typedef unsigned char hash_output_t[THIRTY_TWO_BYTES];

typedef unsigned char tweak_value_t[SIXTEEN_BYTES];

enum pfs_status {
    PFS_SUCCESS = 0,
    PFS_INVALID_PARAM,
    PFS_OUT_OF_MEMORY,
    PFS_SGX_ERROR,
    PFS_SGX_CRYPTO_ERROR,
    PFS_CRYPTO_ERROR,
    PFS_KEY_GEN_ERROR,
    PFS_MAC_COMPUTE_ERROR,
    PFS_VOL_MD_FILE_ABSENT,
    PFS_VOL_MD_CREATE_FOPEN_ERROR,
    PFS_VOL_MD_CREATE_WRITE_ERROR,
    PFS_VOL_MD_PROCESS_FOPEN_ERROR,
    PFS_VOL_MD_PROCESS_READ_ERROR,
    PFS_VOL_MD_PROCESS_KEY_TYPE_ERROR,
    PFS_MAC_VERIFY_ERROR,
    PFS_FILENAME_TOO_LONG,
    PFS_VOL_MD_UNINITIALIZED,
    PFS_FILENAME_ENCRYPT_ERROR,
    PFS_FILENAME_ENCODE_ERROR,
    PFS_PADDED_FILENAME_LEN_INVALID,
    PFS_ENCODED_FILENAME_TOO_LONG,
    PFS_FILENAME_DECRYPT_ERROR,
    PFS_FILENAME_DECODE_ERROR,
    PFS_FILENAME_DECODED_LENGTH_INVALID,
    PFS_INVALID_FILENAME_PARAM,
    PFS_FILENAME_PATH_NOT_ABSOLUTE,
    PFS_MOUNT_POINT_NOT_SET,
    PFS_MOUNT_POINT_NOT_SUBSET_OF_DIR_PATH,
    PFS_REALPATH_API_RETURNED_NULL,
    PFS_FILEPATH_FILENAME_TOO_LONG,
    PFS_DIRPATH_TOO_LONG,
    PFS_DIRENTRY_STRUCT_DNAME_BUF_NOT_STATIC,
    PFS_DECRYPTED_NAME_TOO_LONG,
    PFS_DECRYPTED_NAME_NOT_ZERO_PADDED,
    PFS_FILENAME_NOT_ASCII_STRING,
    PFS_OTHER_ERROR,

};

enum key_type { SEAL_KEY = 1, CUSTOM_KEY };

enum volume_key_type {
    CUSTOM_VCK = 1,
    CUSTOM_VNK,
    CUSTOM_VMK,
    SEAL_VCK,
    SEAL_VNK,
    SEAL_VMK,
};

// Note: struct modified/re-used from SGX SDK's file_crypo.cpp
typedef struct {
    uint32_t index;
    char label[MAX_LABEL_LEN];
    uint64_t volume_key_type;  // context 1
    key_id_t nonce32;          // context 2
    uint32_t output_len;       // in bits
} kdf_source_t;

/* Note: Alignment to 1 byte, to ensure size of (volume meta data)
is same across compiler/platform */
#pragma pack(push, 1)
typedef struct _seal_key_params_t {
    sgx_cpu_svn_t cpu_svn;       /* (  0) Security Version of the CPU */
    sgx_measurement_t mr_signer; /* (128) The value of the enclave's SIGNER measurement */
    sgx_isv_svn_t isv_svn;       /* (258) Security Version of the Enclave */
} seal_key_params_t;

struct prot_data {
    uint16_t key_type;

    key_id_t key_id;

    union {
        seal_key_params_t seal_key;
    } params;
};

typedef struct vol_md {
    struct prot_data prot_data;
    vol_id_t vol_id;
} vol_md_t;

typedef struct vol_keys {
    vck_t vck;
    vnk_t vnk;
    vmk_t vmk;

    key_id_t key_id_vck;
    key_id_t key_id_vnk;
    key_id_t key_id_vmk;
} vol_keys_t;
#pragma pack(pop)

int volume_metadata_setup(char* mnt_path);

int pfs_encrypt_filename(const char* filename, char** encrypted_filename);

int pfs_decrypt_filename(char* dir_path, const char* filename, char** decrypted_filename);

int get_dirname_basename(const char* filename, char** dirc, char** basec, char** dir_path,
                         char** basen);
int check_dir_path_prefix(char* dir_path, bool* path_to_protected_file);

#endif  //_PFS_PLUS_H_
