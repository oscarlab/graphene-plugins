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

#include "pfs_plus.h"

#include "mbedtls/aes.h"
#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h" /* SHA-256 only */

#include "sgx_utils.h"
#include "tseal_migration_attr.h"

#include "base64.h"

#include <stdbool.h>

// Note: sgx_trts.h has sgx_read_rand defn.
#include "sgx_proxy_rand.h"
//#include "sgx_trts.h"

#include <libgen.h>  //mandatory for dirname/basename functions.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <limits.h>
#include <stdlib.h>

#include "protfs_debug.h"

// Globals
vol_md_t vol_md_glb;
vol_keys_t vol_keys_glb;

bool volume_metadata_setup_done = 0;
bool vol_md_init                = 0;
bool vol_md_init_failed         = 0;

extern bool checked_use_of_custom_key;
extern bool using_custom_key;
extern sgx_key_128bit_t sgx_key_glb;

// static declarations
static int vol_md_file_helper(char* mnt_path, char** file_path);
static int compute_mac(uint8_t* buf, size_t buf_len, uint8_t* key, size_t key_len,
                       mac_output_t* mac_output);

static int verify_mac(vol_md_t* vol_md, vol_keys_t* vol_key) {
    int ret = 0;
    vol_id_t computed_vol_id;

    if (!vol_md || !vol_key) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    DBG_PRINT();

    // Compute mac over prot_data
    ret = compute_mac((uint8_t*)&vol_md->prot_data, sizeof(struct prot_data), vol_key->vmk,
                      sizeof(vol_key->vmk), &computed_vol_id);

    if (ret != 0) {
        ret = PFS_MAC_COMPUTE_ERROR;
        goto exit;
    }

    if (memcmp(vol_md->vol_id, &computed_vol_id, sizeof(vol_id_t)) == 0)
        ret = PFS_SUCCESS;
    else
        ret = PFS_MAC_VERIFY_ERROR;

exit:

    return ret;
}

static int derive_volume_keys_from_seal_key(vol_md_t* vol_md, key_id_t* key_id,
                                            key_gen_t* key_gen) {
    int ret = 0;

    sgx_status_t status = SGX_SUCCESS;
    // derive a random key from the enclave sealing key
    sgx_key_request_t key_request;

    if (!vol_md || !key_id || !key_gen) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    memset(&key_request, 0, sizeof(sgx_key_request_t));

    key_request.key_name   = SGX_KEYSELECT_SEAL;
    key_request.key_policy = SGX_KEYPOLICY_MRSIGNER;

    memcpy(&key_request.cpu_svn, &(vol_md->prot_data.params.seal_key.cpu_svn),
           sizeof(sgx_cpu_svn_t));
    memcpy(&key_request.isv_svn, &(vol_md->prot_data.params.seal_key.isv_svn),
           sizeof(sgx_isv_svn_t));

#ifdef PROTFS_DEBUG
    DBG_PRINT("");
    PRINT_BUF("CPU_SVN", (uint8_t*)&key_request.cpu_svn, sizeof(sgx_cpu_svn_t));
    PRINT_BUF("ISV_SVN", (uint8_t*)&key_request.isv_svn, sizeof(sgx_isv_svn_t));
#endif

    key_request.attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
    key_request.attribute_mask.xfrm  = 0x0;
    key_request.misc_mask            = TSEAL_DEFAULT_MISCMASK;

    memcpy((void*)&key_request.key_id, key_id, sizeof(key_id_t));

    status = sgx_get_key(&key_request, key_gen);

    if (status != SGX_SUCCESS) {
        ret = PFS_SGX_ERROR;
        goto exit;
    }

exit:

    return ret;
}

static int generate_seal_volume_keys(vol_md_t* vol_md, vol_keys_t* vol_keys) {
    int ret = 0;
    uint8_t* vnk_ptr;

    if (!vol_md || !vol_keys) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    DBG_PRINT();

    /*Note: vnk is a 32-byte key, since it is used for AES-XTS.
     * but sgx_get_key..only returns 16-byte key..
     * So generating 32 bytes..by calling derive twice..and using
     * key_id for vck..since it is anyway NOT used in the case of sealing
     * keys(generated/managed directly
     * by protect-fs vanilla code).
     */
    ret = derive_volume_keys_from_seal_key(
        vol_md,
        &vol_keys->key_id_vck,  // key_id_vck is used to generate first 16 bytes.
        (sgx_key_128bit_t*)&vol_keys->vnk);

    if (ret != 0) {
        ret = PFS_KEY_GEN_ERROR;
        goto exit;
    }

    vnk_ptr = (uint8_t*)&vol_keys->vnk;

    ret = derive_volume_keys_from_seal_key(
        vol_md,
        &vol_keys->key_id_vnk,  // key_id_vnk is used to generate remaining 16 bytes.
        (sgx_key_128bit_t*)(vnk_ptr + SIXTEEN_BYTES));

    if (ret != 0) {
        ret = PFS_KEY_GEN_ERROR;
        goto exit;
    }

    PRINT_BUF("VNK=", (uint8_t*)&vol_keys->vnk, sizeof(vnk_t));

    ret = derive_volume_keys_from_seal_key(vol_md, &vol_keys->key_id_vmk, &vol_keys->vmk);

    if (ret != 0) {
        ret = PFS_KEY_GEN_ERROR;
        goto exit;
    }

    PRINT_BUF("VMK=", (uint8_t*)&vol_keys->vmk, sizeof(vmk_t));

exit:

    return ret;
}

static int derive_volume_keys_from_custom_key(sgx_key_128bit_t* sgx_key, key_id_t* key_id,
                                              const char* label, enum volume_key_type vk_type,
                                              key_gen_t* key_gen) {
    int ret = 0;
    // int key_len = 0;

    kdf_source_t buf    = {0, "", 0, "", 0};
    sgx_status_t status = SGX_SUCCESS;

    uint32_t len           = 0;
    uint32_t iteration_cnt = 0;

    key_gen_t* key_gen_ptr = NULL;

    if (!key_id || !sgx_key || !key_gen || !label) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    if (!(vk_type == CUSTOM_VCK || vk_type == CUSTOM_VMK || vk_type == CUSTOM_VNK)) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    len = (uint32_t)strnlen(label, MAX_LABEL_LEN + 1);

    if (len > MAX_LABEL_LEN) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    key_gen_ptr = key_gen;

// Note: sources below modified/re-used from SGX SDK's file_crypo.cpp

// index
// SP800-108:
// i � A counter, a binary string of length r that is an input to each iteration
// of a PRF in counter mode [...].

repeat:

    buf.index = 0x01 + iteration_cnt;

    // label
    // SP800-108:
    // Label � A string that identifies the purpose for the derived keying
    // material, which is encoded as a binary string.
    //         The encoding method for the Label is defined in a larger context,
    //         for example, in the protocol that uses a KDF.
    strncpy(buf.label, label, len);

    // context and nonce
    // SP800-108:
    // Context � A binary string containing the information related to the
    // derived keying material.
    //           It may include identities of parties who are deriving and / or
    //           using the derived keying material and,
    //           optionally, a nonce known by the parties who derive the keys.
    buf.volume_key_type = vk_type;

    // copy key_id(already generated random number) to buf
    memcpy((void*)&(buf.nonce32), key_id, sizeof(key_id_t));

    // length of output (128 bits)
    buf.output_len = 0x80;

    if (vk_type == CUSTOM_VNK)
        buf.output_len = 0x100;

    status = sgx_rijndael128_cmac_msg(sgx_key, (const uint8_t*)&buf, sizeof(kdf_source_t),
                                      (key_gen_t*)key_gen_ptr);

    DBG_PRINT("\nafter sgx_cmac_msg, status=%d\n", (int)status);

    if (status != SGX_SUCCESS) {
        ret = PFS_SGX_CRYPTO_ERROR;
        goto exit;
    }

    memset(&buf, 0, sizeof(kdf_source_t));

    iteration_cnt++;

    if (iteration_cnt == 1 && vk_type == CUSTOM_VNK) {
        /*this will move the ptr by 16 bytes(since key_gen_t is 16 bytes)
         * vnk length is 32 bytes
         */
        key_gen_ptr = key_gen_ptr + 1;
        goto repeat;
    }

    if (vk_type != CUSTOM_VNK) {
        PRINT_BUF("Key_gen=", (uint8_t*)key_gen, sizeof(key_gen_t));
    } else {
        PRINT_BUF("Key_gen=", (uint8_t*)key_gen, sizeof(key_gen_t) * 2);
    }

exit:

    return ret;
}

static int generate_custom_volume_keys(vol_md_t* vol_md, sgx_key_128bit_t* sgx_key,
                                       vol_keys_t* vol_keys) {
    int ret = 0;

    if (!sgx_key || !vol_md || !vol_keys) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    DBG_PRINT();

    ret = derive_volume_keys_from_custom_key(sgx_key, &vol_keys->key_id_vck,
                                             "SGX-PROTECTED-FS+-VOLUME-CONTENT-KEY", CUSTOM_VCK,
                                             &vol_keys->vck);

    if (ret != 0) {
        ret = PFS_KEY_GEN_ERROR;
        goto exit;
    }

    ret = derive_volume_keys_from_custom_key(sgx_key, &vol_keys->key_id_vnk,
                                             "SGX-PROTECTED-FS+-VOLUME-NAME-KEY", CUSTOM_VNK,
                                             (key_gen_t*)&vol_keys->vnk);

    if (ret != 0) {
        ret = PFS_KEY_GEN_ERROR;
        goto exit;
    }

    ret = derive_volume_keys_from_custom_key(sgx_key, &vol_keys->key_id_vmk,
                                             "SGX-PROTECTED-FS+-VOLUME-METADATA-KEY", CUSTOM_VMK,
                                             &vol_keys->vmk);

    if (ret != 0) {
        ret = PFS_KEY_GEN_ERROR;
        goto exit;
    }

exit:

    return ret;
}

#define DERIVE_VCK_KEY_ID(key_buf) DERIVE_KEY_ID(key_buf, 0x1)
#define DERIVE_VNK_KEY_ID(key_buf) DERIVE_KEY_ID(key_buf, 0x2)
#define DERIVE_VMK_KEY_ID(key_buf) DERIVE_KEY_ID(key_buf, 0x3)

#define DERIVE_KEY_ID(key_buf, key_index) key_buf[0] = (key_buf[0] & (~3)) | key_index;

static int generate_keyids(vol_md_t* vol_md, vol_keys_t* vol_keys) {
    int ret = 0;

    if (!vol_md || !vol_keys) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    PRINT_BUF("\n generate_keyids: key_id=", (unsigned char*)vol_md->prot_data.key_id,
              sizeof(key_id_t));

    memcpy(&vol_keys->key_id_vck, &vol_md->prot_data.key_id, sizeof(key_id_t));
    memcpy(&vol_keys->key_id_vnk, &vol_md->prot_data.key_id, sizeof(key_id_t));
    memcpy(&vol_keys->key_id_vmk, &vol_md->prot_data.key_id, sizeof(key_id_t));

    DERIVE_VCK_KEY_ID(vol_keys->key_id_vck);
    DERIVE_VNK_KEY_ID(vol_keys->key_id_vnk);
    DERIVE_VMK_KEY_ID(vol_keys->key_id_vmk);

    PRINT_BUF("\n vck key_id=", (unsigned char*)vol_keys->key_id_vck, sizeof(key_id_t));
    PRINT_BUF("\n vnk key_id=", (unsigned char*)vol_keys->key_id_vnk, sizeof(key_id_t));
    PRINT_BUF("\n vmk key_id=", (unsigned char*)vol_keys->key_id_vmk, sizeof(key_id_t));

exit:

    return ret;
}

static int generate_keys(vol_md_t* vol_md, vol_keys_t* vol_keys) {
    int ret = 0;

    if (!vol_md || !vol_keys) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    /* check_use_of_custom_key, does exist in create_vol_md and process_vol_md.
     *  redoing check, to be safe, and future flexibility.
     */
    if (checked_use_of_custom_key == 0) {
        check_use_of_custom_key();
        checked_use_of_custom_key = 1;
    }

    DBG_PRINT("checked_use_of_custom_key=%d, use_custom=%d\n", checked_use_of_custom_key,
              using_custom_key);

    if (using_custom_key == 1 && (vol_md->prot_data.key_type != CUSTOM_KEY)) {
        ret = PFS_OTHER_ERROR;
        goto exit;
    }

    if (generate_keyids(vol_md, vol_keys)) {
        ret = PFS_OTHER_ERROR;
        goto exit;
    }

    if (vol_md->prot_data.key_type == CUSTOM_KEY) {
        ret = generate_custom_volume_keys(vol_md, &sgx_key_glb, vol_keys);
    } else {
        ret = generate_seal_volume_keys(vol_md, vol_keys);
    }

exit:

    return ret;
}

int create_vol_md(char* mnt_path) {
    int ret = PFS_SUCCESS;
    sgx_status_t status;

    sgx_report_t* report = NULL;
    FILE* fp             = NULL;
    char* file_path      = NULL;
    size_t len_written   = 0;

    if (!mnt_path) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    if (checked_use_of_custom_key == 0) {
        check_use_of_custom_key();
        checked_use_of_custom_key = 1;
    }

    DBG_PRINT("checked_use_of_custom_key=%d, use_custom=%d\n", checked_use_of_custom_key,
              using_custom_key);

    ret = vol_md_file_helper(mnt_path, &file_path);

    if (ret != 0) {
        goto exit;
    }

    DBG_PRINT("file_path->%s\n", file_path);

    fp = fopen_fn_glb(file_path, "w");

    if (!fp) {
        DBG_PRINT("Failed to create the vol meta-data blob\n");
        perror("create_vol_md-Failed to create the vol meta-data blob\n");
        ret = PFS_VOL_MD_CREATE_FOPEN_ERROR;
        goto exit;
    }

    memset(&vol_md_glb, 0, sizeof(vol_md_t));

    if (using_custom_key)
        vol_md_glb.prot_data.key_type = CUSTOM_KEY;
    else
        vol_md_glb.prot_data.key_type = SEAL_KEY;

    status = sgx_read_rand((unsigned char*)&vol_md_glb.prot_data.key_id, sizeof(key_id_t));

    if (status != SGX_SUCCESS) {
        ret = PFS_SGX_ERROR;
        goto exit;
    }

    if (vol_md_glb.prot_data.key_type == SEAL_KEY) {
        report = (sgx_report_t*)malloc(sizeof(sgx_report_t));

        if (!report) {
            ret = PFS_OUT_OF_MEMORY;
            goto exit;
        }

        status = sgx_create_report(NULL, NULL, report);

        if (status != SGX_SUCCESS) {
            ret = PFS_SGX_ERROR;
            goto exit;
        }

        memcpy(&vol_md_glb.prot_data.params.seal_key.cpu_svn, &report->body.cpu_svn,
               sizeof(sgx_cpu_svn_t));
        memcpy(&vol_md_glb.prot_data.params.seal_key.isv_svn, &report->body.isv_svn,
               sizeof(sgx_isv_svn_t));
        memcpy(&vol_md_glb.prot_data.params.seal_key.mr_signer, &report->body.mr_signer,
               sizeof(sgx_measurement_t));
    }

    // generate keys(VCK, VNK, VMK)
    ret = generate_keys(&vol_md_glb, &vol_keys_glb);

    if (ret != 0) {
        ret = PFS_KEY_GEN_ERROR;
        goto exit;
    }

    // Compute mac over prot_data
    ret = compute_mac((uint8_t*)&vol_md_glb.prot_data, sizeof(struct prot_data), vol_keys_glb.vmk,
                      sizeof(vol_keys_glb.vmk), &vol_md_glb.vol_id);

    if (ret != 0) {
        DBG_PRINT("mac compute error->%d\n", ret);
        ret = PFS_MAC_COMPUTE_ERROR;
        goto exit;
    }

    // len_written = fwrite_fn_glb((const void *)&vol_md_glb, sizeof(uint8_t),
    // sizeof(vol_md_t), fp);
    len_written = fwrite((const void*)&vol_md_glb, sizeof(uint8_t), sizeof(vol_md_t), fp);

    if (len_written != sizeof(vol_md_t)) {
        DBG_PRINT("Error, after fwrite, len_written = %lu, expected = %lu\n", len_written,
                  sizeof(vol_md_t));
        ret = PFS_VOL_MD_CREATE_WRITE_ERROR;
        goto exit;
    }

exit:

    if (file_path)
        free(file_path);

    if (report)
        free(report);

    if (fp) {
        fclose_fn_glb(fp);
    }

    return ret;
}

// Note: volume-metadata-file is a hidden file(.vol*) under PFS_MOUNT_POINT.
static int vol_md_file_helper(char* mnt_path, char** file_path) {
    int ret     = 0;
    int str_len = 0;

    if (!file_path)
        return PFS_INVALID_PARAM;

    // for extra / and NULL
    str_len = strlen(mnt_path) + 1 + strlen(PFS_VOL_MD) + 1;

    *file_path = (char*)calloc(str_len, 1);

    if (!(*file_path)) {
        ret = PFS_OUT_OF_MEMORY;
        goto exit;
    }

    strncpy(*file_path, mnt_path, strlen(mnt_path));
    *(*file_path + strlen(mnt_path)) = '/';
    strncpy((*file_path) + strlen(mnt_path) + 1, PFS_VOL_MD, strlen(PFS_VOL_MD));

exit:

    return ret;
}

int process_vol_md(char* file_path) {
    int ret = PFS_SUCCESS;

    FILE* fp          = NULL;
    size_t read_bytes = 0;

    if (!file_path) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    if (checked_use_of_custom_key == 0) {
        check_use_of_custom_key();
        checked_use_of_custom_key = 1;
    }

    DBG_PRINT("checked_use_of_custom_key=%d, use_custom=%d\n", checked_use_of_custom_key,
              using_custom_key);

    DBG_PRINT("file_path->%s\n", file_path);

    fp = fopen_fn_glb(file_path, "r");

    if (!fp) {
        DBG_PRINT("Failed to read the vol meta-data blob\n");
        ret = PFS_VOL_MD_PROCESS_FOPEN_ERROR;
        goto exit;
    }

    memset(&vol_md_glb, 0, sizeof(vol_md_t));

    read_bytes = fread_fn_glb(&vol_md_glb, 1, sizeof(vol_md_t), fp);

    if (read_bytes != sizeof(vol_md_t)) {
        DBG_PRINT("Error, after fread, read_bytes = %lu, expected = %lu\n", read_bytes,
                  sizeof(vol_md_t));
        ret = PFS_VOL_MD_PROCESS_READ_ERROR;
        goto exit;
    }

    /*At this point, need to verify authenticity of blob
     * 1. check key_type.
     * 2. use the key_id, to generate_key_ids.
     * 3. use VMK, to verify the MAC of the blob.
     * 4. If MAC fails, set error and return.
     * 5. If all good, then you accept blob...and vmc_init = 1.
     */

    if ((using_custom_key && (vol_md_glb.prot_data.key_type != CUSTOM_KEY)) ||
        (!using_custom_key && (vol_md_glb.prot_data.key_type != SEAL_KEY))) {
        ret = PFS_VOL_MD_PROCESS_KEY_TYPE_ERROR;
        goto exit;
    }

    memset(&vol_keys_glb, 0, sizeof(vol_keys_t));

    // generate keys(VCK, VNK, VMK)
    ret = generate_keys(&vol_md_glb, &vol_keys_glb);

    if (ret != 0) {
        ret = PFS_KEY_GEN_ERROR;
        goto exit;
    }

    // Compute mac over prot_data
    ret = verify_mac(&vol_md_glb, &vol_keys_glb);

    if (ret != 0) {
        DBG_PRINT("error with verifying mac, ret=%d\n", ret);
        ret = PFS_MAC_VERIFY_ERROR;
        goto exit;
    }

exit:

    if (fp) {
        fclose_fn_glb(fp);
    }

    return ret;
}

int volume_metadata_setup(char* mnt_path) {
    /*
     *1. look for hidden .graphene_pfs.bin
     *1. if ((.gra_pfs.bin) && force_new == 1) || !(.gra_pfs.bin))
     *1. 	create_vol_md(char *mnt_path)
     *1. else //process existing file
     *1. 	process_vol_md(char *mnt_path)
     *
     *
     */
    int ret         = 0;
    FILE* fp        = NULL;
    char* file_path = NULL;

    if (!mnt_path) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    ret = vol_md_file_helper(mnt_path, &file_path);

    if (ret != 0) {
        goto exit;
    }

    DBG_PRINT("file_path->%s\n", file_path);
    fp = fopen_fn_glb(file_path, "rb");

    // TODO: Add other checks like force_new parameter in manifest.
    if (!fp) {
        DBG_PRINT("Failed to read the vol meta-data blob, errno=%d\n", errno);
        perror("volume_metadata_setup-Failed to read the vol meta-data blob\n");
        ret = create_vol_md(mnt_path);

    } else {
        DBG_PRINT("vol meta-data blob exists\n");

        fclose_fn_glb(fp);

        ret = process_vol_md(file_path);
    }

    if (ret == PFS_SUCCESS) {
        vol_md_init = 1;
    } else {
        vol_md_init_failed = 1;
    }

exit:

    if (file_path)
        free(file_path);

    return ret;
}

static int compute_mac(uint8_t* buf, size_t buf_len, uint8_t* key, size_t key_len,
                       mac_output_t* mac_output) {
    int ret = 0;

    sgx_status_t sgx_ret;

    if (!buf || (buf_len == 0) || !key || (key_len == 0) || !mac_output) {
        ret = PFS_INVALID_PARAM;
        return ret;
    }

    sgx_ret = sgx_rijndael128_cmac_msg((const sgx_cmac_128bit_key_t*)key, (const uint8_t*)buf,
                                       buf_len, mac_output);

    if (sgx_ret != SGX_SUCCESS) {
        ret = PFS_CRYPTO_ERROR;
    } else {
        PRINT_BUF("\n compute_mac: vol-id mac =", (uint8_t*)mac_output, sizeof(mac_output_t));
    }

    return ret;
}

int compute_hash(uint8_t* buf, int buf_len, hash_output_t* hash_output) {
    int ret = 0;

    if (!buf || !buf_len || !hash_output) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    /* 0 here means use the full SHA-256, not the SHA-224 variant */
    ret = mbedtls_sha256_ret(buf, buf_len, (unsigned char*)hash_output, 0);

    if (ret != 0) {
        DBG_PRINT("error, ret=%d, from mbedtls_sha256", ret);
    }

exit:

    return ret;
}

// Note: secure_io_path refers to pfs_mount_point.
int get_dir_prefix_after_secure_io_path(const char* dir_path,
                                        char** dir_prefix_after_secure_io_path) {
    int ret = 0;

    // mnt_path pointer returned by getenv, should not be freed.
    char* sec_io_path = NULL;

    if (!dir_path || !dir_prefix_after_secure_io_path) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    // note: if dir_path matches secure_io_path, dir_prefix will get set to
    // NULL.
    *dir_prefix_after_secure_io_path = NULL;

    DBG_PRINT("dir_path=%s, strlen of dir_path=%lu\n", dir_path, strlen(dir_path));

    sec_io_path = getenv(PFS_MOUNT_POINT_ENV);

    if (sec_io_path != NULL) {
        DBG_PRINT(
            "sec_io_path=%s, strlen(sec_io_path)=%lu, dir_path=%s, "
            "strlen(dir_path)=%lu\n",
            sec_io_path, strlen(sec_io_path), dir_path, strlen(dir_path));

        if (strlen(dir_path) < strlen(sec_io_path)) {
            ret = PFS_MOUNT_POINT_NOT_SUBSET_OF_DIR_PATH;
            goto exit;
        }

        if (strncmp(sec_io_path, dir_path, strlen(sec_io_path)) != 0) {
            ret = PFS_MOUNT_POINT_NOT_SUBSET_OF_DIR_PATH;
            goto exit;
        }

        if (strlen(dir_path) > strlen(sec_io_path)) {
            *dir_prefix_after_secure_io_path = (char*)dir_path + strlen(sec_io_path);
        }
    } else {
        ret = PFS_MOUNT_POINT_NOT_SET;
        goto exit;
    }

exit:

    return ret;
}

int remove_extra_backslashes_in_dir_path_in_place(char* src_buf) {
    int ret                      = 0;
    int next_index               = 0;
    int prev_index               = 0;
    bool extra_backslashes_exist = 0;

    if (!src_buf) {
        return PFS_INVALID_PARAM;
    }

    next_index++;

    while (src_buf[next_index] != '\0') {
        if ((((src_buf[prev_index] == src_buf[next_index]) && (src_buf[prev_index] == '/'))) != 1) {
            prev_index++;

            if (extra_backslashes_exist) {
                src_buf[prev_index] = src_buf[next_index];
            }

        } else {
            extra_backslashes_exist = 1;
        }

        next_index++;
    }

    prev_index++;
    *(src_buf + prev_index) = '\0';  // terminate string

    return ret;
}

/* Note: When application passes path to directory-path(and-also
 * when setting path in manifest),
 * there should NOT be any trailing or extra backslashes(/).
 * In above cases, it will result in path-prefix used as tweak for file-name encryption,
 * to be different for the same directory-path(versus during file-name decryption).
 * During filename decryption, current code is designed NOT to have extra or
 * trailing back-slashes.
 * Library code uses realpath and dirname apis, which removes trailing back-slash(if any).
 * Since we can't enforce this at the application-level,
 * here we check for extra back-slashes, and strip-out any extra
 * back-slashes. */
int compute_tweak_value(char* dir_path, vol_id_t* vol_id, tweak_value_t* tweak_value) {
    int ret            = 0;
    uint8_t* tweak_buf = NULL;
    int buf_len        = 0;
    hash_output_t hash_output;

    // Note: alternatively, we can replace this logic
    // by calling hash_update, twice, first with vol_id, and then dir_path.

    if (!vol_id || !tweak_value) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    if (dir_path) {
        ret = remove_extra_backslashes_in_dir_path_in_place(dir_path);

        if (ret != 0) {
            ret = PFS_OTHER_ERROR;
            goto exit;
        }
    }

    if (dir_path) {
        DBG_PRINT("dir_path=%s, strlen of dir_path=%lu\n", dir_path, strlen(dir_path));
    }

    buf_len = sizeof(vol_id_t);

    if (dir_path)
        buf_len += strlen(dir_path) + 1;

    tweak_buf = (uint8_t*)calloc(buf_len, 1);

    if (!tweak_buf) {
        ret = PFS_OUT_OF_MEMORY;
        return ret;
    }

    memcpy(tweak_buf, vol_id, sizeof(vol_id_t));

    if (dir_path)
        memcpy(tweak_buf + sizeof(vol_id_t), dir_path, strlen(dir_path));

    ret = compute_hash(tweak_buf, buf_len, &hash_output);

    if (ret != 0) {
        goto exit;
    }

    memcpy(tweak_value, hash_output, sizeof(tweak_value_t));

    PRINT_BUF("tweak_value=", (uint8_t*)tweak_value, sizeof(tweak_value_t));

exit:

    if (tweak_buf) {
        free(tweak_buf);
    }

    return ret;
}

int encrypt_aes_xts(unsigned char* key, size_t key_len, tweak_value_t* tweak_value,
                    const unsigned char* basen, size_t basen_len, unsigned char* encrypted_basen) {
    int ret = 0;
    mbedtls_aes_xts_context enc_xts;

    if (!key || !key_len || !tweak_value || !basen || !basen_len || !encrypted_basen) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    // TODO: add checks for invalid key_len

    if (basen_len < SIXTEEN_BYTES) {
        DBG_PRINT(
            "padded basen length=%lu, less than AES block size and less "
            "than expected\n",
            basen_len);
        ret = PFS_PADDED_FILENAME_LEN_INVALID;
        goto exit;
    }

    PRINT_BUF("AES XTS KEY=", (uint8_t*)key, key_len);

    mbedtls_aes_xts_init(&enc_xts);

    ret = mbedtls_aes_xts_setkey_enc(&enc_xts, key, key_len * 8);

    if (ret != 0) {
        DBG_PRINT("error=%d, from mbedtls_aes_xts_setkey_enc\n", ret);
        goto exit;
    }

    ret = mbedtls_aes_crypt_xts(&enc_xts, MBEDTLS_AES_ENCRYPT, basen_len,
                                (unsigned char*)tweak_value, basen, encrypted_basen);

    if (ret != 0) {
        DBG_PRINT("error=%d, from mbedtls_aes_crypt_xts during enc\n", ret);
        goto exit;
    }

exit:

    return ret;
}

int encrypt_filename(vnk_t* vnk, const char* dir_path, const unsigned char* basen, size_t basen_len,
                     unsigned char* encrypted_basen) {
    int ret = 0;
    tweak_value_t tweak_value;

    char* dir_prefix_after_secure_io_path = NULL;

    if (!vnk || !dir_path || !basen || !basen_len || !encrypted_basen) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    if (basen_len < SIXTEEN_BYTES) {
        DBG_PRINT(
            "padded basen length=%lu, less than AES block size and less "
            "than expected\n",
            basen_len);
        ret = PFS_PADDED_FILENAME_LEN_INVALID;
        goto exit;
    }

    DBG_PRINT("dir_path=%s, strlen of dir_path=%lu\n", dir_path, strlen(dir_path));

    if ((ret = get_dir_prefix_after_secure_io_path(dir_path, &dir_prefix_after_secure_io_path)) !=
        0) {
        goto exit;
    }

    ret = compute_tweak_value(dir_prefix_after_secure_io_path, &vol_md_glb.vol_id, &tweak_value);

    if (ret != 0) {
        goto exit;
    }

    ret = encrypt_aes_xts((unsigned char*)vnk, sizeof(vnk_t), &tweak_value, basen, basen_len,
                          encrypted_basen);

    if (ret != 0) {
        goto exit;
    }

exit:

    return ret;
}

int encode_filename(uint8_t* encrypted_basen, size_t base_len, uint8_t** encoded_basen,
                    size_t* enc_len) {
    int ret = 0;

    if (!encrypted_basen || !base_len || !encoded_basen || !enc_len) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    *encoded_basen = base64_encode(encrypted_basen, base_len, enc_len);

    if (*encoded_basen == NULL) {
        ret = PFS_FILENAME_ENCODE_ERROR;
        goto exit;
    } else {
        DBG_PRINT("encoded_basename=%s, orig_len = %lu, enc_len=%lu\n", *encoded_basen, base_len,
                  *enc_len);
    }

exit:

    return ret;
}

// Note: this api expects absolute path in dir_path.
/* TODO:
For better performance, can we
do getenv(secure_io_path) once, and have a global for it..
(OR) you can group the various globals in one global struct..
that has params..like using_custom_key, secure_io_path..etc
*/
int check_dir_path_prefix(char* dir_path, bool* path_to_protected_file) {
    int ret = 0;

    /*Note:
     * ii) secure_io_path should be subset or equal to path prefix
     */

    char* secure_io_path = NULL;

    if (!dir_path || !path_to_protected_file) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    if (strlen(dir_path) == 0) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    secure_io_path = getenv(PFS_MOUNT_POINT_ENV);

    if (!secure_io_path) {
        DBG_PRINT("secure_io_path is NULL\n");
        ret = PFS_MOUNT_POINT_NOT_SET;
        goto exit;
    }

    /*Note: below checks are primarily to indicate
    if path is protected directory or not..*/
    if (strlen(secure_io_path) <= strlen(dir_path)) {
        if (strncmp(secure_io_path, dir_path, strlen(secure_io_path)) != 0) {
            DBG_PRINT("secure_io_path=%s, NOT subset of dir_path=%s\n", secure_io_path, dir_path);
            *path_to_protected_file = 0;
            goto exit;
        }
    } else {
        DBG_PRINT("secure_io_path=%s, NOT subset of dir_path=%s\n", secure_io_path, dir_path);
        *path_to_protected_file = 0;
        goto exit;
    }

    *path_to_protected_file = 1;

exit:

    return ret;
}

// note: this generic api..can be used where filename is absolute or relative.
int get_dirname_basename(const char* filename, char** dirc, char** basec, char** dir_path,
                         char** basen) {
    int ret = 0;

    if (!filename || !dirc || !basec || !dir_path || !basen) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    *dirc  = strndup(filename, strlen(filename) + 1);
    *basec = strndup(filename, strlen(filename) + 1);

    if (!(*dirc) || !(*basec)) {
        ret = PFS_INVALID_FILENAME_PARAM;
        goto exit;
    }

    *dir_path = dirname(*dirc);
    *basen    = basename(*basec);

    // as per dirname manpage, dirname never returns NULL.
    if (!(*dir_path) || !(*basen)) {
        ret = PFS_INVALID_FILENAME_PARAM;
        goto exit;
    }

    if ((strncmp(*dir_path, DOT_STRING, strlen(DOT_STRING)) == 0) &&
        (strncmp(*basen, DOT_STRING, strlen(DOT_STRING)) == 0)) {
        ret = PFS_INVALID_FILENAME_PARAM;
        goto exit;
    } else if ((strncmp(*dir_path, FWD_SLASH_STRING, strlen(FWD_SLASH_STRING)) == 0) &&
               (strncmp(*basen, FWD_SLASH_STRING, strlen(FWD_SLASH_STRING)) == 0)) {
        ret = PFS_INVALID_FILENAME_PARAM;
        goto exit;
    }

exit:

    return ret;
}

// Note: this api expects absolute path in filename.
int decompose_filename(const char* filename, char** dirc, char** basec, char** dir_path,
                       char** basen) {
    int ret = 0;

    if (!filename || !dirc || !basec || !dir_path || !basen) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    if (filename[0] != '/') {
        ret = PFS_FILENAME_PATH_NOT_ABSOLUTE;
        goto exit;
    }

    if ((ret = get_dirname_basename(filename, dirc, basec, dir_path, basen)) != 0) {
        goto exit;
    }

exit:

    return ret;
}

static int check_if_filename_is_ascii_string(char* name, bool* is_filename_ascii_string) {
    int ret    = 0;
    size_t len = 0;
    size_t cnt = 0;

    if (!name || !is_filename_ascii_string)
        return -1;

    len = strlen(name);

    while (cnt < len) {
        if (name[cnt] < 0) {
            *is_filename_ascii_string = 0;
            break;
        }
        cnt++;
    }

    *is_filename_ascii_string = 0;

    if (cnt == len) {
        *is_filename_ascii_string = 1;
    }

    return ret;
}

int pfs_encrypt_filename(const char* filename, char** encrypted_filename) {
    int ret        = 0;
    int crypto_ret = 0;

    char* dirc  = NULL;
    char* basec = NULL;

    // Note: dirc/basec pointers need to be freed, instead of
    // these pointers set by dirname/basename should not be freed
    char* basen    = NULL;
    char* dir_path = NULL;

    unsigned char* padded_basen    = NULL;
    unsigned char* encrypted_basen = NULL;
    unsigned char* encoded_basen   = NULL;
    size_t encoded_basen_len       = 0;
    size_t padded_basen_len        = 0;
    bool is_filename_ascii_string  = false;

    /*Note: the calls to this api, are expected to have
    absolute path */

    if (!filename || !encrypted_filename) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    if (vol_md_init != true || (vol_md_init_failed == true)) {
        ret = PFS_VOL_MD_UNINITIALIZED;
        goto exit;
    }

    if ((ret = decompose_filename(filename, &dirc, &basec, &dir_path, &basen)) != 0) {
        goto exit;
    }

    /*Note: decompose_filename will ensure that dir_path will not be null.
     * just adding check to be safe..*/
    if (!dir_path) {
        goto exit;
    }

    DBG_PRINT("filename->%s, dirname=%s, basen=%s\n", filename, dir_path, basen);
    DBG_PRINT("strlen(dirname)=%lu, strlen(basen)=%lu\n", strlen(dir_path), strlen(basen));

    // accounting for terminating null string..
    if (strlen(basen) > (PFS_FILENAME_MAX_LENGTH - 1)) {
        ret = PFS_FILENAME_TOO_LONG;
        goto exit;
    }

    ret = check_if_filename_is_ascii_string(basen, &is_filename_ascii_string);

    if ((ret != 0) || (is_filename_ascii_string == false)) {
        ret = PFS_FILENAME_NOT_ASCII_STRING;
        goto exit;
    }

    padded_basen_len = PFS_FILENAME_MAX_LENGTH;

#ifdef FILENAME_LENGTH_FLEXIBLE_PADDING

    padded_basen_len = strlen(basen);

    if ((padded_basen_len % FILENAME_LENGTH_ALIGN) == 0) {
        padded_basen_len = padded_basen_len + FILENAME_LENGTH_ALIGN;
    } else {
        PADDED_LENGTH(padded_basen_len, FILENAME_LENGTH_ALIGN);
    }

    DBG_PRINT("orig_length=%lu, padded_len=%lu\n", strlen(basen), padded_basen_len);

    // accounting for terminating null string..
    if (padded_basen_len > (PFS_FILENAME_MAX_LENGTH - 1)) {
        ret = PFS_FILENAME_TOO_LONG;
        goto exit;
    }

#endif

    padded_basen = (unsigned char*)calloc(padded_basen_len, 1);

    if (!padded_basen) {
        ret = PFS_OUT_OF_MEMORY;
        goto exit;
    }

    memcpy(padded_basen, basen, strlen(basen));

    DBG_PRINT("padded_basen=%s, strlen(padded_basen)=%lu\n", padded_basen,
              strlen((const char*)padded_basen));

    encrypted_basen = (unsigned char*)calloc(padded_basen_len, 1);

    if (!encrypted_basen) {
        ret = PFS_OUT_OF_MEMORY;
        goto exit;
    }

    crypto_ret = encrypt_filename(&vol_keys_glb.vnk, dir_path, (const unsigned char*)padded_basen,
                                  padded_basen_len, encrypted_basen);

    if (crypto_ret != 0) {
        DBG_PRINT("error from encrypt_filename=%d", crypto_ret);
        ret = PFS_FILENAME_ENCRYPT_ERROR;
        goto exit;
    }

    DBG_PRINT("encrypted_basen's len=%lu, encrypted_basen=%s\n", padded_basen_len, encrypted_basen);

    ret = encode_filename(encrypted_basen, padded_basen_len, &encoded_basen, &encoded_basen_len);

    if (ret != 0) {
        ret = PFS_FILENAME_ENCODE_ERROR;
        goto exit;
    }

    DBG_PRINT("encoded_basen's len=%lu, encoded_basen=%s\n", encoded_basen_len, encoded_basen);

    *encrypted_filename = (char*)calloc(strlen(dir_path) + 1 + encoded_basen_len + 1, 1);

    if (*encrypted_filename == NULL) {
        ret = PFS_OUT_OF_MEMORY;
        goto exit;
    }

    memcpy(*encrypted_filename, dir_path, strlen(dir_path));
    *(*encrypted_filename + strlen(dir_path)) = '/';
    memcpy(*encrypted_filename + strlen(dir_path) + 1, encoded_basen, encoded_basen_len);

// Note: caller is responsible to free encrypted_filename */

exit:

    if (dirc)
        free(dirc);

    if (basec)
        free(basec);

    if (padded_basen)
        free(padded_basen);

    if (encrypted_basen)
        free(encrypted_basen);

    if (encoded_basen)
        free(encoded_basen);

    return ret;
}

int decrypt_aes_xts(unsigned char* key, size_t key_len, tweak_value_t* tweak_value,
                    const unsigned char* basen, size_t basen_len, unsigned char* decrypted_basen) {
    int ret = 0;
    mbedtls_aes_xts_context dec_xts;

    if (!key || !key_len || !tweak_value || !basen || !basen_len || !decrypted_basen) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    // TODO: add checks for invalid key_len

    if (basen_len < SIXTEEN_BYTES) {
        DBG_PRINT(
            "padded basen length=%lu, less than AES block size and less "
            "than expected\n",
            basen_len);
        ret = PFS_PADDED_FILENAME_LEN_INVALID;
        goto exit;
    }

    PRINT_BUF("AES XTS KEY=", (uint8_t*)key, key_len);

    mbedtls_aes_xts_init(&dec_xts);

    ret = mbedtls_aes_xts_setkey_dec(&dec_xts, key, key_len * 8);

    if (ret != 0) {
        DBG_PRINT("error=%d, from mbedtls_aes_xts_setkey_enc\n", ret);
        goto exit;
    }

    ret = mbedtls_aes_crypt_xts(&dec_xts, MBEDTLS_AES_DECRYPT, basen_len,
                                (unsigned char*)tweak_value, basen, decrypted_basen);

    if (ret != 0) {
        DBG_PRINT("error=%d, from mbedtls_aes_crypt_xts during dec\n", ret);
        goto exit;
    }

exit:

    return ret;
}

int decrypt_filename(vnk_t* vnk, const char* dir_path, const unsigned char* basen, size_t basen_len,
                     unsigned char* decrypted_basen) {
    int ret = 0;
    tweak_value_t tweak_value;
    char* dir_prefix_after_secure_io_path = NULL;

    if (!vnk || !dir_path || !basen || !basen_len || !decrypted_basen) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    if (basen_len < SIXTEEN_BYTES) {
        DBG_PRINT(
            "padded basen length=%lu, less than AES block size and less "
            "than expected\n",
            basen_len);
        ret = PFS_PADDED_FILENAME_LEN_INVALID;
        goto exit;
    }

    DBG_PRINT("dir_path=%s, strlen of dir_path=%lu\n", dir_path, strlen(dir_path));

    if ((ret = get_dir_prefix_after_secure_io_path(dir_path, &dir_prefix_after_secure_io_path)) !=
        0) {
        goto exit;
    }

    ret = compute_tweak_value(dir_prefix_after_secure_io_path, &vol_md_glb.vol_id, &tweak_value);

    if (ret != 0) {
        goto exit;
    }

    ret = decrypt_aes_xts((unsigned char*)vnk, sizeof(vnk_t), &tweak_value, basen, basen_len,
                          decrypted_basen);

    if (ret != 0) {
        goto exit;
    }

exit:

    return ret;
}

static int check_for_zero_padding_for_filename(char* filename, size_t filename_buf_length) {
    int ret = PFS_SUCCESS;

    size_t filename_str_len = 0;
    uint8_t* zero_buf       = NULL;

    if (!filename || !filename_buf_length) {
        return PFS_INVALID_PARAM;
    }

    if (filename_buf_length != PFS_FILENAME_MAX_LENGTH) {
        return PFS_FILENAME_DECODED_LENGTH_INVALID;
    }

    filename_str_len = strlen(filename);

    if (filename_str_len + 1 > PFS_FILENAME_MAX_LENGTH) {
        return PFS_FILENAME_DECODED_LENGTH_INVALID;
    } else if (filename_str_len >= filename_buf_length) {
        return PFS_FILENAME_DECODED_LENGTH_INVALID;
    } else if ((filename_str_len + 1) == PFS_FILENAME_MAX_LENGTH) {
        // note: this is a valid case.
        return PFS_SUCCESS;
    }

    zero_buf = (uint8_t*)calloc(filename_buf_length - filename_str_len, 1);

    if (!zero_buf) {
        return PFS_OUT_OF_MEMORY;
    }

    if (memcmp(filename + filename_str_len, zero_buf, filename_buf_length - filename_str_len) !=
        0) {
        ret = PFS_DECRYPTED_NAME_NOT_ZERO_PADDED;
        goto exit;
    }

/*DBG_PRINT("decrypted name->%s, zero padded, buf-len=%lu, str-len=%lu\n",
                        filename, filename_buf_length, filename_str_len);*/

exit:

    if (zero_buf) {
        free(zero_buf);
    }

    return ret;
}

/*TODO: re-test code related to FILENAME_LENGTH_FLEXIBLE_PADDING */
/* Note: this api expects filenames to have basenames ONLY. */
int pfs_decrypt_filename(char* dir_path, const char* filename, char** decrypted_filename) {
    int ret        = 0;
    int crypto_ret = 0;

    unsigned char* decoded_basen = NULL;

    size_t encoded_len = 0;
    size_t decoded_len = 0;

    size_t decrypted_len          = 0;
    bool is_filename_ascii_string = 0;

    if (!filename || !decrypted_filename) {
        ret = PFS_INVALID_PARAM;
        goto exit;
    }

    if (vol_md_init != true || (vol_md_init_failed == true)) {
        ret = PFS_VOL_MD_UNINITIALIZED;
        goto exit;
    }

    encoded_len = strlen(filename);

    DBG_PRINT("dirname=%s, filename=%s\n", dir_path, filename);

    DBG_PRINT("strlen(dirname)=%lu, strlen(filename)=%lu\n", strlen(dir_path), encoded_len);

    // accounting for terminating null string..
    if (encoded_len > (PFS_ENCODED_FILENAME_MAX_LENGTH - 1)) {
        ret = PFS_ENCODED_FILENAME_TOO_LONG;
        goto exit;
    }

    decoded_basen = base64_decode((const unsigned char*)filename, encoded_len, &decoded_len);

    if (!decoded_basen) {
        ret = PFS_FILENAME_DECODE_ERROR;
        goto exit;
    } else {
        DBG_PRINT("decoded_basen=%s, encoded_len = %lu, decoded_len=%lu\n", decoded_basen,
                  encoded_len, decoded_len);
    }

#ifndef FILENAME_LENGTH_FLEXIBLE_PADDING
    if (decoded_len != PFS_FILENAME_MAX_LENGTH) {
        DBG_PRINT("ERROR, decoded_len=%lu, != expected MAX_len = %d\n", decoded_len,
                  PFS_FILENAME_MAX_LENGTH);
        ret = PFS_FILENAME_DECODED_LENGTH_INVALID;
        goto exit;
    }
#else
    if ((decoded_len % FILENAME_LENGTH_ALIGN) == 0) {
        DBG_PRINT("decoded_len=%lu, = aligned to = %d\n", decoded_len, FILENAME_LENGTH_ALIGN);
    } else {
        DBG_PRINT("ERROR, decoded_len=%lu, NOT aligned to = %d\n", decoded_len,
                  FILENAME_LENGTH_ALIGN);
        ret = PFS_FILENAME_DECODED_LENGTH_INVALID;
        goto exit;
    }
#endif

    *decrypted_filename = (char*)calloc(decoded_len, 1);

    if (!(*decrypted_filename)) {
        ret = PFS_OUT_OF_MEMORY;
        goto exit;
    }

    crypto_ret = decrypt_filename(&vol_keys_glb.vnk, dir_path, (const unsigned char*)decoded_basen,
                                  decoded_len, (unsigned char*)(*decrypted_filename));

    if (crypto_ret != 0) {
        DBG_PRINT("error from encrypt_filename=%d", crypto_ret);
        ret = PFS_FILENAME_DECRYPT_ERROR;
        goto exit;
    }

    decrypted_len = strlen((const char*)(*decrypted_filename));

/*DBG_PRINT("decrypted_filename's len=%lu, decrypted_basen=%s\n", decrypted_len,
       *decrypted_filename);*/

#ifndef FILENAME_LENGTH_FLEXIBLE_PADDING
    if (decrypted_len > PFS_FILENAME_MAX_LENGTH) {
        DBG_PRINT("ERROR, decrypted_len=%lu, > expected MAX_len = %d\n", decrypted_len,
                  PFS_FILENAME_MAX_LENGTH);
        ret = PFS_FILENAME_TOO_LONG;
        goto exit;
    }

    ret = check_for_zero_padding_for_filename(*decrypted_filename, decoded_len);

    if (ret != 0) {
        goto exit;
    }

    ret = check_if_filename_is_ascii_string(*decrypted_filename, &is_filename_ascii_string);

    if ((ret != 0) || (is_filename_ascii_string == false)) {
        ret = PFS_FILENAME_NOT_ASCII_STRING;
        goto exit;
    }

#endif

// Note: caller is responsible to free decrypted_filename */

exit:

    if (decoded_basen)
        free(decoded_basen);

    return ret;
}
