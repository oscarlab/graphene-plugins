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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdarg.h>

#include <dlfcn.h>
#include <errno.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "fileops_typedefs.h"

#include "pfs_debug.h"
#include "protected_fs_file.h"
#include "sgx_tprotected_fs.h"

//#include "sgx_proxy_key.h"
//#include "sgx_proxy_tseal.h"
#include "sgx_key.h"
#include "sgx_tseal.h"

#include "pfs_plus.h"

#define IO_ERROR_RETURN (-1)
#define IO_SUCCESS_RETURN (0)

/* Note: open or openat needs extra argument mode, only if flags has O_CREAT or
 * O_TMPFILE */
#ifdef __O_TMPFILE
#define IS_MODE_ARG_REQUIRED(flags) (((flags)&O_CREAT) != 0 || ((flags)&__O_TMPFILE) == __O_TMPFILE)
#else
#define IS_MODE_ARG_REQUIRED(flags) (((flags)&O_CREAT) != 0)
#endif

#define FOPEN_STR "fopen"
#define FOPEN64_STR "fopen64"

#define DBG_ERRNO_HELPER(func)                                     \
    {                                                              \
        DBG_PRINT("%s not supported, for protected file\n", func); \
        errno = ENOTSUP;                                           \
    }

// static FILE *sgx_fopen_proxy(const char *filename, const char *mode, ...);
static FILE* sgx_fopen_proxy(const char* filename, const char* mode);
static int sgx_fclose_proxy(FILE* stream);
static size_t sgx_fread_proxy(void* ptr, size_t size, size_t nmemb, FILE* stream);
static size_t sgx_fwrite_proxy(const void* ptr, size_t size, size_t nmemb, FILE* stream);
static int sgx_fseek_proxy(FILE* stream, long int offset, int whence);
static long sgx_ftell_proxy(FILE* stream);
static int sgx_fflush_proxy(FILE* stream);
static int sgx_ferror_proxy(FILE* stream);
static int sgx_feof_proxy(FILE* stream);
static void sgx_clearerr_proxy(FILE* stream);
static void sgx_rewind_proxy(FILE* stream);

static int sgx_putc_proxy(int c, FILE* stream);

static bool check_secure_io_path(const char* filename);
static bool check_if_pfs_file(void* pfs_file_ptr);

static int sgx_fseeko_proxy(FILE* stream, off_t offset, int whence);
static off_t sgx_ftello_proxy(FILE* stream);

static int retreive_custom_key(sgx_key_128bit_t* sgx_key);

/* Globals */
bool checked_use_of_custom_key = 0;
bool using_custom_key          = 0;
sgx_key_128bit_t sgx_key_glb;
int volume_metadata_setup_status = 0;
/* Globals from pfs_plus.c */
extern vol_md_t vol_md_glb;
extern vol_keys_t vol_keys_glb;
extern bool volume_metadata_setup_done;
extern bool vol_md_init;
extern bool vol_md_init_failed;

static uint64_t sgx_file_id = SGX_FILE_ID;

static FILE* fopen_helper(const char* filename, const char* mode, const char* fopen_api);

static int updated_check_secure_io_path(const char* filename, char** abs_file_path,
                                        bool* path_to_protected_file);

/* For "List of Filesystem apis handled (and the ones not handled) by library",
 * for protected-files, please refer to section in README:
 * Note: For non-protected files, ALL C filesystem apis are supported. */

/* Note: List of 64-bit apis below:
fopen64, freopen64,
ftello64, fseeko64, fgetpos64, fsetpos64
open64, openat64 ,creat64
Note: For file seek/tell protect-fs apis supports 64-bit using fseeko/ftello.*/

/*Global pointers, to prevent recursive overloading of fops library, and instead call glibC api,
 when needed. Like, when SGX-ProtectFS calls C system apis and other places in the library. */
#if (_FILE_OFFSET_BITS == 64)
fopen_f_type fopen_fn_glb = (fopen_f_type)dlsym(RTLD_NEXT, "fopen64");
open_f_type open_fn_glb   = (open_f_type)dlsym(RTLD_NEXT, "open64");
#else
fopen_f_type fopen_fn_glb = (fopen_f_type)dlsym(RTLD_NEXT, "fopen");
open_f_type open_fn_glb   = (open_f_type)dlsym(RTLD_NEXT, "open");
#endif

// Note: Below apis names are generic, independant of 32/64 bit.
fclose_f_type fclose_fn_glb     = (fclose_f_type)dlsym(RTLD_NEXT, "fclose");
fread_f_type fread_fn_glb       = (fread_f_type)dlsym(RTLD_NEXT, "fread");
fwrite_f_type fwrite_fn_glb     = (fwrite_f_type)dlsym(RTLD_NEXT, "fwrite");
fflush_f_type fflush_fn_glb     = (fflush_f_type)dlsym(RTLD_NEXT, "fflush");
ferror_f_type ferror_fn_glb     = (ferror_f_type)dlsym(RTLD_NEXT, "ferror");
feof_f_type feof_fn_glb         = (feof_f_type)dlsym(RTLD_NEXT, "feof");
clearerr_f_type clearerr_fn_glb = (clearerr_f_type)dlsym(RTLD_NEXT, "clearerr");
remove_f_type remove_fn_glb     = (remove_f_type)dlsym(RTLD_NEXT, "remove");
fileno_f_type fileno_fn_glb     = (fileno_f_type)dlsym(RTLD_NEXT, "fileno");

// Note: SGX ProtectFS apis uses system apis->fseeko/ftello
fseeko_f_type fseeko_fn_glb = (fseeko_f_type)dlsym(RTLD_NEXT, "fseeko");
ftello_f_type ftello_fn_glb = (ftello_f_type)dlsym(RTLD_NEXT, "ftello");

static bool check_if_pfs_file(void* pfs_file_ptr) {
    void* sgx_file_id_ptr = NULL;

    if (!pfs_file_ptr) {
        DBG_PRINT("invalid ptr. \n");
        return false;
    }

    /* Note:
    For regular non-Protected file's FILE data structure, size when using
    GNU C library is 216 bytes.
    Protected-FS's SGX_FILE* is several KBs in size.
    Expectation is that input to these apis, are either regular FILE*
    or SGX_FILE*, in which case, this api will work fine. */

    /* Below check, parses file pointer, to determine if the file is a
    Protected-FS file or not, based on check for SGX_FILE_ID.*/

    sgx_file_id_ptr = (void*)((uint8_t*)pfs_file_ptr + sizeof(uint64_t));

    if (memcmp(sgx_file_id_ptr, &sgx_file_id, sizeof(uint64_t)) == 0) {
        DBG_PRINT("sgx_file_id match\n");
        return true;
    }

    return false;
}

#define DIR_PATH_MAX_LEN (512)
bool get_directory_prefix(const char* src, char* dest, char* dir_prefix) {
    const char* p    = src;
    const char* name = src;

    while ((*p) != '\0') {
        if ((*p) == '\\' || (*p) == '/')
            name = p + 1;
        p++;
    }

    if (strlen(name) > FILENAME_MAX_LEN - 1) {
        return false;
    }

    strncpy(dest, name, FILENAME_MAX_LEN - 1);
    dest[FILENAME_MAX_LEN - 1] = '\0';

    if (strnlen(dest, 1) == 0) {
        return false;
    }

    if (name - src && ((name - src) < DIR_PATH_MAX_LEN)) {
        strncpy(dir_prefix, src, name - src);
        dir_prefix[name - src] = '\0';
    } else
        return false;

    return true;
}

static bool check_secure_io_path(const char* filename) {
    bool is_path_to_protected_file = false;
    char* abs_file_path            = NULL;

    int ret_val;

    if (!filename)
        return false;

    DBG_PRINT("\nfilename=%s\n", filename);

    if ((ret_val = updated_check_secure_io_path(filename, &abs_file_path,
                                                &is_path_to_protected_file)) != 0) {
        DBG_PRINT("error ret=%d, from updated_check_secure_io_path\n", ret_val);
        is_path_to_protected_file = false;
        goto exit;
    }

    DBG_PRINT("filename->%s, is it path to protected_file=%d\n", filename,
              is_path_to_protected_file);

exit:

    if (abs_file_path)
        free(abs_file_path);

    return is_path_to_protected_file;
}

static int updated_check_secure_io_path(const char* filename, char** abs_file_path,
                                        bool* path_to_protected_file) {
    int ret = 0;

    char* abs_dir_path = NULL;
    char* dirc         = NULL;
    char* basec        = NULL;

    // Note: dirc/basec pointers need to be freed, instead of
    // these pointers set by dirname/basename should not be freed
    char* basen    = NULL;
    char* dir_path = NULL;

    int ret_val = 0;

    if (!filename || !abs_file_path || !path_to_protected_file) {
        return -1;
    }

    // check if path is absolute or relative path
    if (filename[0] == '/') {
        DBG_PRINT("absolute path, file-name=%s\n", filename);

        /*Note: to check for allowed path, filename, needs to have secure-io
        directory path, set in the application’s manifest */
        if ((ret = check_dir_path_prefix((char*)filename, path_to_protected_file)) != 0) {
            goto exit;
        }

        DBG_PRINT("path_to_protected_file=%d\n", *path_to_protected_file);

        return 0;
    } else {
        DBG_PRINT("relative path, file-name=%s\n", filename);

        if ((ret = get_dirname_basename(filename, &dirc, &basec, &dir_path, &basen)) != 0) {
            goto exit;
        }

        DBG_PRINT("dir_path->%s\n", dir_path);

        abs_dir_path = realpath(dir_path, NULL);

        if (abs_dir_path == NULL) {
            DBG_PRINT("abs_dir_path is NULL for filename->%s\n", filename);
            ret = PFS_REALPATH_API_RETURNED_NULL;
            goto exit;
        }

        DBG_PRINT(
            "Path with orig filename=%s, dir_path=%s, basen=%s, "
            "abs_dir_path=%s\n",
            filename, dir_path, basen, abs_dir_path);

        if ((ret = check_dir_path_prefix(abs_dir_path, path_to_protected_file)) != 0) {
            goto exit;
        }

        DBG_PRINT("path to protected_file = %d\n", *path_to_protected_file);

        if (*path_to_protected_file == true) {
            //+2 for accounting for extra / and null termination.
            *abs_file_path = (char*)calloc(strlen(abs_dir_path) + 1 + strlen(basen) + 1, 1);

            if (*abs_file_path == NULL) {
                ret = PFS_OUT_OF_MEMORY;
                goto exit;
            }

            strncpy(*abs_file_path, abs_dir_path, strlen(abs_dir_path));
            *(*abs_file_path + strlen(abs_dir_path)) = '/';
            strncpy(*abs_file_path + strlen(abs_dir_path) + 1, basen, strlen(basen));

            DBG_PRINT(
                "dir path len=%lu, basename length=%lu, "
                "abs_file_path length=%lu\n",
                strlen(abs_dir_path), strlen(basen), strlen(*abs_file_path));

            DBG_PRINT("dir_path = %s, basename = %s, abs_file_path=%s\n", abs_dir_path, basen,
                      *abs_file_path);
        }

        /* Caller is responsible to free abs_file_path */
    }

exit:

    if (dirc)
        free(dirc);

    if (basec)
        free(basec);

    if (abs_dir_path)
        free(abs_dir_path);

    return ret_val;
}

static FILE* fopen_helper(const char* filename, const char* mode, const char* fopen_api) {
    fopen_f_type fopen_fn;
    char* abs_path              = NULL;
    FILE* fptr                  = NULL;
    int ret_val                 = 0;
    bool path_to_protected_file = 0;

    if (!filename || !mode || !fopen_api) {
        return NULL;
    }

    if ((strncmp(fopen_api, FOPEN_STR, strlen(FOPEN_STR)) != 0) &&
        (strncmp(fopen_api, FOPEN64_STR, strlen(FOPEN64_STR)) != 0)) {
        printf("error, invalid fopen in fopen string=%s\n", fopen_api);
        return NULL;
    } else
        DBG_PRINT("fopen using api->=%s\n", fopen_api);

    ret_val = updated_check_secure_io_path(filename, &abs_path, &path_to_protected_file);

    if (ret_val != 0) {
        printf("error in fopen\n");
        fptr = NULL;
        goto exit;
    }

    if (path_to_protected_file) {
        fopen_fn = sgx_fopen_proxy;
        DBG_PRINT("called sgx_fopen_proxy \n");
    } else {
        fopen_fn = (fopen_f_type)dlsym(RTLD_NEXT, fopen_api);
        DBG_PRINT("called system's fopen, fopen_fn=%p\n", fopen_fn);
    }

    if (path_to_protected_file && (abs_path != NULL)) {
        DBG_PRINT("%s: abspath=%s\n", __func__, abs_path);

        fptr = fopen_fn(abs_path, mode);
    } else {
        fptr = fopen_fn(filename, mode);
    }

exit:

    if (abs_path) {
        free(abs_path);
        abs_path = NULL;
    }

    DBG_PRINT("%s: is it a protected file=%d, filename->%s, fptr=%p\n", __func__,
              path_to_protected_file, filename, fptr);

    return fptr;
}

static int read_sealed_custom_key(uint8_t* sealed_key, uint32_t sealed_key_length) {
    int32_t ret = 0;
    FILE* fp    = NULL;
    size_t read_bytes;

    if (!sealed_key || sealed_key_length == 0)
        return -1;

    fp = fopen_fn_glb(SEALED_BLOB, "rb");

    if (!fp) {
        DBG_PRINT("Failed to read the sealed blob\n");
        return -1;
    }

    read_bytes = fread_fn_glb(sealed_key, 1, sealed_key_length, fp);

    if (read_bytes != sealed_key_length) {
        DBG_PRINT("Failed to read sealed_blob \n");
        ret = -1;
    }

    fclose_fn_glb(fp);

    return ret;
}

static int check_and_unseal_custom_key(sgx_key_128bit_t* sgx_key) {
    int32_t status       = 0;
    uint32_t sealed_size = 0;
    uint8_t* sealed;
    uint32_t plain_size = 0;

    if (!sgx_key)
        return -1;

    // allocate mem for sealed_custom_key;
    sealed_size = sizeof(sgx_sealed_data_t) + sizeof(sgx_key_128bit_t);
    sealed      = (uint8_t*)malloc(sealed_size);
    plain_size  = sizeof(sgx_key_128bit_t);

    if (!sealed) {
        DBG_PRINT("malloc failed\n");
        return -1;
    }

    status = read_sealed_custom_key(sealed, sealed_size);

    if (status != 0) {
        DBG_PRINT("error returned by read_sealed_custom_key, status=%d\n", status);
        free(sealed);
        return status;
    }

    DBG_PRINT(
        "%s:%d, after fetching sealed blob, status= %d, sealed_size=%d, "
        "plain_size=%d\n",
        __func__, __LINE__, status, sealed_size, plain_size);

    status =
        sgx_unseal_data((sgx_sealed_data_t*)sealed, NULL, NULL, (uint8_t*)sgx_key, &plain_size);

    DBG_PRINT("%s:%d, after unsealing, status= %d, plain_size=%d\n", __func__, __LINE__, status,
              plain_size);

    free(sealed);

    return status;
}

static int retreive_custom_key(sgx_key_128bit_t* sgx_key) {
    int32_t status = 0;

    if (!sgx_key)
        return -1;

    status = check_and_unseal_custom_key(sgx_key);

    if (status != 0) {
        DBG_PRINT("error ret by check_and_unseal_custom_key, status = %d\n", status);
        // Note: In this case, auto-key(i.e sealing key) will be used.
    }

    return status;
}

int check_use_of_custom_key() {
    char* use_custom_key = NULL;
    int32_t status       = 0;

    if (checked_use_of_custom_key == 0) {
        use_custom_key = getenv(PFS_USE_CUSTOM_KEY_ENV);

        if (use_custom_key != NULL) {
            if (strncmp(use_custom_key, YES_STRING, strlen(use_custom_key)) == 0) {
                status = retreive_custom_key(&sgx_key_glb);

                if (status == 0)
                    using_custom_key = 1;
                else {
                    DBG_PRINT("error in retrieving custom key\n");
                    using_custom_key = 0;
                }
            } else
                using_custom_key = 0;

            DBG_PRINT("\nuse_custom_key=%s, using_custom_key=%d\n", use_custom_key,
                      using_custom_key);
        } else {
            DBG_PRINT("\nuse_custom_key is NOT set in manifest\n");
        }

        checked_use_of_custom_key = 1;
    }

    return status;
}

static FILE* sgx_fopen_proxy(const char* filename, const char* mode) {
    SGX_FILE* sfp            = NULL;
    char* mnt_path           = NULL;
    char* encrypted_filename = NULL;
    int enc_status           = 0;

#ifndef PFS_PLUS_ENABLED

    if (checked_use_of_custom_key == 0) {
        check_use_of_custom_key();
        checked_use_of_custom_key = 1;
    }

    DBG_PRINT("checked_use_of_custom_key=%d, use_custom=%d\n", checked_use_of_custom_key,
              using_custom_key);

    if (using_custom_key) {
        sfp = sgx_fopen(filename, mode, &sgx_key_glb);
    } else {
        sfp = sgx_fopen(filename, mode, NULL);
    }

#else

    mnt_path = getenv(PFS_MOUNT_POINT_ENV);

    if (mnt_path != NULL)
        DBG_PRINT("\nmnt_path=%s, filename=%s\n", mnt_path, filename);
    else {
        printf("Error, mnt_path=%s is NULL, filename=%s\n", mnt_path, filename);
        return NULL;
    }

    if (volume_metadata_setup_done == 0) {
        volume_metadata_setup_status = volume_metadata_setup(mnt_path);
        volume_metadata_setup_done   = 1;
    }

    DBG_PRINT(
        "\nvolume_metadata_setup_done=%d, volume_metadata_setup_status = %d, "
        "vmc_init=%d, vmc_init_failed=%d, use_custom=%d\n",
        volume_metadata_setup_done, volume_metadata_setup_status, vol_md_init, vol_md_init_failed,
        using_custom_key);

    if (volume_metadata_setup_status != PFS_SUCCESS) {
        printf("can't open protected file, volume md setup status, error=%d\n",
               volume_metadata_setup_status);
        return NULL;
    }

    enc_status = pfs_encrypt_filename(filename, &encrypted_filename);

    if (enc_status != 0) {
        CRITICAL_DBG_PRINT("error ret=%d, from pfs_encrypt_filename\n", enc_status);
        return NULL;
    }

    DBG_PRINT(
        "after, pfs_encrypt_filename, orig-filename=%s, "
        "enc-filename=%s, strlen(enc-filename)=%lu\n",
        filename, encrypted_filename, strlen(encrypted_filename));

    if (using_custom_key) {
        sfp = sgx_fopen(encrypted_filename, mode, &vol_keys_glb.vck);
    } else {
        sfp = sgx_fopen(encrypted_filename, mode, NULL);
    }

    if (encrypted_filename) {
        free(encrypted_filename);
        encrypted_filename = NULL;
    }

#endif  // PFS_PLUS_ENABLED

    DBG_PRINT("sfp=%p\n", (void*)sfp);

    return (FILE*)sfp;
}

static int sgx_fclose_proxy(FILE* stream) {
    int ret_val = 0;

    if (stream == NULL) {
        errno = EINVAL;
        return EOF;
    }

    ret_val = sgx_fclose((SGX_FILE*)stream);

    if (ret_val != 0) {
        DBG_PRINT("error retval=%d\n", ret_val);
    }

    return ret_val;
}

static int sgx_remove_proxy(const char* path) {
    int ret_val = 0;

#ifndef PFS_PLUS_ENABLED

    ret_val = sgx_remove(path);

    if (ret_val != 0) {
        DBG_PRINT("error retval=%d\n", ret_val);
    }

#else

    char* encrypted_filename = NULL;
    int enc_status           = 0;

    enc_status = pfs_encrypt_filename(path, &encrypted_filename);

    if (enc_status != 0) {
        CRITICAL_DBG_PRINT("error ret=%d, from pfs_encrypt_filename\n", enc_status);
        errno = EINVAL;
        return IO_ERROR_RETURN;
    }

    DBG_PRINT(
        "after, pfs_encrypt_filename, orig-filename=%s, "
        "enc-filename=%s, strlen(enc-filename)=%lu\n",
        path, encrypted_filename, strlen(encrypted_filename));

    ret_val = sgx_remove(encrypted_filename);

    if (encrypted_filename) {
        free(encrypted_filename);
        encrypted_filename = NULL;
    }

#endif  // PFS_PLUS_ENABLED

    return ret_val;
}

static size_t sgx_fread_proxy(void* ptr, size_t size, size_t nmemb, FILE* stream) {
    return sgx_fread(ptr, size, nmemb, (SGX_FILE*)stream);
}

static size_t sgx_fwrite_proxy(const void* ptr, size_t size, size_t nmemb, FILE* stream) {
    return sgx_fwrite(ptr, size, nmemb, (SGX_FILE*)stream);
}

static int sgx_fseek_proxy(FILE* stream, long int offset, int whence) {
    return (int)sgx_fseek((SGX_FILE*)stream, offset, whence);
}

static long sgx_ftell_proxy(FILE* stream) {
    return (long)sgx_ftell((SGX_FILE*)stream);
}

static int sgx_fseeko_proxy(FILE* stream, off_t offset, int whence) {
    int64_t offset_val = (int64_t)offset;
    return (int)sgx_fseek((SGX_FILE*)stream, offset_val, whence);
}

static off_t sgx_ftello_proxy(FILE* stream) {
    return (off_t)sgx_ftell((SGX_FILE*)stream);
}

static int sgx_fflush_proxy(FILE* stream) {
    return (int)sgx_fflush((SGX_FILE*)stream);
}

static int sgx_ferror_proxy(FILE* stream) {
    return (int)sgx_ferror((SGX_FILE*)stream);
}

static int sgx_feof_proxy(FILE* stream) {
    return (int)sgx_feof((SGX_FILE*)stream);
}

static void sgx_clearerr_proxy(FILE* stream) {
    return sgx_clearerr((SGX_FILE*)stream);
}

static void sgx_rewind_proxy(FILE* stream) {
    int ret_val;
    // Note: as per man page for ftell
    ret_val = sgx_fseek((SGX_FILE*)stream, 0L, SEEK_SET);

    if (ret_val != 0) {
        DBG_PRINT("sgx_fseek error=%d\n", ret_val);
    }

    sgx_clearerr((SGX_FILE*)stream);
}

static int sgx_getc_proxy(FILE* stream) {
    ssize_t read_bytes = 0;
    char byte_read     = 0;
    int error;

    read_bytes = sgx_fread((void*)&byte_read, sizeof(char), 1, (SGX_FILE*)stream);

    if (read_bytes == 0) {
        error = sgx_ferror((SGX_FILE*)stream);
        DBG_PRINT("read_bytes=%lu, EOF reached, byte_read=%c, error=%d\n", read_bytes, byte_read,
                  error);

        // Note: getc is expected to return EOF, if end-of-file is reached.
        return (int)EOF;
    }

    return (int)byte_read;
}

/* Note: moving the file pointer backwards by 1 byte.
this api works fine. */
static int sgx_ungetc_proxy(int c, FILE* stream) {
    long offset;
    int ret_val;

    offset = sgx_ftell_proxy(stream);

    if (offset > 0) {
        ret_val = sgx_fseek_proxy(stream, offset - 1, SEEK_SET);
    }

    if (offset == 0 || ret_val != 0) {
        DBG_PRINT("error, offset =%lu, ret_val=%d\n", offset, ret_val);
    }

    DBG_PRINT("offset =%lu, c=%c\n", offset, c);

    return (int)c;
}

static int sgx_putc_proxy(int c, FILE* stream) {
    ssize_t nbytes         = 0;
    unsigned char one_byte = 0;
    int error;

    one_byte = (unsigned char)c;

    nbytes = sgx_fwrite((void*)&one_byte, sizeof(char), 1, (SGX_FILE*)stream);

    if (nbytes != 1) {
        error = sgx_ferror((SGX_FILE*)stream);
        DBG_PRINT("error, nbytes=%lu, one_byte=%c, error=%d\n", nbytes, one_byte, error);

        // Note: putc is expected to return EOF, for error cases.
        return (int)EOF;
    }

    return c;
}

/* TODO: currently sgx_flock/unlock apis are stubs.
investigate, if we can add interface to get pfs objects's FILE*,
and then do a lock/unlock using the system's lock/unlock api.*/
static void sgx_flockfile_proxy(FILE* stream) {
    DBG_PRINT("stream=%p\n", (void*)stream);
    return;
}

static void sgx_funlockfile_proxy(FILE* stream) {
    DBG_PRINT("stream=%p\n", (void*)stream);
    return;
}

static int sgx_ftrylockfile_proxy(FILE* stream) {
    DBG_PRINT("stream=%p\n", (void*)stream);
    return 0;
}

/*Note: implemented this api, based on man page for fgets().
Tested within graphene, works fine.
*/
static char* sgx_fgets_proxy(char* s, int size, FILE* stream) {
    ssize_t read_bytes = 0;
    char byte_read     = 0;
    int error;
    int count = 0;

    if (!s || !stream || size == 0) {
        return NULL;
    }

    for (; count < (size - 1);) {
        read_bytes = sgx_fread((void*)&byte_read, sizeof(char), 1, (SGX_FILE*)stream);

        if (read_bytes == 0) {
            error = sgx_ferror((SGX_FILE*)stream);
            DBG_PRINT("read_bytes=%lu, EOF reached, byte_read=%c, error=%d\n", read_bytes,
                      byte_read, error);

            /* Note:fgets() return s on success,and NULL on error or when end
            of file occurs while no characters have been read.*/
            if (count == 0) {
                return NULL;
            } else
                break;
        } else {
            // DBG_PRINT("byte_read=%c\n", byte_read);*/
            s[count++] = byte_read;
            if (byte_read == '\n')
                break;
        }
    }

    // terminate with null character.
    if (count <= (size - 1)) {
        s[count] = '\0';
    }

    return s;
}

int sgx_fputs_proxy(const char* s, FILE* stream) {
    ssize_t written_bytes = 0;
    int error;
    size_t count      = 0;
    size_t str_length = 0;

    if (!s || !stream) {
        return EOF;
    }

    DBG_PRINT("sgx_fputs_proxy");

    str_length = strlen(s);

    if (str_length <= 0)
        return EOF;

    for (count = 0; count < str_length; count++) {
        written_bytes = sgx_fwrite((void*)(((char*)s + count)), sizeof(char), 1, (SGX_FILE*)stream);

        if (written_bytes != 1) {
            error = sgx_ferror((SGX_FILE*)stream);
            DBG_PRINT("error=%d, written_bytes=%lu\n", error, written_bytes);

            return EOF;
        }
    }

    if (count != str_length) {
        DBG_PRINT("error, count=%lu, str_len=%lu\n", count, str_length);
        return EOF;
    }

    // Note: fputs returns 1 for success.
    return 1;
}

/* Note: APIs below are intercepted, and SUPPORTED for protected files*/
FILE* fopen(const char* filename, const char* mode) {
    DBG_PRINT();
    return fopen_helper(filename, mode, FOPEN_STR);
}

size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream) {
    fread_f_type fread_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        fread_fn = sgx_fread_proxy;
    } else {
        fread_fn = (fread_f_type)dlsym(RTLD_NEXT, "fread");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return fread_fn(ptr, size, nmemb, stream);
}

size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream) {
    fwrite_f_type fwrite_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        fwrite_fn = sgx_fwrite_proxy;
    } else {
        fwrite_fn = (fwrite_f_type)dlsym(RTLD_NEXT, "fwrite");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return fwrite_fn(ptr, size, nmemb, stream);
}

int fflush(FILE* stream) {
    fflush_f_type fflush_fn;

    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        fflush_fn = sgx_fflush_proxy;
    } else {
        fflush_fn = (fflush_f_type)dlsym(RTLD_NEXT, "fflush");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return fflush_fn(stream);
}

int fseek(FILE* stream, long int offset, int whence) {
    fseek_f_type fseek_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        fseek_fn = sgx_fseek_proxy;
    } else {
        fseek_fn = (fseek_f_type)dlsym(RTLD_NEXT, "fseek");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return fseek_fn(stream, offset, whence);
}

long ftell(FILE* stream) {
    ftell_f_type ftell_fn;

    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        ftell_fn = sgx_ftell_proxy;
    } else {
        ftell_fn = (ftell_f_type)dlsym(RTLD_NEXT, "ftell");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return ftell_fn(stream);
}

int fseeko(FILE* stream, off_t offset, int whence) {
    fseeko_f_type fseeko_fn;

    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        fseeko_fn = sgx_fseeko_proxy;
    } else {
        fseeko_fn = (fseeko_f_type)dlsym(RTLD_NEXT, "fseeko");
    }

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    return fseeko_fn(stream, offset, whence);
}

off_t ftello(FILE* stream) {
    ftello_f_type ftello_fn;

    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        ftello_fn = sgx_ftello_proxy;
    } else {
        ftello_fn = (ftello_f_type)dlsym(RTLD_NEXT, "ftello");
    }

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    return ftello_fn(stream);
}

void rewind(FILE* stream) {
    rewind_f_type rewind_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        rewind_fn = sgx_rewind_proxy;
    } else {
        rewind_fn = (rewind_f_type)dlsym(RTLD_NEXT, "rewind");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return rewind_fn(stream);
}

int fclose(FILE* stream) {
    fclose_f_type fclose_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        fclose_fn = sgx_fclose_proxy;
    } else {
        fclose_fn = (fclose_f_type)dlsym(RTLD_NEXT, "fclose");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return fclose_fn(stream);
}

int ferror(FILE* stream) {
    ferror_f_type ferror_fn;

    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        ferror_fn = sgx_ferror_proxy;
    } else {
        ferror_fn = (ferror_f_type)dlsym(RTLD_NEXT, "ferror");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return ferror_fn(stream);
}

int feof(FILE* stream) {
    feof_f_type feof_fn;

    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        feof_fn = sgx_feof_proxy;
    } else {
        feof_fn = (feof_f_type)dlsym(RTLD_NEXT, "feof");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return feof_fn(stream);
}

void clearerr(FILE* stream) {
    clearerr_f_type clearerr_fn;

    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        clearerr_fn = sgx_clearerr_proxy;
    } else {
        clearerr_fn = (clearerr_f_type)dlsym(RTLD_NEXT, "clearerr");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return clearerr_fn(stream);
}

int remove(const char* path) {
    remove_f_type remove_fn;
    char* abs_path              = NULL;
    int ret_val                 = 0;
    bool path_to_protected_file = 0;

    if (!path) {
        errno = EINVAL;
        return IO_ERROR_RETURN;
    }

    ret_val = updated_check_secure_io_path(path, &abs_path, &path_to_protected_file);

    if (ret_val != 0) {
        printf("error in %s\n", __func__);
        errno   = EINVAL;
        ret_val = IO_ERROR_RETURN;
        goto exit;
    }

    if (path_to_protected_file) {
        remove_fn = sgx_remove_proxy;
        DBG_PRINT("called sgx_remove_proxy \n");
    } else {
        remove_fn = (remove_f_type)dlsym(RTLD_NEXT, "remove");
        DBG_PRINT("calling system's remove\n");
    }

    if (path_to_protected_file && (abs_path != NULL)) {
        DBG_PRINT("%s: abspath=%s\n", __func__, abs_path);

        ret_val = remove_fn(abs_path);
    } else {
        ret_val = remove_fn(path);
    }

exit:

    if (abs_path) {
        free(abs_path);
        abs_path = NULL;
    }

    return ret_val;
}

/* Note: when python invokes getc, it gets translated to _IO_getc. */
int _IO_getc(FILE* stream) {
    getc_f_type getc_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        getc_fn = sgx_getc_proxy;
    } else {
        getc_fn = (getc_f_type)dlsym(RTLD_NEXT, "_IO_getc");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return getc_fn(stream);
}

int getc(FILE* stream) {
    getc_f_type getc_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        getc_fn = sgx_getc_proxy;
    } else {
        getc_fn = (getc_f_type)dlsym(RTLD_NEXT, "getc");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return getc_fn(stream);
}

int ungetc(int c, FILE* stream) {
    ungetc_f_type ungetc_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        ungetc_fn = sgx_ungetc_proxy;
    } else {
        ungetc_fn = (ungetc_f_type)dlsym(RTLD_NEXT, "ungetc");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return ungetc_fn(c, stream);
}

int fgetc(FILE* stream) {
    return getc(stream);
}

char* fgets(char* s, int size, FILE* stream) {
    fgets_f_type fgets_fn;

    bool pfs_file = false;

    if (!s || !stream || size == 0) {
        return NULL;
    }

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        fgets_fn = sgx_fgets_proxy;
    } else {
        fgets_fn = (fgets_f_type)dlsym(RTLD_NEXT, "fgets");
    }

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    return fgets_fn(s, size, stream);
}

/* as per C standard, putc is
 * implemented as a macro->libio/stdio.h:#define putc(_ch, _fp) _IO_putc (_ch, _fp)
 * so here we need a handler for the actual function used by macro, to intercept.
 */
int _IO_putc(int c, FILE* stream) {
    putc_f_type putc_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        putc_fn = sgx_putc_proxy;
    } else {
        putc_fn = (putc_f_type)dlsym(RTLD_NEXT, "_IO_putc");
    }

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    return putc_fn(c, stream);
}

int fputc(int c, FILE* stream) {
    putc_f_type putc_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        putc_fn = sgx_putc_proxy;
    } else {
        putc_fn = (putc_f_type)dlsym(RTLD_NEXT, "fputc");
    }

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    return putc_fn(c, stream);
}

int fputs(const char* s, FILE* stream) {
    fputs_f_type fputs_fn;

    bool pfs_file = false;

    if (!s || !stream) {
        return EOF;
    }

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        fputs_fn = sgx_fputs_proxy;
    } else {
        fputs_fn = (fputs_f_type)dlsym(RTLD_NEXT, "fputs");
    }

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    return fputs_fn(s, stream);
}

/* Note: APIs below are intercepted, but blocked for protected files */
/* Note: Without the handlers, for fgetpos, fsetpos, there
 is a seg-fault, when protected-file pointer is passed directly to glibC api. */
int fgetpos(FILE* stream, fpos_t* pos) {
    fgetpos_f_type fgetpos_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return -1;
    } else {
        fgetpos_fn = (fgetpos_f_type)dlsym(RTLD_NEXT, "fgetpos");
    }

    return fgetpos_fn(stream, pos);
}

int fsetpos(FILE* stream, const fpos_t* pos) {
    fsetpos_f_type fsetpos_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return -1;
    } else {
        fsetpos_fn = (fsetpos_f_type)dlsym(RTLD_NEXT, "fsetpos");
    }

    return fsetpos_fn(stream, pos);
}

/* Note: Below apis need to be tested...for both protected
 and un-protected files.*/
void setbuf(FILE* stream, char* buf) {
    setbuf_f_type setbuf_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return;
    } else {
        setbuf_fn = (setbuf_f_type)dlsym(RTLD_NEXT, "setbuf");
    }

    return setbuf_fn(stream, buf);
}

void setbuffer(FILE* stream, char* buf, size_t size) {
    setbuffer_f_type setbuffer_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return;
    } else {
        setbuffer_fn = (setbuffer_f_type)dlsym(RTLD_NEXT, "setbuffer");
    }

    return setbuffer_fn(stream, buf, size);
}

void setlinebuf(FILE* stream) {
    setlinebuf_f_type setlinebuf_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return;
    } else {
        setlinebuf_fn = (setlinebuf_f_type)dlsym(RTLD_NEXT, "setlinebuf");
    }

    return setlinebuf_fn(stream);
}

int setvbuf(FILE* stream, char* buf, int mode, size_t size) {
    setvbuf_f_type setvbuf_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return -1;
    } else {
        setvbuf_fn = (setvbuf_f_type)dlsym(RTLD_NEXT, "setvbuf");
    }

    return setvbuf_fn(stream, buf, mode, size);
}

int rename(const char* oldpath, const char* newpath) {
    rename_f_type rename_fn;

    if (check_secure_io_path(oldpath)) {
        DBG_PRINT("%s NOT allowed for secure file->%s\n", __func__, oldpath);
        errno = EACCES;
        return -1;
    }

    if (check_secure_io_path(newpath)) {
        DBG_PRINT("%s NOT allowed for secure file->%s\n", __func__, newpath);
        errno = EACCES;
        return -1;
    }

    DBG_PRINT("invoking glib C api->%s\n", __func__);

    rename_fn = (rename_f_type)dlsym(RTLD_NEXT, "rename");

    return rename_fn(oldpath, newpath);
}

int renameat(int olddirfd, const char* oldpath, int newdirfd, const char* newpath) {
    renameat_f_type renameat_fn;

    if (check_secure_io_path(oldpath)) {
        DBG_PRINT("%s NOT allowed for secure file->%s\n", __func__, oldpath);
        errno = EACCES;
        return -1;
    }

    if (check_secure_io_path(newpath)) {
        DBG_PRINT("%s NOT allowed for secure file->%s\n", __func__, newpath);
        errno = EACCES;
        return -1;
    }

    DBG_PRINT("invoking glib C api->%s\n", __func__);

    renameat_fn = (renameat_f_type)dlsym(RTLD_NEXT, "renameat");

    return renameat_fn(olddirfd, oldpath, newdirfd, newpath);
}

int fileno(FILE* stream) {
    fileno_f_type fileno_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return -1;
    } else {
        fileno_fn = (fileno_f_type)dlsym(RTLD_NEXT, "fileno");
    }

    return fileno_fn(stream);
}

FILE* freopen(const char* path, const char* mode, FILE* stream) {
    freopen_f_type freopen_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return NULL;
    } else {
        freopen_fn = (freopen_f_type)dlsym(RTLD_NEXT, "freopen");
    }

    return freopen_fn(path, mode, stream);
}

int truncate(const char* path, off_t length) {
    truncate_f_type truncate_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)path);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (check_secure_io_path(path)) {
        DBG_PRINT("%s NOT allowed for secure files.\n", __func__);
        errno = EACCES;
        return -1;
    } else {
        truncate_fn = (truncate_f_type)dlsym(RTLD_NEXT, __func__);
    }

    return truncate_fn(path, length);
}

/*
Note: As per http://c-faq.com/varargs/handoff.html, it
is NOT feasible, to intercept fscanf, and call system's fscanf,
since fscanf does NOT accept va_list.
So the alternative(similar to what glibc does), is to
invoke their v-variants
int fprintf(FILE *stream, const char *format, ...)
int fscanf(FILE *stream, const char *format, ...)
int fwscanf(FILE * stream, const wchar_t * format, ...)
int fwprintf(FILE * stream, const wchar_t * format, ...)
*/

int fprintf(FILE* stream, const char* format, ...) {
    vfprintf_f_type vfprintf_fn;
    bool pfs_file = false;
    int ret       = 0;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return EOF;
    } else {
        va_list argp;
        va_start(argp, format);
        vfprintf_fn = (vfprintf_f_type)dlsym(RTLD_NEXT, "vfprintf");
        ret         = vfprintf_fn(stream, format, argp);
        va_end(argp);
        return ret;
    }
}

int fscanf(FILE* stream, const char* format, ...) {
    vfscanf_f_type vfscanf_fn;
    bool pfs_file = false;
    int ret       = 0;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return EOF;
    } else {
        va_list argp;
        va_start(argp, format);
        vfscanf_fn = (vfscanf_f_type)dlsym(RTLD_NEXT, "vfscanf");
        ret        = vfscanf_fn(stream, format, argp);
        va_end(argp);
        return ret;
    }
}

int fwprintf(FILE* stream, const wchar_t* format, ...) {
    vfwprintf_f_type vfwprintf_fn;
    bool pfs_file = false;
    int ret       = 0;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return EOF;
    } else {
        va_list argp;
        va_start(argp, format);
        vfwprintf_fn = (vfwprintf_f_type)dlsym(RTLD_NEXT, "vfwprintf");
        ret          = vfwprintf_fn(stream, format, argp);
        va_end(argp);
        return ret;
    }
}

int fwscanf(FILE* stream, const wchar_t* format, ...) {
    vfwscanf_f_type vfwscanf_fn;
    bool pfs_file = false;
    int ret       = 0;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return EOF;
    } else {
        va_list argp;
        va_start(argp, format);
        vfwscanf_fn = (vfwscanf_f_type)dlsym(RTLD_NEXT, "vfwscanf");
        ret         = vfwscanf_fn(stream, format, argp);
        va_end(argp);
        return ret;
    }
}

int vfscanf(FILE* stream, const char* format, va_list ap) {
    vfscanf_f_type vfscanf_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return EOF;
    } else {
        vfscanf_fn = (vfscanf_f_type)dlsym(RTLD_NEXT, "vfscanf");
    }

    return vfscanf_fn(stream, format, ap);
}

int vfprintf(FILE* stream, const char* format, va_list ap) {
    vfprintf_f_type vfprintf_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return EOF;
    } else {
        vfprintf_fn = (vfprintf_f_type)dlsym(RTLD_NEXT, "vfprintf");
    }

    return vfprintf_fn(stream, format, ap);
}

/* Note: APIs below(wide-char apis) are intercepted, and Blocked for protected files*/
wint_t fgetwc(FILE* stream) {
    fgetwc_f_type fgetwc_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return WEOF;
    } else {
        fgetwc_fn = (fgetwc_f_type)dlsym(RTLD_NEXT, "fgetwc");
    }

    return fgetwc_fn(stream);
}

wint_t getwc(FILE* stream) {
    return fgetwc(stream);
}

wchar_t* fgetws(wchar_t* ws, int n, FILE* stream) {
    fgetws_f_type fgetws_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return NULL;
    } else {
        fgetws_fn = (fgetws_f_type)dlsym(RTLD_NEXT, "fgetws");
    }

    return fgetws_fn(ws, n, stream);
}

wint_t ungetwc(wint_t wc, FILE* stream) {
    ungetwc_f_type ungetwc_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return WEOF;
    } else {
        ungetwc_fn = (ungetwc_f_type)dlsym(RTLD_NEXT, "ungetwc");
    }

    return ungetwc_fn(wc, stream);
}

wint_t fputwc(wchar_t wc, FILE* stream) {
    fputwc_f_type fputwc_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return WEOF;
    } else {
        fputwc_fn = (fputwc_f_type)dlsym(RTLD_NEXT, "fputwc");
    }

    return fputwc_fn(wc, stream);
}

wint_t putwc(wchar_t wc, FILE* stream) {
    return fputwc(wc, stream);
}

int fputws(const wchar_t* ws, FILE* stream) {
    fputws_f_type fputws_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return WEOF;
    } else {
        fputws_fn = (fputws_f_type)dlsym(RTLD_NEXT, "fputws");
    }

    return fputws_fn(ws, stream);
}

int vfwscanf(FILE* stream, const wchar_t* format, va_list arg) {
    vfwscanf_f_type vfwscanf_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return EOF;
    } else {
        vfwscanf_fn = (vfwscanf_f_type)dlsym(RTLD_NEXT, "vfwscanf");
    }

    return vfwscanf_fn(stream, format, arg);
}

int vfwprintf(FILE* stream, const wchar_t* format, va_list arg) {
    vfwprintf_f_type vfwprintf_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return EOF;
    } else {
        vfwprintf_fn = (vfwprintf_f_type)dlsym(RTLD_NEXT, "vfwprintf");
    }

    return vfwprintf_fn(stream, format, arg);
}

int fwide(FILE* stream, int mode) {
    fwide_f_type fwide_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return 0;
    } else {
        fwide_fn = (fwide_f_type)dlsym(RTLD_NEXT, "fwide");
    }

    return fwide_fn(stream, mode);
}

/* Note: Adding support to over-load 64-bit apis: */
FILE* fopen64(const char* filename, const char* mode) {
    DBG_PRINT();
    return fopen_helper(filename, mode, FOPEN64_STR);
}

int fseeko64(FILE* stream, off64_t offset, int whence) {
    fseeko64_f_type fseeko64_fn;

    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        fseeko64_fn = sgx_fseeko_proxy;
    } else {
        fseeko64_fn = (fseeko64_f_type)dlsym(RTLD_NEXT, "fseeko64");
    }

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    return fseeko64_fn(stream, offset, whence);
}

off64_t ftello64(FILE* stream) {
    ftello64_f_type ftello64_fn;

    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        ftello64_fn = sgx_ftello_proxy;
    } else {
        ftello64_fn = (ftello64_f_type)dlsym(RTLD_NEXT, "ftello64");
    }

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    return ftello64_fn(stream);
}

FILE* freopen64(const char* path, const char* mode, FILE* stream) {
    freopen_f_type freopen_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return NULL;
    } else {
        freopen_fn = (freopen_f_type)dlsym(RTLD_NEXT, "freopen64");
    }

    return freopen_fn(path, mode, stream);
}

int fgetpos64(FILE* stream, fpos64_t* pos) {
    fgetpos64_f_type fgetpos64_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return -1;
    } else {
        fgetpos64_fn = (fgetpos64_f_type)dlsym(RTLD_NEXT, "fgetpos64");
    }

    return fgetpos64_fn(stream, pos);
}

int fsetpos64(FILE* stream, const fpos64_t* pos) {
    fsetpos64_f_type fsetpos64_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    DBG_PRINT("%s, pfs_file=%d\n", __func__, pfs_file);

    if (pfs_file) {
        DBG_ERRNO_HELPER(__func__);
        return -1;
    } else {
        fsetpos64_fn = (fsetpos64_f_type)dlsym(RTLD_NEXT, "fsetpos64");
    }

    return fsetpos64_fn(stream, pos);
}

/* Note: APIs below(which return file-descriptors) are intercepted, and Blocked for protected
 * files*/
int creat(const char* filename, mode_t mode) {
    creat_f_type creat_fn;

    if (!filename) {
        errno = EINVAL;
        return -1;
    }

    if (check_secure_io_path(filename)) {
        DBG_ERRNO_HELPER(__func__);
        return -1;
    } else {
        creat_fn = (creat_f_type)dlsym(RTLD_NEXT, "creat");
        DBG_PRINT("calling system's creat, creat_fn=%p\n", creat_fn);
    }

    return creat_fn(filename, mode);
}

/* Note: retreiving mode, only for case where flags has O_CREAT
or O_TMPFILE, similar to how glibc handles it*/
int open(const char* filename, int flags, ...) {
    open_f_type open_fn;
    int mode = 0;

    if (!filename) {
        errno = EINVAL;
        return -1;
    }

    if (check_secure_io_path(filename)) {
        DBG_ERRNO_HELPER(__func__);
        return -1;
    }

    open_fn = (open_f_type)dlsym(RTLD_NEXT, "open");

    DBG_PRINT("calling system's open, open_fn=%p\n", open_fn);

    if (IS_MODE_ARG_REQUIRED(flags)) {
        va_list arg;
        va_start(arg, flags);
        mode = va_arg(arg, int);
        va_end(arg);
        DBG_PRINT("in %s, flags = %d, mode=%d\n", __func__, flags, mode);
    }

    return open_fn(filename, flags, mode);
}

int openat(int dirfd, const char* filename, int flags, ...) {
    openat_f_type openat_fn;
    int mode = 0;

    if (!filename) {
        errno = EINVAL;
        return -1;
    }

    if (check_secure_io_path(filename)) {
        DBG_ERRNO_HELPER(__func__);
        return -1;
    }

    openat_fn = (openat_f_type)dlsym(RTLD_NEXT, "openat");

    DBG_PRINT("calling system's openat, openat_fn=%p\n", openat_fn);

    if (IS_MODE_ARG_REQUIRED(flags)) {
        va_list arg;
        va_start(arg, flags);
        mode = va_arg(arg, int);
        va_end(arg);
        DBG_PRINT("in %s, flags = %d, mode=%d\n", __func__, flags, mode);
    }

    return openat_fn(dirfd, filename, flags, mode);
}

int creat64(const char* filename, mode_t mode) {
    creat_f_type creat_fn;

    if (!filename) {
        errno = EINVAL;
        return -1;
    }

    if (check_secure_io_path(filename)) {
        DBG_ERRNO_HELPER(__func__);
        return -1;
    } else {
        creat_fn = (creat_f_type)dlsym(RTLD_NEXT, "creat64");
        DBG_PRINT("calling system's creat, creat_fn=%p\n", creat_fn);
    }

    return creat_fn(filename, mode);
}

/* Note: retreiving mode, only for case where flags has O_CREAT
or O_TMPFILE, similar to how glibc handles it*/
int open64(const char* filename, int flags, ...) {
    open_f_type open_fn;
    int mode = 0;

    if (!filename) {
        errno = EINVAL;
        return -1;
    }

    if (check_secure_io_path(filename)) {
        DBG_ERRNO_HELPER(__func__);
        return -1;
    }

    open_fn = (open_f_type)dlsym(RTLD_NEXT, "open64");

    DBG_PRINT("calling system's open, open_fn=%p\n", open_fn);

    if (IS_MODE_ARG_REQUIRED(flags)) {
        va_list arg;
        va_start(arg, flags);
        mode = va_arg(arg, int);
        va_end(arg);
        DBG_PRINT("in %s, flags = %d, mode=%d\n", __func__, flags, mode);
    }

    return open_fn(filename, flags, mode);
}

int openat64(int dirfd, const char* filename, int flags, ...) {
    openat_f_type openat_fn;
    int mode = 0;

    if (!filename) {
        errno = EINVAL;
        return -1;
    }

    if (check_secure_io_path(filename)) {
        DBG_ERRNO_HELPER(__func__);
        return -1;
    }

    openat_fn = (openat_f_type)dlsym(RTLD_NEXT, "openat64");

    DBG_PRINT("calling system's openat, openat_fn=%p\n", openat_fn);

    if (IS_MODE_ARG_REQUIRED(flags)) {
        va_list arg;
        va_start(arg, flags);
        mode = va_arg(arg, int);
        va_end(arg);
        DBG_PRINT("in %s, flags = %d, mode=%d\n", __func__, flags, mode);
    }

    return openat_fn(dirfd, filename, flags, mode);
}

/* Note: APIs below are intercepted, and its a no-op for protected files*/
/* Note: for python usage, ftrylockfile, flockfile, funlockfile, were needed
initially. Not neeed now, keeping it for reference */
int ftrylockfile(FILE* stream) {
    ftrylockfile_f_type ftrylockfile_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        ftrylockfile_fn = sgx_ftrylockfile_proxy;
    } else {
        ftrylockfile_fn = (ftrylockfile_f_type)dlsym(RTLD_NEXT, "ftrylockfile");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return ftrylockfile_fn(stream);
}

void flockfile(FILE* stream) {
    flockfile_f_type flockfile_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        flockfile_fn = sgx_flockfile_proxy;
    } else {
        flockfile_fn = (flockfile_f_type)dlsym(RTLD_NEXT, "flockfile");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return flockfile_fn(stream);
}

void funlockfile(FILE* stream) {
    funlockfile_f_type funlockfile_fn;
    bool pfs_file = false;

    pfs_file = check_if_pfs_file((void*)stream);

    if (pfs_file) {
        funlockfile_fn = sgx_funlockfile_proxy;
    } else {
        funlockfile_fn = (funlockfile_f_type)dlsym(RTLD_NEXT, "funlockfile");
    }

    DBG_PRINT("pfs_file=%d\n", pfs_file);

    return funlockfile_fn(stream);
}
