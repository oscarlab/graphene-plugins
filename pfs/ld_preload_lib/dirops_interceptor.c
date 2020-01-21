/*
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
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "fileops_typedefs.h"

#include "dirops_typedefs.h"

#include "pfs_plus.h"

#include <stdbool.h>

#define DBG_ERRNO_HELPER(func)                                         \
    {                                                                  \
        DBG_PRINT("%s NOT supported for protected directory\n", func); \
        errno = ENOTSUP;                                               \
    }

static int check_secure_io_dir_path(const char* dirname, char** abs_dir_path,
                                    bool* path_to_protected_file);

static int alloc_and_init_pfs_dir(pfs_dir_t** pfs_dir, char* dir_path, DIR* open_dir_ptr);

static int check_secure_io_dir_path(const char* dirname, char** abs_dir_path,
                                    bool* path_to_protected_file) {
    int ret = 0;

    if (!dirname || !abs_dir_path || !path_to_protected_file) {
        return -1;
    }

    // check if path is absolute or relative path
    if (dirname[0] == '/') {
        DBG_PRINT("absolute path, dir-name=%s\n", dirname);

        /*Note: to check for allowed path, dirname, needs to have secure-io
        directory path, set in the application’s manifest */
        if ((ret = check_dir_path_prefix((char*)dirname, path_to_protected_file)) != 0) {
            goto exit;
        }

        DBG_PRINT("path_to_protected_file=%d\n", *path_to_protected_file);

        return 0;
    } else {
        DBG_PRINT("relative dirname =%s\n", dirname);

        *abs_dir_path = realpath(dirname, NULL);

        if (*abs_dir_path == NULL) {
            DBG_PRINT("abs_dir_path is NULL for dirpath->%s\n", dirname);
            ret = PFS_REALPATH_API_RETURNED_NULL;
            goto exit;
        }

        DBG_PRINT("Path with orig dirname=%s, abs_dir_path=%s\n", dirname, *abs_dir_path);

        if ((ret = check_dir_path_prefix(*abs_dir_path, path_to_protected_file)) != 0) {
            goto exit;
        }

        DBG_PRINT("path to protected_file = %d\n", *path_to_protected_file);

        /* Caller is responsible to free abs_dir_path */
    }

exit:

    return ret;
}

static int check_pfs_dir_object(DIR* dir_ptr, bool* pfs_dir_object) {
    pfs_dir_t* pfs_dir = NULL;

    if (!dir_ptr || !pfs_dir_object) {
        return PFS_INVALID_PARAM;
    }

    pfs_dir = (pfs_dir_t*)dir_ptr;

    if (pfs_dir->dir_id == PFS_DIR_ID) {
        DBG_PRINT("pfs dir ptr");
        *pfs_dir_object = 1;
    } else {
        *pfs_dir_object = 0;
    }

    return 0;
}

static int alloc_and_init_pfs_dir(pfs_dir_t** pfs_dir, char* dir_path, DIR* open_dir_ptr) {
    int ret                 = 0;
    pfs_dir_t* dupe_pfs_dir = NULL;
    int dir_path_len        = 0;

    if (!pfs_dir || !dir_path || !open_dir_ptr) {
        return PFS_INVALID_PARAM;
    }

    dir_path_len = strlen(dir_path);

    if ((dir_path_len + 1) > MAX_DIR_PATH)
        return PFS_DIRPATH_TOO_LONG;

    *pfs_dir = (pfs_dir_t*)calloc(sizeof(pfs_dir_t), 1);

    dupe_pfs_dir = *pfs_dir;

    if (!(dupe_pfs_dir)) {
        DBG_PRINT("out of memory\n");
        ret = PFS_OUT_OF_MEMORY;
        goto exit;
    }

    dupe_pfs_dir->dir_id = PFS_DIR_ID;

    dupe_pfs_dir->dir_path = (uint8_t*)calloc(dir_path_len + 1, 1);

    if (!(dupe_pfs_dir->dir_path)) {
        DBG_PRINT("out of memory\n");
        ret = PFS_OUT_OF_MEMORY;
        goto exit;
    }

    memcpy(dupe_pfs_dir->dir_path, dir_path, dir_path_len);

    dupe_pfs_dir->dir_ptr = (DIR*)open_dir_ptr;

exit:

    if (ret != 0) {
        if (dupe_pfs_dir) {
            if (dupe_pfs_dir->dir_path) {
                free(dupe_pfs_dir->dir_path);
                dupe_pfs_dir->dir_path = NULL;
            }
            free(dupe_pfs_dir);
            dupe_pfs_dir = NULL;
        }
    }

    return ret;
}

static void free_pfs_dir(pfs_dir_t* pfs_dir) {
    if (!pfs_dir) {
        return;
    }

    if (pfs_dir->dir_path) {
        free(pfs_dir->dir_path);
        pfs_dir->dir_path = NULL;
    }

    free(pfs_dir);
    pfs_dir = NULL;

    return;
}

/* Note: The only fields in the dirent structure that are mandated
 * by POSIX.1 are: d_name[], of unspecified size. This api expects
 * struct dirent to have a fixed buf of 256 for d_name. currently
 * not supporting the case, where the underlying C library can use
 * malloc..to allocate dname buf. */
static int decrypt_filename_wrapper(char* dir_path, struct dirent* entry,
                                    struct dirent64* entry64) {
    int ret                  = 0;
    char* decrypted_filename = NULL;
    int dec_len              = 0;
    char* filename           = NULL;

    if (!dir_path) {
        return PFS_INVALID_PARAM;
    }

    // only one entry or entry64 expected to be NON-NULL.
    if ((!entry && !entry64) || (entry && entry64)) {
        return PFS_INVALID_PARAM;
    }

    if (entry) {
        /*TODO: may have to change this to macro using 255 */
        if (sizeof(entry->d_name) < PFS_ENCODED_FILENAME_MAX_LENGTH) {
            return PFS_DIRENTRY_STRUCT_DNAME_BUF_NOT_STATIC;
        }

        filename = entry->d_name;
    } else {
        if (sizeof(entry64->d_name) < PFS_ENCODED_FILENAME_MAX_LENGTH) {
            return PFS_DIRENTRY_STRUCT_DNAME_BUF_NOT_STATIC;
        }

        filename = entry64->d_name;
    }

    DBG_PRINT("abs dir_path=%s, d_name->%s\n", dir_path, filename);

    ret = pfs_decrypt_filename(dir_path, filename, &decrypted_filename);

    if (ret != 0) {
        DBG_PRINT("error ret=%d, from pfs_decrypt_filename\n", ret);
        goto exit;
    }

    dec_len = strlen(decrypted_filename);

    DBG_PRINT("decrypted_name->%s, strlen->%lu\n", decrypted_filename, dec_len);

    if ((dec_len + 1) > PFS_ENCODED_FILENAME_MAX_LENGTH) {
        ret = PFS_DECRYPTED_NAME_TOO_LONG;
        goto exit;
    }

    strncpy(filename, decrypted_filename, dec_len);
    filename[dec_len] = '\0';

    DBG_PRINT("updated decrypted_name in dentry->%s, strlen->%lu\n", filename, strlen(filename));

exit:

    if (decrypted_filename) {
        free(decrypted_filename);
    }

    return ret;
}

/*Note: Currently we do NOT support encryption for directory-names.*/
DIR* opendir(const char* dirname) {
    int ret = 0;

    opendir_f_type opendir_fn;
    closedir_f_type closedir_fn;

    DIR* open_dir_ptr  = NULL;
    pfs_dir_t* pfs_dir = NULL;
    void* dir_ptr_ret  = NULL;

    char* abs_dir_path          = NULL;
    bool path_to_protected_file = 0;

    char* dir_path      = NULL;
    size_t dir_path_len = 0;

    DBG_PRINT("absolute (or) relative dir_path=%s, strlen=%lu\n", dirname, strlen(dirname));

    opendir_fn  = (opendir_f_type)dlsym(RTLD_NEXT, "opendir");
    closedir_fn = (closedir_f_type)dlsym(RTLD_NEXT, "closedir");

    // check if name has path to secure_io_directory...
    ret = check_secure_io_dir_path(dirname, &abs_dir_path, &path_to_protected_file);

    if (ret != 0) {
        DBG_PRINT("error %d, from check_secure_io_dir_path\n", ret);
        dir_ptr_ret = NULL;
        goto exit;
    }

    if (abs_dir_path) {
        dir_path = abs_dir_path;
    } else {
        dir_path = (char*)dirname;
    }

    dir_path_len = strlen(dir_path);

    DBG_PRINT("absolute dir-path=%s, strlen=%lu\n", dir_path, dir_path_len);

    // TODO: For code readability, add pfs_opendir, and move the code
    // related to protected directory.
    if (path_to_protected_file) {
        // check only if file is under protected directory.
        if ((dir_path_len + 1) > MAX_DIR_PATH) {
            dir_ptr_ret = NULL;
            goto exit;
        }
    }

    open_dir_ptr = opendir_fn(dir_path);

    if (!open_dir_ptr) {
        dir_ptr_ret = NULL;
        goto exit;
    } else {
        dir_ptr_ret = (void*)open_dir_ptr;
    }

    if (path_to_protected_file) {
        ret = alloc_and_init_pfs_dir(&pfs_dir, dir_path, open_dir_ptr);

        if (ret != 0) {
            dir_ptr_ret = NULL;
            goto exit;
        }

        dir_ptr_ret = (pfs_dir_t*)pfs_dir;

        DBG_PRINT("PFS DIR ptr=0x%p, open_dir_ptr=0x%p\n", dir_ptr_ret, open_dir_ptr);
    }

exit:

    // closedir..in case where we encounter error..with valid open_dir_ptr.
    if (dir_ptr_ret == NULL) {
        if (open_dir_ptr != NULL) {
            closedir_fn(open_dir_ptr);
        }

        if (pfs_dir != NULL) {
            free_pfs_dir(pfs_dir);
        }
    }

    if (abs_dir_path) {
        free(abs_dir_path);
    }

    DBG_PRINT("DIR ptr=0x%p\n", dir_ptr_ret);

    return (DIR*)dir_ptr_ret;
}

int closedir(DIR* dirp) {
    closedir_f_type closedir_fn;
    bool pfs_dir_obj   = 0;
    pfs_dir_t* pfs_dir = NULL;
    int ret            = 0;

    DBG_PRINT("DIR ptr=0x%p\n", dirp);

    closedir_fn = (closedir_f_type)dlsym(RTLD_NEXT, "closedir");

    if ((ret = check_pfs_dir_object(dirp, &pfs_dir_obj)) != 0) {
        return -1;
    }

    // TODO: For code readability, add pfs_closedir, and move the code
    // related to protected directory.
    if (pfs_dir_obj) {
        pfs_dir = (pfs_dir_t*)dirp;

        DBG_PRINT("PFS dirpath=%s, open DIR ptr=0x%p\n", pfs_dir->dir_path, pfs_dir->dir_ptr);

        ret = closedir_fn(pfs_dir->dir_ptr);

        // note:allocated during opendir call, freed in closedir call.
        free_pfs_dir(pfs_dir);
    } else {
        ret = closedir_fn(dirp);
    }

    return ret;
}

struct dirent* readdir(DIR* dirp) {
    readdir_f_type readdir_fn;
    bool pfs_dir_obj     = 0;
    pfs_dir_t* pfs_dir   = NULL;
    int ret              = 0;
    struct dirent* entry = NULL;

    DBG_PRINT("%s:%d: DIR ptr=0x%p\n", __func__, __LINE__, dirp);

    readdir_fn = (readdir_f_type)dlsym(RTLD_NEXT, "readdir");

    if ((ret = check_pfs_dir_object(dirp, &pfs_dir_obj)) != 0) {
        return NULL;
    }

    if (pfs_dir_obj) {
        pfs_dir = (pfs_dir_t*)dirp;

        DBG_PRINT("PFS dirpath=%s, open DIR ptr=0x%p\n", pfs_dir->dir_path, pfs_dir->dir_ptr);

        entry = readdir_fn(pfs_dir->dir_ptr);

        if (entry) {
            // filename encryption not supported for directories.
            if (entry->d_type != DT_DIR) {
                decrypt_filename_wrapper((char*)pfs_dir->dir_path, entry, NULL);
            }
        }
    } else {
        entry = readdir_fn(dirp);
    }

    return entry;
}

struct dirent64* readdir64(DIR* dirp) {
    readdir64_f_type readdir64_fn;
    bool pfs_dir_obj       = 0;
    pfs_dir_t* pfs_dir     = NULL;
    int ret                = 0;
    struct dirent64* entry = NULL;

    DBG_PRINT("%s:%d: DIR ptr=0x%p\n", __func__, __LINE__, dirp);

    readdir64_fn = (readdir64_f_type)dlsym(RTLD_NEXT, "readdir64");

    if ((ret = check_pfs_dir_object(dirp, &pfs_dir_obj)) != 0) {
        return NULL;
    }

    if (pfs_dir_obj) {
        pfs_dir = (pfs_dir_t*)dirp;

        DBG_PRINT("PFS dirpath=%s, open DIR ptr=0x%p\n", pfs_dir->dir_path, pfs_dir->dir_ptr);

        entry = readdir64_fn(pfs_dir->dir_ptr);

        if (entry) {
            // filename encryption not supported for directories.
            if (entry->d_type != DT_DIR) {
                decrypt_filename_wrapper((char*)pfs_dir->dir_path, NULL, entry);
            }
        }
    } else {
        entry = readdir64_fn(dirp);
    }

    return entry;
}

int readdir_r(DIR* dirp, struct dirent* entry, struct dirent** result) {
    readdir_r_f_type readdir_r_fn;
    bool pfs_dir_obj = 0;
    int ret          = 0;

    DBG_PRINT("DIR ptr=0x%p\n", dirp);

    readdir_r_fn = (readdir_r_f_type)dlsym(RTLD_NEXT, "readdir_r");

    if ((ret = check_pfs_dir_object(dirp, &pfs_dir_obj)) != 0) {
        return EBADF;
    }

    if (pfs_dir_obj) {
        DBG_ERRNO_HELPER(__func__);
        return EBADF;
    } else {
        ret = readdir_r_fn(dirp, entry, result);
    }

    return ret;
}

int readdir64_r(DIR* dirp, struct dirent64* entry, struct dirent64** result) {
    readdir64_r_f_type readdir64_r_fn;
    bool pfs_dir_obj = 0;
    int ret          = 0;

    DBG_PRINT("DIR ptr=0x%p\n", dirp);

    readdir64_r_fn = (readdir64_r_f_type)dlsym(RTLD_NEXT, "readdir64_r");

    if ((ret = check_pfs_dir_object(dirp, &pfs_dir_obj)) != 0) {
        return EBADF;
    }

    if (pfs_dir_obj) {
        DBG_ERRNO_HELPER(__func__);
        return EBADF;
    } else {
        ret = readdir64_r_fn(dirp, entry, result);
    }

    return ret;
}

void rewinddir(DIR* dirp) {
    rewinddir_f_type rewinddir_fn;
    bool pfs_dir_obj   = 0;
    pfs_dir_t* pfs_dir = NULL;
    int ret            = 0;

    DBG_PRINT("DIR ptr=0x%p\n", dirp);

    rewinddir_fn = (rewinddir_f_type)dlsym(RTLD_NEXT, "rewinddir");

    if ((ret = check_pfs_dir_object(dirp, &pfs_dir_obj)) != 0) {
        return;
    }

    if (pfs_dir_obj) {
        pfs_dir = (pfs_dir_t*)dirp;

        DBG_PRINT("PFS dirpath=%s, open DIR ptr=0x%p\n", pfs_dir->dir_path, pfs_dir->dir_ptr);

        rewinddir_fn(pfs_dir->dir_ptr);
    } else {
        rewinddir_fn(dirp);
    }

    return;
}

void seekdir(DIR* dirp, long int pos) {
    seekdir_f_type seekdir_fn;
    bool pfs_dir_obj   = 0;
    pfs_dir_t* pfs_dir = NULL;
    int ret            = 0;

    DBG_PRINT("DIR ptr=0x%p\n", dirp);

    seekdir_fn = (seekdir_f_type)dlsym(RTLD_NEXT, "seekdir");

    if ((ret = check_pfs_dir_object(dirp, &pfs_dir_obj)) != 0) {
        return;
    }

    if (pfs_dir_obj) {
        pfs_dir = (pfs_dir_t*)dirp;

        DBG_PRINT("PFS dirpath=%s, open DIR ptr=0x%p\n", pfs_dir->dir_path, pfs_dir->dir_ptr);

        seekdir_fn(pfs_dir->dir_ptr, pos);
    } else {
        seekdir_fn(dirp, pos);
    }

    return;
}

long int telldir(DIR* dirp) {
    telldir_f_type telldir_fn;
    bool pfs_dir_obj   = 0;
    pfs_dir_t* pfs_dir = NULL;
    int ret            = 0;

    DBG_PRINT("DIR ptr=0x%p\n", dirp);

    telldir_fn = (telldir_f_type)dlsym(RTLD_NEXT, "telldir");

    if ((ret = check_pfs_dir_object(dirp, &pfs_dir_obj)) != 0) {
        return -1;
    }

    if (pfs_dir_obj) {
        pfs_dir = (pfs_dir_t*)dirp;

        DBG_PRINT("PFS dirpath=%s, open DIR ptr=0x%p\n", pfs_dir->dir_path, pfs_dir->dir_ptr);

        return telldir_fn(pfs_dir->dir_ptr);
    } else {
        return telldir_fn(dirp);
    }
}

int scandir(const char* dirp, struct dirent*** namelist, int (*filter)(const struct dirent*),
            int (*compar)(const struct dirent**, const struct dirent**)) {
    scandir_f_type scandir_fn;
    int ret = 0;

    char* abs_dir_path          = NULL;
    bool path_to_protected_file = 0;

    char* dir_path = NULL;

    DBG_PRINT("DIR ptr=0x%p\n", dirp);

    scandir_fn = (scandir_f_type)dlsym(RTLD_NEXT, "scandir");

    // check if name has path to secure_io_directory...
    ret = check_secure_io_dir_path(dirp, &abs_dir_path, &path_to_protected_file);

    if (ret != 0) {
        DBG_PRINT("error %d, from check_secure_io_dir_path\n", ret);
        ret = -1;
        goto exit;
    }

    if (abs_dir_path) {
        dir_path = abs_dir_path;
    } else {
        dir_path = (char*)dirp;
    }

    DBG_PRINT("absolute dir-path=%s, strlen=%lu\n", dir_path, strlen(dir_path));

    if (path_to_protected_file) {
        DBG_ERRNO_HELPER(__func__);
        ret = -1;
        goto exit;
    }

    ret = scandir_fn(dirp, namelist, filter, compar);

exit:

    if (abs_dir_path) {
        free(abs_dir_path);
    }

    return ret;
}

int scandirat(int dirfd, const char* dirp, struct dirent*** namelist,
              int (*filter)(const struct dirent*),
              int (*compar)(const struct dirent**, const struct dirent**)) {
    scandirat_f_type scandirat_fn;
    int ret = 0;

    char* abs_dir_path          = NULL;
    bool path_to_protected_file = 0;

    char* dir_path = NULL;

    DBG_PRINT("DIR ptr=0x%p\n", dirp);

    scandirat_fn = (scandirat_f_type)dlsym(RTLD_NEXT, "scandirat");

    // check if name has path to secure_io_directory...
    ret = check_secure_io_dir_path(dirp, &abs_dir_path, &path_to_protected_file);

    if (ret != 0) {
        DBG_PRINT("error %d, from check_secure_io_dir_path\n", ret);
        ret = -1;
        goto exit;
    }

    if (abs_dir_path) {
        dir_path = abs_dir_path;
    } else {
        dir_path = (char*)dirp;
    }

    DBG_PRINT("absolute dir-path=%s, strlen=%lu\n", dir_path, strlen(dir_path));

    if (path_to_protected_file) {
        DBG_ERRNO_HELPER(__func__);
        ret = -1;
        goto exit;
    }

    ret = scandirat_fn(dirfd, dirp, namelist, filter, compar);

exit:

    if (abs_dir_path) {
        free(abs_dir_path);
    }

    return ret;
}

int scandir64(const char* dirp, struct dirent64*** namelist, int (*filter)(const struct dirent64*),
              int (*compar)(const struct dirent64**, const struct dirent64**)) {
    scandir64_f_type scandir64_fn;
    int ret = 0;

    char* abs_dir_path          = NULL;
    bool path_to_protected_file = 0;

    char* dir_path = NULL;

    DBG_PRINT("DIR ptr=0x%p\n", dirp);

    scandir64_fn = (scandir64_f_type)dlsym(RTLD_NEXT, "scandir64");

    // check if name has path to secure_io_directory...
    ret = check_secure_io_dir_path(dirp, &abs_dir_path, &path_to_protected_file);

    if (ret != 0) {
        DBG_PRINT("error %d, from check_secure_io_dir_path\n", ret);
        ret = -1;
        goto exit;
    }

    if (abs_dir_path) {
        dir_path = abs_dir_path;
    } else {
        dir_path = (char*)dirp;
    }

    DBG_PRINT("absolute dir-path=%s, strlen=%lu\n", dir_path, strlen(dir_path));

    if (path_to_protected_file) {
        DBG_ERRNO_HELPER(__func__);
        ret = -1;
        goto exit;
    }

    ret = scandir64_fn(dirp, namelist, filter, compar);

exit:

    if (abs_dir_path) {
        free(abs_dir_path);
    }

    return ret;
}

int scandirat64(int dirfd, const char* dirp, struct dirent64*** namelist,
                int (*filter)(const struct dirent64*),
                int (*compar)(const struct dirent64**, const struct dirent64**)) {
    scandirat64_f_type scandirat64_fn;
    int ret = 0;

    char* abs_dir_path          = NULL;
    bool path_to_protected_file = 0;

    char* dir_path = NULL;

    DBG_PRINT("DIR ptr=0x%p\n", dirp);

    scandirat64_fn = (scandirat64_f_type)dlsym(RTLD_NEXT, "scandirat64");

    // check if name has path to secure_io_directory...
    ret = check_secure_io_dir_path(dirp, &abs_dir_path, &path_to_protected_file);

    if (ret != 0) {
        DBG_PRINT("error %d, from check_secure_io_dir_path\n", ret);
        ret = -1;
        goto exit;
    }

    if (abs_dir_path) {
        dir_path = abs_dir_path;
    } else {
        dir_path = (char*)dirp;
    }

    DBG_PRINT("absolute dir-path=%s, strlen=%lu\n", dir_path, strlen(dir_path));

    if (path_to_protected_file) {
        DBG_ERRNO_HELPER(__func__);
        ret = -1;
        goto exit;
    }

    ret = scandirat64_fn(dirfd, dirp, namelist, filter, compar);

exit:

    if (abs_dir_path) {
        free(abs_dir_path);
    }

    return ret;
}

/* Note: if we allow this api for protected directory,
 * then it would complicate, since we would have add support
 * for apis that take fd, such as fdopendir, getdirentries..etc.
 */
int dirfd(DIR* dirp) {
    dirfd_f_type dirfd_fn;
    bool pfs_dir_obj = 0;
    int ret          = 0;

    DBG_PRINT("DIR ptr=0x%p\n", dirp);

    dirfd_fn = (dirfd_f_type)dlsym(RTLD_NEXT, "dirfd");

    if ((ret = check_pfs_dir_object(dirp, &pfs_dir_obj)) != 0) {
        errno = EINVAL;
        return -1;
    }

    if (pfs_dir_obj) {
        DBG_ERRNO_HELPER(__func__);
        return -1;
    } else {
        return dirfd_fn(dirp);
    }
}

int nftw(const char* dirp,
         int (*fn)(const char* fpath, const struct stat* sb, int typeflag, struct FTW* ftwbuf),
         int nopenfd, int flags) {
    nftw_f_type nftw_fn;
    int ret = 0;

    char* abs_dir_path          = NULL;
    bool path_to_protected_file = 0;

    char* dir_path = NULL;

    DBG_PRINT("DIR ptr=0x%p\n", dirp);

    nftw_fn = (nftw_f_type)dlsym(RTLD_NEXT, "nftw");

    // check if name has path to secure_io_directory...
    ret = check_secure_io_dir_path(dirp, &abs_dir_path, &path_to_protected_file);

    if (ret != 0) {
        DBG_PRINT("error %d, from check_secure_io_dir_path\n", ret);
        ret = -1;
        goto exit;
    }

    if (abs_dir_path) {
        dir_path = abs_dir_path;
    } else {
        dir_path = (char*)dirp;
    }

    DBG_PRINT("absolute dir-path=%s, strlen=%lu\n", dir_path, strlen(dir_path));

    if (path_to_protected_file) {
        DBG_ERRNO_HELPER(__func__);
        ret = -1;
        goto exit;
    }

    /*TODO: calling nftw api within graphene hangs graphene application.
     * Internal memory fault. needs investigation.
     */
    ret = nftw_fn(dirp, fn, nopenfd, flags);

exit:

    if (abs_dir_path) {
        free(abs_dir_path);
    }

    return ret;
}

int nftw64(const char* dirp,
           int (*fn)(const char* fpath, const struct stat64* sb, int typeflag, struct FTW* ftwbuf),
           int nopenfd, int flags) {
    nftw64_f_type nftw64_fn;
    int ret = 0;

    char* abs_dir_path          = NULL;
    bool path_to_protected_file = 0;

    char* dir_path = NULL;

    DBG_PRINT("DIR ptr=0x%p\n", dirp);

    nftw64_fn = (nftw64_f_type)dlsym(RTLD_NEXT, "nftw64");

    // check if name has path to secure_io_directory...
    ret = check_secure_io_dir_path(dirp, &abs_dir_path, &path_to_protected_file);

    if (ret != 0) {
        DBG_PRINT("error %d, from check_secure_io_dir_path\n", ret);
        ret = -1;
        goto exit;
    }

    if (abs_dir_path) {
        dir_path = abs_dir_path;
    } else {
        dir_path = (char*)dirp;
    }

    DBG_PRINT("absolute dir-path=%s, strlen=%lu\n", dir_path, strlen(dir_path));

    if (path_to_protected_file) {
        DBG_ERRNO_HELPER(__func__);
        ret = -1;
        goto exit;
    }

    /*TODO: calling nftw api within graphene hangs graphene application.
     * Internal memory fault. needs investigation.
     */
    ret = nftw64_fn(dirp, fn, nopenfd, flags);

exit:

    if (abs_dir_path) {
        free(abs_dir_path);
    }

    return ret;
}
