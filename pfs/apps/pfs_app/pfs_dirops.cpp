/*
 * License: BSD 3-Clause License
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

#include <dirent.h>
#include <dlfcn.h>
#include <libgen.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>

#include <errno.h>
#include <ftw.h>
#include <time.h>

#include "fileops_typedefs.h"
#include "perf_meas.h"
#include "pfs_app.h"
#include "pfs_debug.h"

static void using_readdir_api(const char* name);
static void using_readdir64_api(const char* name);

static void using_readdir_r_api(const char* name);
static void using_readdir64_r_api(const char* name);

static int using_scandir_api(const char* dir_path);
static int using_scandir64_api(const char* dir_path);
static int using_scandirat_api(const char* dir_path);
static int using_scandirat64_api(const char* dir_path);

static void using_readdir_api(const char* name) {
    DIR* dir;
    struct dirent* entry;
    char* file_path = NULL;

    if (!(dir = opendir(name)))
        return;

    printf("%s: recursive listing, parent dir=%s\n", __func__, name);

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            file_path = (char*)calloc(strlen(name) + 1 + strlen(entry->d_name) + 1, 1);

            if (!file_path) {
                printf("calloc fails\n");
                continue;
            }

            strncpy(file_path, name, strlen(name));
            file_path[strlen(name)] = '/';
            strncpy(file_path + strlen(name) + 1, entry->d_name, strlen(entry->d_name));

            printf("[DIRECTORY->%s], type->%d\n", entry->d_name, entry->d_type);
            using_readdir_api(file_path);
        } else {
            printf("FILE-> %s, type->%d\n", entry->d_name, entry->d_type);
        }
    }

    if (file_path) {
        free(file_path);
        file_path = NULL;
    }

    closedir(dir);
}

static void using_readdir64_api(const char* name) {
    DIR* dir;
    struct dirent64* entry;
    char* file_path = NULL;

    if (!(dir = opendir(name)))
        return;

    printf("%s: recursive listing, parent dir=%s\n", __func__, name);

    while ((entry = readdir64(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            file_path = (char*)calloc(strlen(name) + 1 + strlen(entry->d_name) + 1, 1);

            if (!file_path) {
                printf("calloc fails\n");
                continue;
            }

            strncpy(file_path, name, strlen(name));
            file_path[strlen(name)] = '/';
            strncpy(file_path + strlen(name) + 1, entry->d_name, strlen(entry->d_name));

            printf("[DIRECTORY->%s], type->%d\n", entry->d_name, entry->d_type);
            using_readdir64_api(file_path);
        } else {
            printf("FILE-> %s, type->%d\n", entry->d_name, entry->d_type);
        }
    }

    if (file_path) {
        free(file_path);
        file_path = NULL;
    }

    closedir(dir);
}

static void using_readdir_r_api(const char* name) {
    DIR* dir;
    struct dirent entry;
    struct dirent* result = NULL;
    char* file_path       = NULL;
    int ret               = 0;

    if (!(dir = opendir(name)))
        return;

    printf("%s: recursive listing, parent dir=%s\n", __func__, name);

    memset(&entry, 0, sizeof(entry));

    while ((ret = readdir_r(dir, &entry, &result)) == 0 && result != NULL) {
        if (entry.d_type == DT_DIR) {
            if (strcmp(entry.d_name, ".") == 0 || strcmp(entry.d_name, "..") == 0)
                continue;

            file_path = (char*)calloc(strlen(name) + 1 + strlen(entry.d_name) + 1, 1);

            if (!file_path) {
                printf("calloc fails\n");
                continue;
            }

            strncpy(file_path, name, strlen(name));
            file_path[strlen(name)] = '/';
            strncpy(file_path + strlen(name) + 1, entry.d_name, strlen(entry.d_name));

            printf("[DIRECTORY->%s], type->%d\n", entry.d_name, entry.d_type);
            using_readdir_r_api(file_path);
        } else {
            printf("FILE-> %s, type->%d\n", entry.d_name, entry.d_type);
        }
    }

    if (file_path) {
        free(file_path);
        file_path = NULL;
    }

    closedir(dir);
}

static void using_readdir64_r_api(const char* name) {
    DIR* dir;
    struct dirent64 entry;
    struct dirent64* result = NULL;
    char* file_path         = NULL;
    int ret                 = 0;

    if (!(dir = opendir(name)))
        return;

    printf("%s: recursive listing, parent dir=%s\n", __func__, name);

    memset(&entry, 0, sizeof(entry));

    while ((ret = readdir64_r(dir, &entry, &result)) == 0 && result != NULL) {
        if (entry.d_type == DT_DIR) {
            if (strcmp(entry.d_name, ".") == 0 || strcmp(entry.d_name, "..") == 0)
                continue;

            file_path = (char*)calloc(strlen(name) + 1 + strlen(entry.d_name) + 1, 1);

            if (!file_path) {
                printf("calloc fails\n");
                continue;
            }

            strncpy(file_path, name, strlen(name));
            file_path[strlen(name)] = '/';
            strncpy(file_path + strlen(name) + 1, entry.d_name, strlen(entry.d_name));

            printf("[DIRECTORY->%s], type->%d\n", entry.d_name, entry.d_type);
            using_readdir64_r_api(file_path);
        } else {
            printf("FILE-> %s, type->%d\n", entry.d_name, entry.d_type);
        }
    }

    if (file_path) {
        free(file_path);
        file_path = NULL;
    }

    closedir(dir);
}

static int using_scandir_api(const char* dir_path) {
    struct dirent** namelist;
    int n;
    char* file_path = NULL;

    if (!dir_path)
        return -1;

    n = scandir(dir_path, &namelist, NULL, alphasort);

    printf("%s:%d: dir_path=%s, n=%d\n", __func__, __LINE__, dir_path, n);

    if (n < 0) {
        perror("scandir");
        return n;
    }

    while (n--) {
        printf("%s\n", namelist[n]->d_name);

        if (namelist[n]->d_type == DT_DIR) {
            if (strcmp(namelist[n]->d_name, ".") == 0 || strcmp(namelist[n]->d_name, "..") == 0)
                continue;

            file_path = (char*)calloc(strlen(dir_path) + 1 + strlen(namelist[n]->d_name) + 1, 1);

            if (!file_path) {
                printf("calloc fails\n");
                continue;
            }

            strncpy(file_path, dir_path, strlen(dir_path));
            file_path[strlen(dir_path)] = '/';
            strncpy(file_path + strlen(dir_path) + 1, namelist[n]->d_name,
                    strlen(namelist[n]->d_name));

            printf("[DIRECTORY->%s], type->%d\n", namelist[n]->d_name, namelist[n]->d_type);
            using_scandir_api(file_path);
        } else {
            printf("FILE-> %s, type->%d\n", namelist[n]->d_name, namelist[n]->d_type);
        }

        free(namelist[n]);
    }

    free(namelist);

    if (file_path) {
        free(file_path);
        file_path = NULL;
    }

    return 0;
}

static int using_scandir64_api(const char* dir_path) {
    struct dirent64** namelist;
    int n;
    char* file_path = NULL;

    if (!dir_path)
        return -1;

    n = scandir64(dir_path, &namelist, NULL, NULL);

    printf("%s:%d: dir_path=%s, n=%d\n", __func__, __LINE__, dir_path, n);

    if (n < 0) {
        perror("scandir64");
        return n;
    }

    while (n--) {
        printf("%s\n", namelist[n]->d_name);

        if (namelist[n]->d_type == DT_DIR) {
            if (strcmp(namelist[n]->d_name, ".") == 0 || strcmp(namelist[n]->d_name, "..") == 0)
                continue;

            file_path = (char*)calloc(strlen(dir_path) + 1 + strlen(namelist[n]->d_name) + 1, 1);

            if (!file_path) {
                printf("calloc fails\n");
                continue;
            }
            strncpy(file_path, dir_path, strlen(dir_path));
            file_path[strlen(dir_path)] = '/';
            strncpy(file_path + strlen(dir_path) + 1, namelist[n]->d_name,
                    strlen(namelist[n]->d_name));

            printf("[DIRECTORY->%s], type->%d\n", namelist[n]->d_name, namelist[n]->d_type);
            using_scandir64_api(file_path);
        } else {
            printf("FILE-> %s, type->%d\n", namelist[n]->d_name, namelist[n]->d_type);
        }

        free(namelist[n]);
    }

    free(namelist);

    if (file_path) {
        free(file_path);
        file_path = NULL;
    }

    return 0;
}

static int using_scandirat_api(const char* dir_path) {
    struct dirent** namelist;
    int n;
    char* file_path = NULL;

    if (!dir_path)
        return -1;

    // note: passing absolute path, so fd can be NULL(i.e. it is ignored).
    n = scandirat(NULL, dir_path, &namelist, NULL, NULL);

    printf("%s:%d: dir_path=%s, n=%d\n", __func__, __LINE__, dir_path, n);

    if (n < 0) {
        perror("scandirat");
        return n;
    }

    while (n--) {
        printf("%s\n", namelist[n]->d_name);

        if (namelist[n]->d_type == DT_DIR) {
            if (strcmp(namelist[n]->d_name, ".") == 0 || strcmp(namelist[n]->d_name, "..") == 0)
                continue;

            file_path = (char*)calloc(strlen(dir_path) + 1 + strlen(namelist[n]->d_name) + 1, 1);

            if (!file_path) {
                printf("calloc fails\n");
                continue;
            }

            strncpy(file_path, dir_path, strlen(dir_path));
            file_path[strlen(dir_path)] = '/';
            strncpy(file_path + strlen(dir_path) + 1, namelist[n]->d_name,
                    strlen(namelist[n]->d_name));

            printf("[DIRECTORY->%s], type->%d\n", namelist[n]->d_name, namelist[n]->d_type);
            using_scandirat_api(file_path);
        } else {
            printf("FILE-> %s, type->%d\n", namelist[n]->d_name, namelist[n]->d_type);
        }

        free(namelist[n]);
    }

    free(namelist);

    if (file_path) {
        free(file_path);
        file_path = NULL;
    }

    return 0;
}

static int using_scandirat64_api(const char* dir_path) {
    struct dirent64** namelist;
    int n;
    char* file_path = NULL;

    if (!dir_path)
        return -1;

    // note: passing absolute path, so fd can be NULL(i.e. it is ignored).
    n = scandirat64(NULL, dir_path, &namelist, NULL, NULL);

    printf("%s:%d: dir_path=%s, n=%d\n", __func__, __LINE__, dir_path, n);

    if (n < 0) {
        perror("scandirat64");
        return n;
    }

    while (n--) {
        printf("%s\n", namelist[n]->d_name);

        if (namelist[n]->d_type == DT_DIR) {
            if (strcmp(namelist[n]->d_name, ".") == 0 || strcmp(namelist[n]->d_name, "..") == 0)
                continue;

            file_path = (char*)calloc(strlen(dir_path) + 1 + strlen(namelist[n]->d_name) + 1, 1);

            if (!file_path) {
                printf("calloc fails\n");
                continue;
            }
            strncpy(file_path, dir_path, strlen(dir_path));
            file_path[strlen(dir_path)] = '/';
            strncpy(file_path + strlen(dir_path) + 1, namelist[n]->d_name,
                    strlen(namelist[n]->d_name));

            printf("[DIRECTORY->%s], type->%d\n", namelist[n]->d_name, namelist[n]->d_type);
            using_scandirat64_api(file_path);
        } else {
            printf("FILE-> %s, type->%d\n", namelist[n]->d_name, namelist[n]->d_type);
        }

        free(namelist[n]);
    }

    free(namelist);

    if (file_path) {
        free(file_path);
        file_path = NULL;
    }

    return 0;
}

static void using_other_dirops_apis(const char* name) {
    DIR* dir;
    struct dirent* entry;
    char* file_path     = NULL;
    int fd              = 0;
    long int dir_offset = 0;

    if (!(dir = opendir(name)))
        return;

    printf("%s: recursive listing, parent dir=%s\n", __func__, name);

    fd = dirfd(dir);

    printf("fd=%d after call to dirfd, parent dir path=%s\n", fd, name);

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            printf("[DIRECTORY->%s], type->%d\n", entry->d_name, entry->d_type);
        } else {
            printf("FILE->%s, type->%d\n", entry->d_name, entry->d_type);

            // testing other apis..and then exiting
            dir_offset = telldir(dir);

            if (dir_offset == -1) {
                printf("error = %d, from telldir\n", dir_offset);
                break;
            } else {
                seekdir(dir, dir_offset);
                rewinddir(dir);
                printf("exiting loop, after other apis are called\n");
                break;
            }
        }
    }

    if (file_path) {
        free(file_path);
        file_path = NULL;
    }

    closedir(dir);
}

#ifndef USE_FDS
#define USE_FDS 16
#endif

int list_entry(const char* filepath, const struct stat* info, const int typeflag,
               struct FTW* pathinfo) {
    if (!filepath || !info || !pathinfo || typeflag < 0) {
        return -1;
    }

    return 0;
}

int using_nftw_api(const char* const dirpath) {
    int result = 0;

    if (dirpath == NULL || *dirpath == '\0') {
        return EINVAL;
    }

    result = nftw(dirpath, list_entry, USE_FDS, FTW_PHYS);
    if (result >= 0)
        errno = result;

    return errno;
}

int list_entry64(const char* filepath, const struct stat64* info, const int typeflag,
                 struct FTW* pathinfo) {
    if (!filepath || !info || !pathinfo || typeflag < 0) {
        return -1;
    }

    return 0;
}

int using_nftw64_api(const char* const dirpath) {
    int result = 0;

    if (dirpath == NULL || *dirpath == '\0') {
        return EINVAL;
    }

    result = nftw64(dirpath, list_entry64, USE_FDS, FTW_PHYS);
    if (result >= 0)
        errno = result;

    return errno;
}

int pfs_readdir_test() {
    uint32_t i;
    int ret_val = 0;

    const char* dir_names_abs[] = {
        CLEAR_DIR_PATH, PROTECTED_DIR_PATH,
    };

    printf("%s,%d:\n", __func__, __LINE__);

    for (i = 0; i < sizeof(dir_names_abs) / sizeof(char*); i++) {
        using_readdir_api(dir_names_abs[i]);
    }

    return ret_val;
}

int pfs_readdir64_test() {
    uint32_t i;
    int ret_val = 0;

    const char* dir_names_abs[] = {
        CLEAR_DIR_PATH, PROTECTED_DIR_PATH,
    };

    printf("%s,%d:\n", __func__, __LINE__);

    for (i = 0; i < sizeof(dir_names_abs) / sizeof(char*); i++) {
        using_readdir64_api(dir_names_abs[i]);
    }

    return ret_val;
}

int pfs_readdir_r_test() {
    uint32_t i;
    int ret_val = 0;

    const char* dir_names_abs[] = {
        CLEAR_DIR_PATH, PROTECTED_DIR_PATH,
    };

    printf("%s,%d:\n", __func__, __LINE__);

    for (i = 0; i < sizeof(dir_names_abs) / sizeof(char*); i++) {
        using_readdir_r_api(dir_names_abs[i]);
    }

    return ret_val;
}

int pfs_readdir64_r_test() {
    uint32_t i;
    int ret_val = 0;

    const char* dir_names_abs[] = {
        CLEAR_DIR_PATH, PROTECTED_DIR_PATH,
    };

    printf("%s,%d:\n", __func__, __LINE__);

    for (i = 0; i < sizeof(dir_names_abs) / sizeof(char*); i++) {
        using_readdir64_r_api(dir_names_abs[i]);
    }

    return ret_val;
}

int pfs_scandir_test() {
    uint32_t i;
    int ret_val = 0;

    const char* dir_names_abs[] = {
        CLEAR_DIR_PATH, PROTECTED_DIR_PATH,
    };

    printf("%s,%d:\n", __func__, __LINE__);

    for (i = 0; i < sizeof(dir_names_abs) / sizeof(char*); i++) {
        using_scandir_api(dir_names_abs[i]);
    }

    return ret_val;
}

int pfs_scandir64_test() {
    uint32_t i;
    int ret_val = 0;

    const char* dir_names_abs[] = {
        CLEAR_DIR_PATH, PROTECTED_DIR_PATH,
    };

    printf("%s,%d:\n", __func__, __LINE__);

    for (i = 0; i < sizeof(dir_names_abs) / sizeof(char*); i++) {
        using_scandir64_api(dir_names_abs[i]);
    }

    return ret_val;
}

int pfs_scandirat_test() {
    uint32_t i;
    int ret_val = 0;

    const char* dir_names_abs[] = {
        CLEAR_DIR_PATH, PROTECTED_DIR_PATH,
    };

    printf("%s,%d:\n", __func__, __LINE__);

    for (i = 0; i < sizeof(dir_names_abs) / sizeof(char*); i++) {
        using_scandirat_api(dir_names_abs[i]);
    }

    return ret_val;
}

int pfs_scandirat64_test() {
    uint32_t i;
    int ret_val = 0;

    const char* dir_names_abs[] = {
        CLEAR_DIR_PATH, PROTECTED_DIR_PATH,
    };

    printf("%s,%d:\n", __func__, __LINE__);

    for (i = 0; i < sizeof(dir_names_abs) / sizeof(char*); i++) {
        using_scandirat64_api(dir_names_abs[i]);
    }

    return ret_val;
}

int pfs_other_dirops_apis_test() {
    uint32_t i;
    int ret_val = 0;

    const char* dir_names_abs[] = {
        CLEAR_DIR_PATH, PROTECTED_DIR_PATH,
    };

    printf("%s,%d:\n", __func__, __LINE__);

    for (i = 0; i < sizeof(dir_names_abs) / sizeof(char*); i++) {
        using_other_dirops_apis(dir_names_abs[i]);
    }

    return ret_val;
}

int pfs_nftw_test() {
    uint32_t i;
    int ret_val = 0;

    const char* dir_names_abs[] = {
        /*CLEAR_DIR_PATH, */ PROTECTED_DIR_PATH,
    };

    printf("%s,%d:\n", __func__, __LINE__);

    for (i = 0; i < sizeof(dir_names_abs) / sizeof(char*); i++) {
        using_nftw_api(dir_names_abs[i]);
    }

    return ret_val;
}

int pfs_nftw64_test() {
    uint32_t i;
    int ret_val = 0;

    const char* dir_names_abs[] = {
        /*CLEAR_DIR_PATH, */ PROTECTED_DIR_PATH,
    };

    printf("%s,%d:\n", __func__, __LINE__);

    for (i = 0; i < sizeof(dir_names_abs) / sizeof(char*); i++) {
        using_nftw64_api(dir_names_abs[i]);
    }

    return ret_val;
}

int pfs_directory_system_apis_test() {
    int overall_ret = 0;

    overall_ret += pfs_readdir_test();
    overall_ret += pfs_readdir64_test();
    overall_ret += pfs_readdir_r_test();
    overall_ret += pfs_readdir64_r_test();
    overall_ret += pfs_scandir_test();
    overall_ret += pfs_scandir64_test();
    overall_ret += pfs_scandirat_test();
    overall_ret += pfs_scandirat64_test();
    overall_ret += pfs_other_dirops_apis_test();
    overall_ret += pfs_nftw_test();
    overall_ret += pfs_nftw64_test();

    printf("\n#######%s, %s#######\n", __func__, ZERO_RESULT(overall_ret));

    return overall_ret;
}
