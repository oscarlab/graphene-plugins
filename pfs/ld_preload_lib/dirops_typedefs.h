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

#ifndef _DIROPS_TYPEDEFS_H_
#define _DIROPS_TYPEDEFS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

#include <dirent.h>
#include <ftw.h>

#include <sys/types.h>
#include <unistd.h>

#include <errno.h>

#include "pfs_debug.h"

#define PFS_DIR_ID 0x5046535F4449525F  // magic cookie PFS_DIR_

#define MAX_DIR_PATH (4096)

typedef struct _pfs_dir {
    uint64_t dir_id;
    DIR* dir_ptr;
    uint8_t* dir_path;
} pfs_dir_t;

typedef DIR* (*opendir_f_type)(const char* name);
typedef int (*closedir_f_type)(DIR* dirp);

typedef struct dirent* (*readdir_f_type)(DIR* dirp);
typedef struct dirent64* (*readdir64_f_type)(DIR* dirp);

typedef int (*readdir_r_f_type)(DIR* dirp, struct dirent* entry, struct dirent** result);
typedef int (*readdir64_r_f_type)(DIR* dirp, struct dirent64* entry, struct dirent64** result);

typedef void (*rewinddir_f_type)(DIR* dirp);
typedef void (*seekdir_f_type)(DIR* dirp, long int pos);
typedef long int (*telldir_f_type)(DIR* dirp);

typedef int (*scandir_f_type)(const char* dirp, struct dirent*** namelist,
                              int (*filter)(const struct dirent*),
                              int (*compar)(const struct dirent**, const struct dirent**));

typedef int (*scandirat_f_type)(int dirfd, const char* dirp, struct dirent*** namelist,
                                int (*filter)(const struct dirent*),
                                int (*compar)(const struct dirent**, const struct dirent**));

typedef int (*scandir64_f_type)(const char* dirp, struct dirent64*** namelist,
                                int (*filter)(const struct dirent64*),
                                int (*compar)(const struct dirent64**, const struct dirent64**));

typedef int (*scandirat64_f_type)(int dirfd, const char* dirp, struct dirent64*** namelist,
                                  int (*filter)(const struct dirent64*),
                                  int (*compar)(const struct dirent64**, const struct dirent64**));

typedef int (*dirfd_f_type)(DIR* dirp);

typedef int (*nftw_f_type)(const char* dirp, int (*fn)(const char* fpath, const struct stat* sb,
                                                       int typeflag, struct FTW* ftwbuf),
                           int nopenfd, int flags);

typedef int (*nftw64_f_type)(const char* dirp, int (*fn)(const char* fpath, const struct stat64* sb,
                                                         int typeflag, struct FTW* ftwbuf),
                             int nopenfd, int flags);

#endif /* _DIROPS_TYPEDEFS_H_ */
