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

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <unistd.h>

#include "sgx_tseal.h"

#include "dirops_typedefs.h"
#include "fileops_typedefs.h"
#include "protfs_debug.h"

#include "perf_meas.h"
#include "protfs_app.h"
#include "protfs_dirops.h"

static int protfs_create_new_file(const char* prot_path, const char* filename, FILE** sfp);
static int protect_clear_file(const char* clear_path, const char* clear_file,
                              const char* prot_path);

/* if file already exists, returns error */
static int protfs_create_new_file(const char* prot_path, const char* filename, FILE** sfp) {
    uint32_t full_path_len = 0;
    char* full_path        = NULL;
    int ret                = 0;

    if (!filename || !sfp || !prot_path)
        return -1;

    printf("filename is =%s\n", filename);

    full_path_len = strlen(prot_path) + 1 + strlen(filename) + 1;

    if (full_path_len + 1 > FILE_PATH_MAX) {
        printf("file_path=%s too long, length=%d\n", full_path, full_path_len);
        return -1;
    }

    full_path = (char*)calloc(full_path_len + 1, 1);

    if (!full_path)
        return -1;

    strncpy(full_path, prot_path, strlen(prot_path));
    full_path[strlen(prot_path)] = '/';
    strncpy(full_path + strlen(prot_path) + 1, filename, strlen(filename));

    printf("full_path=%s\n", full_path);

    *sfp = fopen(full_path, "rb");

    if (*sfp == NULL) {
        printf("File does NOT exist, need to CREATE one\n");

        *sfp = fopen(full_path, "w+b");

        if (*sfp == NULL) {
            printf("File does NOT exist, error in creating file\n");
            ret = -1;
            goto exit;
        }
    } else if (*sfp != NULL) {
        printf("File ALREADY exists.\n");
        ret = -1;
        goto exit;
    }

exit:

    if (full_path)
        free(full_path);

    return ret;
}

/* opens existing clear file, and outputs protected file */
static int protect_clear_file(const char* clear_path, const char* clear_file,
                              const char* prot_path) {
    char* buffer  = NULL;
    int file_size = 0;

    ssize_t bytes_read    = 0;
    ssize_t read_length   = 0;
    ssize_t bytes_written = 0;

    int bytes_written_total = 0;
    int bytes_read_total    = 0;

    FILE* fclear           = NULL;
    int ret_val            = 0;
    char* full_path        = NULL;
    uint32_t full_path_len = 0;

    FILE* sfp = NULL;

    if (!clear_file || !clear_path || !prot_path)
        return -1;

    full_path_len = strlen(clear_path) + 1 + strlen(clear_file) + 1;

    if (full_path_len + 1 > FILE_PATH_MAX) {
        printf("file_path=%s too long, file_size=%d\n", full_path, full_path_len);
        return -1;
    }

    full_path = (char*)calloc(full_path_len + 1, 1);

    if (!full_path)
        return -1;

    strncpy(full_path, clear_path, strlen(clear_path));
    full_path[strlen(clear_path)] = '/';
    strncpy(full_path + strlen(clear_path) + 1, clear_file, strlen(clear_file));

    printf("full_path=%s\n", full_path);

    fclear = fopen(full_path, "rb");

    if (!fclear) {
        printf("file doesnt exist, errno=%d, full_path=%s\n", errno, full_path);
        ret_val = -1;
        goto exit;
    }

    ret_val = fseek(fclear, 0, SEEK_END);

    if (ret_val == -1) {
        goto exit;
    }

    file_size = ftell(fclear);

    if (file_size == -1 || file_size == 0) {
        ret_val = -1;
        goto exit;
    }

    ret_val = fseek(fclear, 0, SEEK_SET);

    if (ret_val == -1) {
        goto exit;
    }

    printf("Length of file=%s, is =%d\n", full_path, file_size);

    if (MAX_SIZE_FOR_FILE_READ < file_size) {
        read_length = MAX_SIZE_FOR_FILE_READ;
    } else
        read_length = file_size;

    buffer = (char*)malloc(read_length);

    if (!buffer) {
        ret_val = -1;
        goto exit;
    }

    bytes_read_total = 0;

    // opening the protected file.
    ret_val = protfs_create_new_file(prot_path, clear_file, &sfp);

    if (ret_val != 0) {
        ret_val = -1;
        goto exit;
    }

    while (bytes_read_total < file_size) {
        bytes_read = fread(buffer, sizeof(uint8_t), read_length, fclear);

        printf("Length of buffer is =%lu, bytes read=%lu\n", read_length, bytes_read);

        if (bytes_read != read_length) {
            ret_val = ferror(fclear);

            if (ret_val != 0) {
                printf("error in fread=%d\n", ret_val);
                break;
            }
        }

        // Write to protected file
        bytes_written = fwrite(buffer, sizeof(uint8_t), bytes_read, sfp);
        printf("Size of Write=  %lu\n", bytes_written);

        if (bytes_written != bytes_read) {
            printf("error, ret=%d, size of Write=%lu, bytes_read=%lu\n", ret_val, bytes_written,
                   bytes_read);
            break;
        }

        // to protected_file.
        bytes_written_total = bytes_written_total + bytes_read;

        bytes_read_total = bytes_read_total + bytes_read;

        if (file_size > bytes_read_total) {
            if ((file_size - bytes_read_total) > MAX_SIZE_FOR_FILE_READ)
                read_length = MAX_SIZE_FOR_FILE_READ;
            else
                read_length = file_size - bytes_read_total;
        }
    }

    if (ret_val == 0) {
        printf("file_size =%d, bytes_read_total=%d, bytes_written_total=%d\n", file_size,
               bytes_read_total, bytes_written_total);
    }

exit:
    if (full_path)
        free(full_path);

    if (buffer)
        free(buffer);

    if (sfp)
        fclose(sfp);

    if (fclear)
        fclose(fclear);

    return ret_val;
}

/* Recursively dives into the source directory,
 * and creates protected files into the destination directory.
 * It creates new sub-directories in destination, to duplicate
 * the directory-tree from source to destination, and transforms.
 * clear files into protected files.
 */
int protect_files(char* src_dir_path, char* dest_dir_path) {
    int ret = 0;

    DIR* src_dir_ptr;
    struct dirent* entry;
    char* src_file_path  = NULL;
    char* dest_file_path = NULL;

    if (!src_dir_path || !dest_dir_path)
        return -1;

    if (!(src_dir_ptr = opendir(src_dir_path)))
        return -1;

    printf("%s: recursive listing, parent src_dir_ptr=%s\n", __func__, src_dir_path);

    while ((entry = readdir(src_dir_ptr)) != NULL) {
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            src_file_path = (char*)calloc(strlen(src_dir_path) + 1 + strlen(entry->d_name) + 1, 1);

            if (!src_file_path) {
                printf("calloc fails\n");
                goto exit;
            }

            strncpy(src_file_path, src_dir_path, strlen(src_dir_path));
            src_file_path[strlen(src_dir_path)] = '/';
            strncpy(src_file_path + strlen(src_dir_path) + 1, entry->d_name, strlen(entry->d_name));

            dest_file_path =
                (char*)calloc(strlen(dest_dir_path) + 1 + strlen(entry->d_name) + 1, 1);

            if (!dest_file_path) {
                printf("calloc fails\n");
                goto exit;
            }

            strncpy(dest_file_path, dest_dir_path, strlen(dest_dir_path));
            dest_file_path[strlen(dest_dir_path)] = '/';
            strncpy(dest_file_path + strlen(dest_dir_path) + 1, entry->d_name,
                    strlen(entry->d_name));

            if ((ret = mkdir(dest_file_path, 0775) != 0) && (errno != EEXIST)) {
                printf("mkdir fails for->%s, errno=%d\n", dest_file_path, errno);
                goto exit;
            }

            printf("[DIRECTORY->%s], type->%d, src_path->%s, dest_path->%s\n", entry->d_name,
                   entry->d_type, src_file_path, dest_file_path);
            protect_files(src_file_path, dest_file_path);
        } else if (entry->d_type == DT_REG) {
            printf("FILE-> %s, type->%d\n", entry->d_name, entry->d_type);
            protect_clear_file(src_dir_path, entry->d_name, dest_dir_path);
        } else {
            printf("No-op for FILE-> %s, type->%d\n", entry->d_name, entry->d_type);
        }
    }

exit:

    if (src_file_path) {
        free(src_file_path);
        src_file_path = NULL;
    }

    if (dest_file_path) {
        free(dest_file_path);
        dest_file_path = NULL;
    }

    closedir(src_dir_ptr);

    return ret;
}
