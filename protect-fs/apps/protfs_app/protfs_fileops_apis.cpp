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

// static bool remove_file = 0;
char sprintf_buf_glb[SPRINTF_BUFSIZE];

static int protfs_character_string_apis_test(FILE* sfp, file_type_t file_type);
static int protfs_getc_ungetc_test(FILE* sfp, file_type_t file_type);

static int protfs_file_offset_apis_test(const char* path_to_file, file_type_t file_type);
static int protfs_secure_io_path_test();
static int protfs_app_long_filename_test();
static int system_apis_open_close(const char* filename, file_type);

static int protfs_getc_ungetc_test(FILE* sfp, file_type_t file_type) {
    size_t file_len           = 0;
    uint8_t string_to_write[] = "Trial run";
    int32_t ret_val           = 0;

    char byte_read;
    char byte_from_ungetc;
    long offset;
    long offset_after_ungetc;

    unsigned int i;
    int overall_ret = 0;

    if (!sfp) {
        printf("\nDEBUG: Null pointer to %s", __func__);
        return -1;
    }

    ret_val = fseek(sfp, 0L, SEEK_SET);

    file_len = fwrite(string_to_write, sizeof(uint8_t), sizeof(string_to_write), sfp);

    printf("DEBUG, after fwrite, file_len = %d\n", (int)file_len);

    ret_val = fflush(sfp);

    fseek(sfp, 0, SEEK_END);
    file_len = (unsigned long)ftell(sfp);

    ret_val = fseek(sfp, 0L, SEEK_SET);

    printf("DEBUG, file_len = %lu\n", file_len);

    for (i = 1; i <= file_len; i++) {
        byte_read = getc(sfp);
        offset    = ftell(sfp);

        if (byte_read == 'r') {
            byte_from_ungetc    = ungetc(byte_read, sfp);
            offset_after_ungetc = ftell(sfp);

            snprintf(sprintf_buf_glb, SPRINTF_BUFSIZE,
                     "byte_read=%c, byte_from_ungetc=%c. offset=%ld, offset_after_ungetc=%ld",
                     byte_read, byte_from_ungetc, offset, offset_after_ungetc);
            overall_ret += check_bool_and_print_dbg(
                "getc_ungetc", file_type,
                ((byte_read == byte_from_ungetc) && ((offset_after_ungetc + 1) == offset)),
                sprintf_buf_glb);

            break;
        }
    }

    return overall_ret;
}

// Note: Test works fine...
static int protfs_character_string_apis_test(FILE* sfp, file_type_t file_type) {
    int32_t ret_val = 0;
    int overall_ret = 0;
    uint8_t read_buffer[BUFFER_SIZE];

    const char string_to_write[] = "Trial run";
    const char test_string[]     = "You said what";

    int byte_read    = 0;
    int byte_written = 0;

    uint64_t offset = 0;

    if (!sfp) {
        printf("\nDEBUG: invalid params to %s", __func__);
        return -1;
    }

    memset(read_buffer, 0, sizeof(read_buffer));

    ret_val = fseek(sfp, 0L, SEEK_SET);
    // printf("DEBUG, after fseek, ret = %d\n", (int)ret_val);
    overall_ret += check_bool_and_print_dbg("fseek", file_type, (ret_val == 0), (char*)"");

    // Read from File
    offset = ftell(sfp);
    // printf("DEBUG: File offset = %lu\n", offset);
    overall_ret += check_bool_and_print_dbg("ftell", file_type, (offset == 0), (char*)"");

    byte_read = fgetc(sfp);
    offset    = ftell(sfp);

    byte_written = putc(byte_read, sfp);
    offset       = ftell(sfp);

    snprintf(sprintf_buf_glb, SPRINTF_BUFSIZE, "getc = %d, putc = %d", byte_read, byte_written);
    overall_ret += check_bool_and_print_dbg("fgetc_putc", file_type, (byte_written == byte_read),
                                            sprintf_buf_glb);

    ret_val = fseek(sfp, 0L, SEEK_SET);
    // printf("DEBUG, after fseek, ret = %d\n", (int)ret_val);

    offset = ftell(sfp);
    // printf("DEBUG: File offset = %lu\n", offset);

    byte_read = fgetc(sfp);
    offset    = ftell(sfp);

    byte_written = fputc(byte_read, sfp);
    offset       = ftell(sfp);

    snprintf(sprintf_buf_glb, SPRINTF_BUFSIZE, "getc = %d, putc = %d", byte_read, byte_written);
    overall_ret +=
        check_bool_and_print_dbg("fgetc_fputc", file_type, (byte_written == byte_read), (char*)"");

    ret_val = fseek(sfp, 0L, SEEK_SET);
    // printf("DEBUG, after fseek, ret = %d\n", (int)ret_val);

    if (sizeof(read_buffer) >= sizeof(string_to_write)) {
        fgets((char*)read_buffer, sizeof(string_to_write), sfp);
    }

    ret_val = fseek(sfp, 0L, SEEK_SET);
    // printf("DEBUG, after fseek, ret = %d\n", (int)ret_val);

    ret_val = fputs((char*)test_string, sfp);
    // printf("ret_val from fputs: %d\n", ret_val);

    ret_val = fseek(sfp, 0L, SEEK_SET);
    // printf("DEBUG, after fseek, ret = %d\n", (int)ret_val);

    if (sizeof(read_buffer) >= sizeof(test_string)) {
        fgets((char*)read_buffer, sizeof(test_string), sfp);
    }

    snprintf(sprintf_buf_glb, SPRINTF_BUFSIZE, "fgets = %s, fputs = %s", read_buffer, test_string);
    overall_ret += check_bool_and_print_dbg(
        "fputs_fgets", file_type,
        (strncmp((const char*)read_buffer, test_string, strlen(test_string)) == 0), (char*)"");

    overall_ret += protfs_getc_ungetc_test(sfp, file_type);

    return overall_ret;
}

static int protfs_file_offset_apis_test(const char* path_to_file, file_type_t file_type) {
    FILE* sfp = NULL;
    uint8_t read_buffer[BUFFER_SIZE];
    int32_t ret_val = 0;
    int overall_ret = 0;

    if (!path_to_file) {
        printf("\nDEBUG: invalid params to %s", __func__);
        return -1;
    }

    ret_val = open_file_wrapper(path_to_file, &sfp);

    if (ret_val != 0) {
        return ret_val;
    }

    memset(read_buffer, 0, sizeof(read_buffer));

    ret_val = fseek(sfp, 0L, SEEK_SET);
    // printf("DEBUG, after fseek, ret = %d\n", (int)ret_val);

    // Read from File
    int64_t file_offset = 0;
    file_offset         = ftell(sfp);
    // printf("DEBUG: File offset = %lu\n", file_offset);

    fpos_t position;

    ret_val = fgetpos(sfp, &position);

    overall_ret += check_ret_and_print_dbg("fgetpos", file_type, ret_val);

    fputs("Hello, World!", sfp);

    ret_val = fsetpos(sfp, &position);

    overall_ret += check_ret_and_print_dbg("fsetpos", file_type, ret_val);

    fputs("This is going to override previous content", sfp);

    ret_val = fseeko(sfp, 0L, SEEK_SET);
    // printf("DEBUG, after fseeko, ret = %d\n", (int)ret_val);
    overall_ret += check_bool_and_print_dbg("fseeko", file_type, (ret_val == 0), (char*)"");

    // Read from File
    file_offset = ftello(sfp);
    // printf("DEBUG: File offset = %ld\n", file_offset);
    overall_ret += check_bool_and_print_dbg("ftello", file_type, (file_offset == 0), (char*)"");

    ret_val = fclose(sfp);

    // printf("DEBUG, after fclose, ret_val = %d\n", (int)ret_val);

    return overall_ret;
}

static int protfs_secure_io_path_test() {
    FILE* fp = NULL;
    unsigned int i;
    int ret_val     = 0;
    int overall_ret = 0;

    const char* file_names[] = {"/protfs_dir/non_secrets/temp100", "/protfs_dir/secrets/temp100"};

    const char* file_names_rel[] = {"../non_secrets/temp101", "../secrets/temp101"};

    const char* file_names_invalid[] = {"../non_sec/temp101", "/protfs_dir/sec/temp100"};

    for (i = 0; i < sizeof(file_names) / sizeof(char*); i++) {
        fp = fopen(file_names[i], "w+");

        snprintf(sprintf_buf_glb, SPRINTF_BUFSIZE, "filepath=%s", file_names[i]);

        overall_ret +=
            check_bool_and_print_dbg("fopen", NOT_APPLICABLE, (fp != NULL), (char*)sprintf_buf_glb);

        if (fp) {
            fclose(fp);
            fp = NULL;
        }
    }

    ret_val = chdir(TEST_DIR_PATH);

    if (ret_val != 0) {
        printf("chdir to %s, returned error, ret_val=%d, errno=%d\n", TEST_DIR_PATH, ret_val,
               errno);
        overall_ret += -1;
        goto exit;
    }

    for (i = 0; i < sizeof(file_names_rel) / sizeof(char*); i++) {
        fp = fopen(file_names_rel[i], "w+");

        snprintf(sprintf_buf_glb, SPRINTF_BUFSIZE, "filepath=%s", file_names_rel[i]);

        overall_ret +=
            check_bool_and_print_dbg("fopen", NOT_APPLICABLE, (fp != NULL), (char*)sprintf_buf_glb);

        if (fp) {
            fclose(fp);
            fp = NULL;
        }
    }

    for (i = 0; i < sizeof(file_names_invalid) / sizeof(char*); i++) {
        fp = fopen(file_names_invalid[i], "r");

        snprintf(sprintf_buf_glb, SPRINTF_BUFSIZE, "filepath=%s", file_names_invalid[i]);

        overall_ret +=
            check_bool_and_print_dbg("fopen", NOT_APPLICABLE, (fp == NULL), (char*)sprintf_buf_glb);

        if (fp) {
            fclose(fp);
            fp = NULL;
        }
    }

exit:

    printf("%s, %d: ret_val->%d\n", __func__, __LINE__, overall_ret);

    return overall_ret;
}

// Note: Test API for low-level system apis that use file-descriptor
// like open/close..to ensure it works fine for normal files(i.e. non-protected files).
static int system_apis_open_close(const char* filename, file_type_t file_type) {
    int ret                   = 0;
    int overall_ret           = 0;
    int fd                    = -1;
    mode_t mode               = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
    ssize_t len               = 0;
    uint8_t string_to_write[] = "^^Low-level-APIs->Trial run^^";

    if (filename == NULL || strnlen(filename, 1) == 0) {
        printf("filename is NULL or empty\n");
        return -1;
    }

    // create the file if it doesn't exists, read-only/read-write
    fd = open(filename, O_CREAT | O_RDWR | O_APPEND, mode);

    overall_ret += check_fd_and_print_dbg("open", file_type, fd);

    len = write(fd, string_to_write, sizeof(string_to_write));

    overall_ret += check_bool_and_print_dbg(
        "write", file_type, ((file_type == NORMAL && (len == sizeof(string_to_write))) ||
                             (file_type == PROTECTED && len == -1)),
        (char*)"");

    ret = close(fd);
    overall_ret += check_ret_and_print_dbg("close", file_type, ret);

    return overall_ret;
}

static int protfs_app_long_filename_test() {
    int ret         = 0;
    int overall_ret = 0;
    char filename[FILENAME_MAX_LENGTH];
    char* file_path = NULL;
    uint32_t cnt    = 0;
    FILE* fp        = NULL;

    memset(filename, 0, sizeof(filename));

    for (cnt = 0; cnt < sizeof(filename) - 1; cnt++) {
        filename[cnt] = 'a';
    }

    file_path = (char*)calloc(strlen(CLEAR_DIR_PATH) + 1 + sizeof(filename) + 1, 1);

    if (file_path != NULL) {
        strncpy(file_path, CLEAR_DIR_PATH, strlen(CLEAR_DIR_PATH));
        file_path[strlen(CLEAR_DIR_PATH)] = '/';
        strncpy(file_path + strlen(CLEAR_DIR_PATH) + 1, filename, strlen(filename));

        // printf("filename=%s, strlen(filename)=%lu\n", filename, strlen(filename));
        // printf("file-path=%s, strlen(file-path)=%lu\n", file_path, strlen(file_path));

        fp = fopen((const char*)file_path, "wb+");

        snprintf(sprintf_buf_glb, SPRINTF_BUFSIZE, "filepath=%s", file_path);

        overall_ret +=
            check_bool_and_print_dbg("fopen", NOT_APPLICABLE, (fp != NULL), (char*)sprintf_buf_glb);

        if (fp) {
            ret = fclose(fp);
            ret = remove(file_path);
        }
    }

    if (file_path) {
        free(file_path);
    }

    return overall_ret;
}

int check_ret_and_print_dbg(const char* func, file_type_t file_type, int ret_val) {
    int ret     = 0;
    bool result = 0;

    if (!func)
        return -1;

    if (file_type == PROTECTED) {
        result = (ret_val == -1) ? 1 : 0;

        printf("\n%s, %s, file_type=%s, ret_val=%d, errno=%d\n", func, EXPECTED_TRUE(result),
               "PROTECTED", ret_val, errno);
    } else {
        result = (ret_val == 0) ? 1 : 0;

        printf("\n%s, %s, file_type=%s, ret_val=%d, errno=%d\n", func, EXPECTED_TRUE(result),
               "NORMAL", ret_val, errno);
    }

    // Note: Helps to verify that over-riding apis set the correct errno
    errno = 0;

    return (ret | !result);
}

int check_ptr_and_print_dbg(const char* func, file_type_t file_type, void* ptr) {
    int ret     = 0;
    bool result = 0;

    if (!func)
        return -1;

    if (file_type == PROTECTED) {
        result = (ptr == NULL) ? 1 : 0;

        printf("\n%s, %s, file_type=%s, ptr=%p, errno=%d\n", func, EXPECTED_TRUE(result),
               "PROTECTED", ptr, errno);
    } else {
        result = (ptr != NULL) ? 1 : 0;

        printf("\n%s, %s, file_type=%s, ptr=%p, errno=%d\n", func, EXPECTED_TRUE(result), "NORMAL",
               ptr, errno);
    }

    // Note: Helps to verify that over-riding apis set the correct errno
    errno = 0;

    return (ret | !result);
}

int check_fd_and_print_dbg(const char* func, file_type_t file_type, int fd) {
    int ret     = 0;
    bool result = 0;

    if (!func)
        return -1;

    if (file_type == PROTECTED) {
        result = (fd == -1) ? 1 : 0;

        printf("\n%s, %s, file_type=%s, fd=%d, errno=%d\n", func, EXPECTED_TRUE(result),
               "PROTECTED", fd, errno);
    } else {
        result = (fd > 0) ? 1 : 0;

        printf("\n%s, %s, file_type=%s, fd=%d, errno=%d\n", func, EXPECTED_TRUE(result), "NORMAL",
               fd, errno);
    }

    // Note: Helps to verify that over-riding apis set the correct errno
    errno = 0;

    return (ret | !result);
}

int check_errno_and_print_dbg(const char* func, file_type_t file_type, wint_t ret_val) {
    int ret     = 0;
    bool result = 0;

    if (!func)
        return -1;

    if (file_type == PROTECTED) {
        result = (errno == ENOTSUP) ? 1 : 0;

        printf("\n%s, %s, file_type=%s, errno=%d, ret_val=%d\n", func, EXPECTED_TRUE(result),
               "PROTECTED", errno, ret_val);
    } else {
        result = (errno == 0) ? 1 : 0;

        printf("\n%s, %s, file_type=%s, errno=%d, ret_val=%d\n", func, EXPECTED_TRUE(result),
               "NORMAL", errno, ret_val);
    }

    // Note: Helps to verify that over-riding apis set the correct errno
    errno = 0;

    return (ret | !result);
}

int check_bool_and_print_dbg(const char* func, file_type_t file_type, bool result, char* dbg_str) {
    int ret = 0;

    if (!func)
        return -1;

    printf("\n%s, %s, file_type=%s, errno=%d, dbg_str->%s\n", func, EXPECTED_TRUE(result),
           (file_type == PROTECTED) ? "PROTECTED"
                                    : ((file_type == NORMAL) ? "NORMAL" : "NOT_APPLICABLE"),
           errno, dbg_str);

    // Note: Helps to verify that over-riding apis set the correct errno
    errno = 0;

    return (ret | !result);
}

int open_file_wrapper(const char* path_to_file, FILE** fp) {
    int ret   = 0;
    FILE* sfp = NULL;

    if (!path_to_file || !fp)
        return -1;

    printf("\nsizeof(path)=%lu, file-name=%s\n", strlen(path_to_file), path_to_file);

    sfp = fopen((const char*)path_to_file, "rb");

    if (sfp == NULL) {
        printf("DEBUG, creating new testfile in wb+ mode \n");

        sfp = fopen((const char*)path_to_file, "wb+");
    } else {
        fclose(sfp);
        // Note: changed mode from ab+ to wb+ to shorten
        // debug output of file content, to ease debugging.
        /*printf("DEBUG, opening existing file in ab+ mode\n");
        sfp = fopen((const char*)path_to_file, "ab+");*/
        printf("DEBUG, opening existing file in wb+ mode\n");
        sfp = fopen((const char*)path_to_file, "wb+");
    }

    if (!sfp) {
        printf("DEBUG, %s:%d, error sfp=%p is NULL\n", __func__, __LINE__, sfp);
        return -1;
    } else {
        *fp = sfp;
    }

    return ret;
}

int create_test_file(const char* path_to_file) {
    FILE* sfp                 = NULL;
    size_t buffer_len         = 0;
    uint8_t string_to_write[] = "Trial run";
    int32_t ret_val           = 0;

    if (!path_to_file) {
        printf("\nDEBUG: invalid params to %s", __func__);
        return -1;
    }

    ret_val = open_file_wrapper(path_to_file, &sfp);

    if (ret_val != 0) {
        return ret_val;
    }

    buffer_len = fwrite(string_to_write, sizeof(uint8_t), sizeof(string_to_write), sfp);
    // printf("DEBUG, after fwrite, buffer_len = %d\n", (int)buffer_len);

    ret_val = fclose(sfp);
    // printf("DEBUG, after fclose, ret_val = %d\n", (int)ret_val);

    return ret_val;
}

// Note: Test works fine...
int test_for_apis_supported_for_protected_files(const char* path_to_file, file_type_t file_type) {
    FILE* sfp                 = NULL;
    size_t buffer_len         = 0;
    uint8_t string_to_write[] = "Trial run";
    uint8_t read_buffer[BUFFER_SIZE];
    int32_t ret_val = 0;
    int overall_ret = 0;

    bool result = 0;
    errno       = 0;

    if (!path_to_file) {
        printf("\nDEBUG: invalid params to %s", __func__);
        return -1;
    }

    ret_val = open_file_wrapper(path_to_file, &sfp);

    if (ret_val != 0) {
        return ret_val;
    }

    buffer_len = fwrite(string_to_write, sizeof(uint8_t), sizeof(string_to_write), sfp);

    overall_ret += check_bool_and_print_dbg("fwrite", file_type,
                                            (buffer_len == sizeof(string_to_write)), (char*)"");

    ret_val = fflush(sfp);

    overall_ret += check_bool_and_print_dbg("fflush", file_type, (ret_val == 0), (char*)"");

    ret_val = ferror(sfp);

    printf("DEBUG, after ferror, ret_val = %d\n", (int)ret_val);

    memset(read_buffer, 0, sizeof(read_buffer));

    /*Note: Application needs to do a seek to reset
    the file offset to the start of the file, i.e if it tries
    to do a file read, after doing a write */
    ret_val = fseek(sfp, 0L, SEEK_SET);

    overall_ret += check_bool_and_print_dbg("fseek", file_type, (ret_val == 0), (char*)"");

    buffer_len = fread(read_buffer, sizeof(uint8_t), sizeof(read_buffer), sfp);
    // printf("DEBUG, after fread, file_len = %d\n", (int)buffer_len);

    overall_ret += check_bool_and_print_dbg("fread", file_type, (buffer_len > 0), (char*)"");

    // Read from File
    uint64_t file_offset = 0;
    file_offset          = ftell(sfp);
    // printf("DEBUG: File offset = %lu\n", file_offset);

    overall_ret += check_bool_and_print_dbg("ftell", file_type, (file_offset != -1), (char*)"");

    printf("DEBUG: Stuff fread from file byte output\n");

    for (unsigned int cnt = 0; cnt < buffer_len; cnt++) {
        printf("%c", read_buffer[cnt]);
        if (!((cnt + 1) % 12))
            printf("\n");
    }

    ret_val = feof(sfp);
    overall_ret += check_bool_and_print_dbg("feof", file_type, (ret_val != -1), (char*)"");

    clearerr(sfp);

    ret_val = feof(sfp);

    // printf("DEBUG, after feof, ret_val = %d\n", (int)ret_val);

    overall_ret += protfs_character_string_apis_test(sfp, file_type);

    ret_val = fclose(sfp);
    overall_ret += check_bool_and_print_dbg("fclose", file_type, (ret_val != -1), (char*)"");

    errno   = 0;
    ret_val = remove(path_to_file);
    overall_ret += check_bool_and_print_dbg("remove", file_type, (ret_val == 0), (char*)"");

    printf("MOUNT_POINT : %s\n", getenv("PFS_MOUNT_POINT"));

    printf("\n#######%s, file_type=%s, %s#######\n", __func__, FILE_TYPE_STRING(file_type),
           ZERO_RESULT(overall_ret));

    return overall_ret;
}

// Note: Test works fine...except for issues commented below.
int test_for_apis_unsupported_for_protected_files(const char* path_to_file, file_type_t file_type) {
    FILE* sfp       = NULL;
    FILE* fp        = NULL;
    int fd          = 0;
    int rename_ret  = 0;
    int overall_ret = 0;
    int val         = 0;

    uint8_t read_buffer[BUFFER_SIZE];
    int32_t ret_val            = 0;
    const char rename_suffix[] = "_rename";
    char* renamed_path         = NULL;

    uint8_t test_string[] = "You said what";

    if (!path_to_file) {
        printf("\nDEBUG: invalid params to %s", __func__);
        return -1;
    }

    errno = 0;

    ret_val = open_file_wrapper(path_to_file, &sfp);

    if (ret_val != 0) {
        return ret_val;
    }

    memset(read_buffer, 0, sizeof(read_buffer));

    ret_val = fseek(sfp, 0L, SEEK_SET);
    // printf("DEBUG, after fseek, ret = %d\n", (int)ret_val);

    // Read from File
    uint64_t file_offset = 0;
    file_offset          = ftell(sfp);
    printf("DEBUG: File offset = %lu\n", file_offset);

    fd = fileno(sfp);

    overall_ret += check_fd_and_print_dbg("fileno", file_type, fd);

    /* TODO: Investigate. after freopen, graphene issue: when closing a NORMAL(non-protected) file.
     * Error->malloc(): memory corruption:, FUTEX_WAIT: 0x31701b40 (val = 2) vs 2 mask = ffffffff */
    // Re-opening file with a different mode.
    /*fp = freopen(path_to_file, "rw+", sfp);

    overall_ret += check_ptr_and_print_dbg("freopen", file_type, (void*)fp);

    if (fp != NULL)
        ret_val = fclose(fp);*/

    fpos_t position;

    ret_val = fgetpos(sfp, &position);

    overall_ret += check_ret_and_print_dbg("fgetpos", file_type, ret_val);

    ret_val = fsetpos(sfp, &position);

    overall_ret += check_ret_and_print_dbg("fsetpos", file_type, ret_val);

    /* TODO: Investigate/resolve below.
     * For NORMAL file, seeing error below.
     * Error->Saturation error in exit code -131, getting rounded down to 125
     * For PROTECTED file, since library does NOT handle, it seg-faults.
     */
    /*
        ret_val = fscanf(sfp, "%d", &val);

        overall_ret += check_bool_and_print_dbg(
            "fscanf", file_type,
            ((file_type == NORMAL && ret_val > 0) || (file_type == PROTECTED && ret_val == -1)),
            (char*)"");

        ret_val = fprintf(sfp, "%d", val);

        overall_ret += check_bool_and_print_dbg(
            "fprintf", file_type,
            ((file_type == NORMAL && ret_val > 0) || (file_type == PROTECTED && ret_val == -1)),
            (char*)"");

        ret_val = fwscanf(sfp, (wchar_t*)"%d", &val);

        overall_ret += check_bool_and_print_dbg(
            "fwscanf", file_type,
            ((file_type == NORMAL && ret_val > 0) || (file_type == PROTECTED && ret_val == -1)),
            (char*)"");

        ret_val = fwprintf(sfp, (wchar_t*)"%d", val);

        overall_ret += check_bool_and_print_dbg(
            "fwprintf", file_type,
            ((file_type == NORMAL && ret_val > 0) || (file_type == PROTECTED && ret_val == -1)),
            (char*)"");
    */

    setbuf(sfp, (char*)test_string);
    overall_ret += check_errno_and_print_dbg("setbuf", file_type, 0);

    setbuffer(sfp, (char*)test_string, sizeof(test_string));
    overall_ret += check_errno_and_print_dbg("setbuffer", file_type, 0);

    setlinebuf(sfp);
    overall_ret += check_errno_and_print_dbg("setlinebuf", file_type, 0);

    ret_val = setvbuf(sfp, (char*)test_string, _IONBF, sizeof(test_string));
    overall_ret += check_ret_and_print_dbg("setvbuf", file_type, ret_val);

    renamed_path =
        (char*)calloc((strlen(path_to_file) + strlen(rename_suffix) + 1), sizeof(uint8_t));

    if (!renamed_path) {
        printf("malloc failed");
        return -1;
    }

    strncpy(renamed_path, path_to_file, strlen(path_to_file));

    renamed_path =
        strncat(renamed_path, (const char*)rename_suffix, strlen((const char*)rename_suffix));

    printf("path to rename to=%s\n", renamed_path);

    rename_ret = rename(path_to_file, renamed_path);

    overall_ret += check_ret_and_print_dbg("rename", file_type, rename_ret);

    if (rename_ret == 0) {
        rename_ret = rename(renamed_path, path_to_file);

        snprintf(sprintf_buf_glb, SPRINTF_BUFSIZE,
                 "undoing of rename, old path=%s, new path=%s, ret_val=%d", path_to_file,
                 renamed_path, rename_ret);
        overall_ret += check_bool_and_print_dbg("rename", file_type,
                                                ((file_type == NORMAL && rename_ret == 0) ||
                                                 (file_type == PROTECTED && rename_ret == -1)),
                                                sprintf_buf_glb);
    }

    rename_ret = renameat(AT_FDCWD, path_to_file, AT_FDCWD, renamed_path);

    overall_ret += check_bool_and_print_dbg(
        "renameat", file_type,
        ((file_type == NORMAL && rename_ret == -1) || (file_type == PROTECTED && rename_ret == -1)),
        "");

    if (rename_ret == 0) {
        rename_ret = renameat(AT_FDCWD, renamed_path, AT_FDCWD, path_to_file);

        snprintf(sprintf_buf_glb, SPRINTF_BUFSIZE,
                 "undoing of renameat, old path=%s, new path=%s, ret_val=%d", path_to_file,
                 renamed_path, rename_ret);
        overall_ret += check_bool_and_print_dbg("rename", file_type,
                                                ((file_type == NORMAL && rename_ret == 0) ||
                                                 (file_type == PROTECTED && rename_ret == -1)),
                                                sprintf_buf_glb);
    }

    /* TODO: Investigate graphene issue: Calling fclose ..after
     * successful rename on NORMAL file...causes error below:
     * Error->Fail: Trying to drop reference count below 0
     * Saturation error in exit code -131, getting rounded down to 125
     */
    if (file_type != NORMAL)
        ret_val = fclose(sfp);

    if (renamed_path)
        free(renamed_path);

    printf("\n#######%s, file_type=%s, %s#######\n", __func__, FILE_TYPE_STRING(file_type),
           ZERO_RESULT(overall_ret));

    return overall_ret;
}

// Note: Test works fine...
int test_for_blocking_apis_that_return_file_descriptor(const char* path_to_file,
                                                       file_type_t file_type) {
    int ret         = 0;
    int overall_ret = 0;
    int fd;

    int flags = O_CREAT;

    mode_t mode = S_IRWXU | S_IRGRP | S_IROTH;

    errno = 0;

    fd = creat(path_to_file, mode);

    overall_ret += check_fd_and_print_dbg("creat", file_type, fd);

    ret = close(fd);

    overall_ret += check_ret_and_print_dbg("close", file_type, ret);

    fd = open(path_to_file, flags, mode);

    overall_ret += check_fd_and_print_dbg("open", file_type, fd);

    ret = close(fd);

    overall_ret += check_ret_and_print_dbg("close", file_type, ret);

    flags = O_RDWR;

    fd = open(path_to_file, flags);

    // printf("fd=%d, after open without mode\n", fd);
    overall_ret += check_fd_and_print_dbg("open", file_type, fd);

    ret = close(fd);

    overall_ret += check_ret_and_print_dbg("close", file_type, ret);

    fd = open(path_to_file, O_TMPFILE | O_RDWR, mode);

    // printf("fd=%d, after open using O_TMPFILE\n", fd);
    overall_ret += check_fd_and_print_dbg("open", file_type, fd);

    close(fd);

    flags = O_CREAT;

    fd = openat(0, path_to_file, flags, mode);

    // printf("fd=%d, after openat\n", fd);
    overall_ret += check_fd_and_print_dbg("openat", file_type, fd);

    flags = O_RDWR;

    fd = openat(0, path_to_file, flags);

    // printf("fd=%d, after openat without mode\n", fd);
    overall_ret += check_fd_and_print_dbg("openat", file_type, fd);

    close(fd);

    printf("\n#######%s, file_type=%s, %s#######\n", __func__, FILE_TYPE_STRING(file_type),
           ZERO_RESULT(overall_ret));

    return overall_ret;
}

int test_for_misc_test_cases1(const char* path_to_file, file_type_t file_type) {
    int overall_ret = 0;

    errno = 0;

    overall_ret += protfs_file_offset_apis_test(path_to_file, file_type);
    overall_ret += system_apis_open_close(path_to_file, file_type);

    printf("\n#######%s, file_type=%s, %s#######\n", __func__, FILE_TYPE_STRING(file_type),
           ZERO_RESULT(overall_ret));

    return overall_ret;
}

int test_for_misc_test_cases2() {
    int overall_ret = 0;

    errno = 0;

    overall_ret += protfs_secure_io_path_test();
    overall_ret += protfs_app_long_filename_test();

    printf("\n#######%s, %s#######\n", __func__, ZERO_RESULT(overall_ret));

    return overall_ret;
}

static int open_file_wrapper_64bit(const char* path_to_file, FILE** fp) {
    int ret   = 0;
    FILE* sfp = NULL;

    if (!path_to_file || !fp)
        return -1;

    printf("sizeof(path)=%lu, file-name=%s\n", strlen(path_to_file), path_to_file);

    sfp = fopen64((const char*)path_to_file, "rb+");

    if (sfp == NULL) {
        printf("DEBUG, creating new testfile in wb+ mode \n");

        sfp = fopen64((const char*)path_to_file, "w+b");
    } else {
        fclose(sfp);
        printf("DEBUG, opening existing file in ab+ mode\n");

        sfp = fopen64((const char*)path_to_file, "a+b");
    }

    if (!sfp) {
        printf("DEBUG, %s:%d, error sfp=%p is NULL\n", __func__, __LINE__, sfp);
        return -1;
    } else {
        *fp = sfp;
    }

    return ret;
}

static int blocking_64bit_apis_that_return_file_descriptor(const char* path_to_file,
                                                           file_type_t file_type) {
    int ret_val     = 0;
    int overall_ret = 0;

    int fd;

    int flags = O_CREAT;

    mode_t mode = S_IRWXU | S_IRGRP | S_IROTH;

    fd = creat64(path_to_file, mode);

    overall_ret += check_fd_and_print_dbg("creat64", file_type, fd);

    close(fd);

    fd = open64(path_to_file, flags, mode);

    overall_ret += check_fd_and_print_dbg("open64", file_type, fd);

    ret_val = close(fd);

    overall_ret += check_ret_and_print_dbg("close", file_type, ret_val);

    flags = O_RDWR;

    // open without mode
    fd = open64(path_to_file, flags);

    overall_ret += check_fd_and_print_dbg("open64", file_type, fd);

    ret_val = close(fd);

    overall_ret += check_ret_and_print_dbg("close", file_type, ret_val);

    // open using O_TMPFILE
    fd = open64(path_to_file, O_TMPFILE | O_RDWR, mode);

    overall_ret += check_fd_and_print_dbg("open64", file_type, fd);

    close(fd);

    flags = O_CREAT;

    fd = openat64(0, path_to_file, flags, mode);

    overall_ret += check_fd_and_print_dbg("openat64", file_type, fd);

    flags = O_RDWR;

    // openat without mode
    fd = openat64(0, path_to_file, flags);

    overall_ret += check_fd_and_print_dbg("openat64", file_type, fd);

    close(fd);

    return overall_ret;
}

static int protfs_override_test_64bit(const char* path_to_file, file_type_t file_type) {
    FILE* sfp                 = NULL;
    size_t buffer_len         = 0;
    uint8_t string_to_write[] = "Trial run";
    uint8_t read_buffer[BUFFER_SIZE];
    int32_t ret_val = 0;
    int overall_ret = 0;

    if (!path_to_file) {
        printf("\nDEBUG: invalid params to %s", __func__);
        return -1;
    }

    ret_val = open_file_wrapper_64bit(path_to_file, &sfp);

    if (ret_val != 0) {
        return ret_val;
    }

    buffer_len = fwrite(string_to_write, sizeof(uint8_t), sizeof(string_to_write), sfp);
    printf("DEBUG, after fwrite, buffer_len = %d\n", (int)buffer_len);

    ret_val = fflush(sfp);
    printf("DEBUG, after fflush, ret_val = %d\n", (int)ret_val);

    memset(read_buffer, 0, sizeof(read_buffer));

    ret_val = fseeko64(sfp, 0L, SEEK_SET);
    printf("DEBUG, after fseek, ret = %d\n", (int)ret_val);

    buffer_len = fread(read_buffer, sizeof(uint8_t), sizeof(read_buffer), sfp);
    printf("DEBUG, after fread, file_len = %d\n", (int)buffer_len);

    // Read from File
    uint64_t file_offset = 0;
    file_offset          = ftello64(sfp);
    printf("DEBUG: File offset = %lu\n", file_offset);

    printf("DEBUG: Stuff fread from file byte output\n");

    for (unsigned int cnt = 0; cnt < buffer_len; cnt++) {
        printf("%c", read_buffer[cnt]);
        if (!((cnt + 1) % 12))
            printf("\n");
    }

    fpos64_t position;
    FILE* new_fp = NULL;

    ret_val = fgetpos64(sfp, &position);

    overall_ret += check_ret_and_print_dbg("fgetpos64", file_type, ret_val);

    fputs("Hello, World!", sfp);

    ret_val = fsetpos64(sfp, &position);

    overall_ret += check_ret_and_print_dbg("fsetpos64", file_type, ret_val);

    // If filename is NOT specified..it will close the original
    // file and re-open with the new mode.
    new_fp = freopen64("", "rw+", sfp);

    overall_ret += check_ptr_and_print_dbg("freopen64", file_type, (void*)new_fp);

    fclose(sfp);

    return overall_ret;
}

int test_for_64bit_apis(const char* path_to_file, file_type_t file_type) {
    int overall_ret = 0;

    errno = 0;

    overall_ret += protfs_override_test_64bit(path_to_file, file_type);
    overall_ret += blocking_64bit_apis_that_return_file_descriptor(path_to_file, file_type);

    printf("\n#######%s, file_type=%s, %s#######\n", __func__, FILE_TYPE_STRING(file_type),
           ZERO_RESULT(overall_ret));

    return overall_ret;
}

// TODO: Test code for vfscanf, vfprintf
