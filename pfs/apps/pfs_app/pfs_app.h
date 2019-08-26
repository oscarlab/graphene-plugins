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

#ifndef _PFS_APP_H_
#define _PFS_APP_H_

#include "pfs_plus.h"

/* Note: When application sets path to directory-path(and-also
 * when setting path in manifest),
 * there should NOT be any trailing backslash(/) */
#define PROTECTED_DIR_PATH "/pfs_dir/secrets"
#define CLEAR_DIR_PATH "/pfs_dir/non_secrets"
// Note: Below path mounted in manifest
#define TEST_DIR_PATH "/pfs_dir/test_dir"

#define FILENAME_MAX_LENGTH (PFS_FILENAME_MAX_LENGTH + 30)

#define FILE_PATH_MAX (4096)
#define MAX_SIZE_FOR_FILE_READ (512)

#define PATH_TO_PFS_TESTFILE1 "/pfs_dir/secrets/sub_dir1/pfs_file1"
#define PATH_TO_PFS_TESTFILE2 "/pfs_dir/secrets/sub_dir1/pfs_file2"
#define PATH_TO_PFS_TESTFILE3 "/pfs_dir/secrets/sub_dir1/pfs_file3"

#define PATH_TO_NON_PFS_TESTFILE "/pfs_dir/non_secrets/non_pfs_file1"
#define PATH_TO_NON_PFS_TESTFILE2 "/pfs_dir/non_secrets/non_pfs_file2"
#define PATH_TO_NON_PFS_TESTFILE3 "/pfs_dir/non_secrets/non_pfs_file3"

#define BUFFER_SIZE (128)
#define SPRINTF_BUFSIZE (300)

/* Note: Enable testing for different categories of system-apis,
using macros below. */
#define BASIC_SANITY_TEST_FOR_SUPPORTED_APIS_AND_READDIR_TEST
//#define PFS_UNSUPPORTED_APIS_TEST
//#define PFS_BLOCKING_APIS_THAT_RETURN_FILE_DESCRIPTOR
//#define PFS_MISC_TEST_CASES
//#define PFS_64BIT_API_TEST_CASES
//#define PFS_WIDECHAR_UNSUPPORTED_APIS_TEST
//#define PFS_DIR_APIS_TESTING

//#define PFS_CONVERT_NORMAL_FILES_TO_PROTECTED_FILES
//#define PFS_API_PERF_MEAS

#define ZERO_RESULT(ret_val) ((ret_val == 0) ? "PASS" : "ERROR")
#define EXPECTED_TRUE(result) ((result == 1) ? "PASS" : "ERROR")
#define FILE_TYPE_STRING(file_type) ((file_type == PROTECTED) ? "PROTECTED" : "NORMAL")

typedef enum file_type { NORMAL, PROTECTED, NOT_APPLICABLE } file_type_t;

int open_file_wrapper(const char* path_to_file, FILE** fp);
int create_test_file(const char* path_to_file);

int test_for_apis_supported_for_protected_files(const char* path_to_file, file_type_t file_type);
int test_for_apis_unsupported_for_protected_files(const char* path_to_file, file_type_t file_type);

int test_for_blocking_apis_that_return_file_descriptor(const char* path_to_file,
                                                       file_type_t file_type);
int test_for_misc_test_cases1(const char* path_to_file, file_type_t file_type);
int test_for_misc_test_cases2();

int test_for_wide_char_apis_unsupported(const char* path_to_file, file_type_t file_type);
int test_for_64bit_apis(const char* path_to_file, file_type_t file_type);

int protect_files(char* src_dir_path, char* dest_dir_path);

int check_ret_and_print_dbg(const char* func, file_type_t file_type, int ret_val);
int check_ptr_and_print_dbg(const char* func, file_type_t file_type, void* ptr);
int check_fd_and_print_dbg(const char* func, file_type_t file_type, int fd);
int check_errno_and_print_dbg(const char* func, file_type_t file_type, wint_t ret_val);
int check_bool_and_print_dbg(const char* func, file_type_t file_type, bool result, char* dbg_str);

#endif /* _PFS_APP_H_ */
