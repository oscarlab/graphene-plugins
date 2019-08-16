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
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>

#include "protfs_debug.h"

#include "perf_meas.h"
#include "protfs_app.h"
#include "protfs_dirops.h"

int main() {
    printf("%s, pass\n", __func__);

#ifdef BASIC_SANITY_TEST_FOR_SUPPORTED_APIS_AND_READDIR_TEST
    test_for_apis_supported_for_protected_files(PATH_TO_NON_PFS_TESTFILE, NORMAL);
    test_for_apis_supported_for_protected_files(PATH_TO_PFS_TESTFILE1, PROTECTED);
    /* Test files get removed, in *supported* api above.
     * re-creating , test files to test recursive listing of
    files(with file-names decrypted for protected files). */
    create_test_file(PATH_TO_NON_PFS_TESTFILE);
    create_test_file(PATH_TO_PFS_TESTFILE1);
    create_test_file(PATH_TO_PFS_TESTFILE2);
    protfs_readdir_test();
#endif

#ifdef PROTFS_UNSUPPORTED_APIS_TEST
    test_for_apis_unsupported_for_protected_files(PATH_TO_NON_PFS_TESTFILE, NORMAL);
    test_for_apis_unsupported_for_protected_files(PATH_TO_PFS_TESTFILE1, PROTECTED);
#endif

#ifdef PROTFS_BLOCKING_APIS_THAT_RETURN_FILE_DESCRIPTOR
    // test_for_blocking_apis_that_return_file_descriptor(PATH_TO_NON_PFS_TESTFILE, NORMAL);
    test_for_blocking_apis_that_return_file_descriptor(PATH_TO_PFS_TESTFILE1, PROTECTED);
#endif

#ifdef PROTFS_MISC_TEST_CASES
    test_for_misc_test_cases1(PATH_TO_NON_PFS_TESTFILE, NORMAL);
    test_for_misc_test_cases1(PATH_TO_PFS_TESTFILE1, PROTECTED);
    test_for_misc_test_cases2();
#endif

#ifdef PROTFS_DIR_APIS_TESTING
    protfs_directory_system_apis_test();
#endif

#ifdef PROTFS_64BIT_API_TEST_CASES
    test_for_64bit_apis(PATH_TO_NON_PFS_TESTFILE, NORMAL);
    test_for_64bit_apis(PATH_TO_PFS_TESTFILE1, PROTECTED);
#endif

#ifdef PROTFS_WIDECHAR_UNSUPPORTED_APIS_TEST
    test_for_wide_char_apis_unsupported(PATH_TO_NON_PFS_TESTFILE3, NORMAL);
    test_for_wide_char_apis_unsupported(PATH_TO_PFS_TESTFILE3, PROTECTED);
#endif

#ifdef PROTFS_CONVERT_NORMAL_FILES_TO_PROTECTED_FILES
    protect_files(CLEAR_DIR_PATH, PROTECTED_DIR_PATH);
#endif

#ifdef PROTFS_API_PERF_MEAS
    protfs_run_perf_meas_test(PATH_TO_PFS_TESTFILE1);
#endif

    return 0;
}
