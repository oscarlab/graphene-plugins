#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#include <stdarg.h>
#include <string.h>

#include "protfs_debug.h"

#include "perf_meas.h"
#include "protfs_app.h"
#include "protfs_dirops.h"

static int wide_format_vfwscanf(FILE* stream, const wchar_t* format, ...) {
    int ret = 0;
    va_list args;
    va_start(args, format);
    ret = vfwscanf(stream, format, args);
    printf("\n%s, ret->%d\n:", __func__, ret);

    va_end(args);

    return ret;
}

static int wide_format_vfwprintf(FILE* stream, const wchar_t* format, ...) {
    int ret = 0;

    va_list args;
    va_start(args, format);
    ret = vfwprintf(stream, format, args);
    printf("\n%s, ret->%d\n:", __func__, ret);

    va_end(args);

    return ret;
}

int test_for_wide_char_apis_unsupported(const char* path_to_file, file_type_t file_type) {
    FILE* sfp   = NULL;
    int ret_val = 0;

    wint_t wc;
    wint_t wc2;
    wchar_t test_string[100];
    wchar_t* ret_str = NULL;

    bool result     = 0;
    int overall_ret = 0;

    errno = 0;

    if (!path_to_file) {
        printf("\nDEBUG: invalid params to %s", __func__);
        return -1;
    }

    ret_val = open_file_wrapper(path_to_file, &sfp);

    if (ret_val != 0) {
        return ret_val;
    }

    fputs("Hello World\n", sfp);

    fclose(sfp);

    sfp = fopen(path_to_file, "ab+");
    if (!sfp) {
        perror("Can't open file for reading");
        return EXIT_FAILURE;
    }

    ret_val = fseek(sfp, 0L, SEEK_SET);
    printf("DEBUG, after fseek, ret = %d\n", (int)ret_val);

    uint64_t file_offset = 0;
    file_offset          = ftell(sfp);
    printf("DEBUG: File offset = %lu\n", file_offset);

    while ((wc = fgetwc(sfp)) != WEOF) {
        putwchar(wc);
    }

    overall_ret += check_errno_and_print_dbg("fgetwc", file_type, wc);

    ret_val = fseek(sfp, 0L, SEEK_SET);
    printf("DEBUG, after fseek, ret = %d\n", (int)ret_val);

    while ((wc = getwc(sfp)) != WEOF) {
        putwchar(wc);
    }

    overall_ret += check_errno_and_print_dbg("getwc", file_type, wc);

    ret_val = fseek(sfp, 0L, SEEK_SET);
    printf("DEBUG, after fseek, ret = %d\n", (int)ret_val);

    wc  = getwc(sfp);
    wc2 = ungetwc(wc, sfp);

    overall_ret += check_errno_and_print_dbg("ungetwc", file_type, wc);

    ret_val = fseek(sfp, 0L, SEEK_SET);
    wc      = fputwc(L'I', sfp);
    overall_ret += check_errno_and_print_dbg("fputwc", file_type, wc);

    wc = putwc(L'J', sfp);
    overall_ret += check_errno_and_print_dbg("putwc", file_type, wc);

    ret_val = fseek(sfp, 0L, SEEK_SET);

    ret_str = fgetws(test_string, sizeof(test_string), sfp);

    result = 0;
    if (file_type == NORMAL) {
        if (ret_str != NULL) {
            if (wcsncmp(ret_str, test_string, wcslen(test_string)) == 0) {
                result = 1;
            }
        }
    } else if (file_type == PROTECTED && ret_str == NULL && errno == ENOTSUP) {
        result = 1;
    }

    overall_ret += check_bool_and_print_dbg("fgetws", file_type, result, (char*)"");

    ret_val = fputws(test_string, sfp);
    result  = 0;
    if ((file_type == NORMAL && ret_val > 0) || (file_type == PROTECTED && ret_val == -1)) {
        result = 1;
    }
    overall_ret += check_bool_and_print_dbg("fputws", file_type, result, (char*)"");

    ret_val = fwide(sfp, 0);

    result = 0;
    if ((file_type == NORMAL && ret_val > 0) || (file_type == PROTECTED && ret_val == 0)) {
        result = 1;
    }
    overall_ret += check_bool_and_print_dbg("fwide", file_type, result, (char*)"");

    ret_val = wide_format_vfwscanf(sfp, L" %ls", test_string);

    result = 0;
    if ((file_type == NORMAL && ret_val > 0) || (file_type == PROTECTED && ret_val == -1)) {
        result = 1;
    }
    overall_ret += check_bool_and_print_dbg("vfwscanf", file_type, result, (char*)"");

    ret_val = wide_format_vfwprintf(sfp, L"String with wide-char variable %ls.\n", L"arguments");

    result = 0;
    if ((file_type == NORMAL && ret_val > 0) || (file_type == PROTECTED && ret_val == -1)) {
        result = 1;
    }
    overall_ret += check_bool_and_print_dbg("vfwprintf", file_type, result, (char*)"");

    fclose(sfp);

    printf("\n#######%s, file_type=%s, %s#######\n", __func__, FILE_TYPE_STRING(file_type),
           ZERO_RESULT(overall_ret));

    return overall_ret;
}
