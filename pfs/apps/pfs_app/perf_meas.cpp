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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/time.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>

#include "perf_meas.h"

#include <errno.h>
#include <time.h>

#include "pfs_app.h"

float perf_meas[MAX_APIS];
// Note: Order of strings needs to match, with enum->apis_measured above.
char apis_meas[MAX_APIS][255] = {"fopen", "fread", "fwrite", "fflush", "fseek", "ftell", "fclose"};

uint8_t onek_buf[1024]   = {1};
uint8_t twok_buf[2048]   = {2};
uint8_t fourk_buf[4096]  = {4};
uint8_t eightk_buf[8192] = {8};

struct perf_run runs[] = {{onek_buf, sizeof(onek_buf)},
                          {twok_buf, sizeof(twok_buf)},
                          {fourk_buf, sizeof(fourk_buf)},
                          {eightk_buf, sizeof(eightk_buf)}};

void get_time(struct timeval* time) {
    if (!time)
        return;

    gettimeofday(time, NULL);
}

void compute_duration(struct timeval* t1, struct timeval* t2, float* elapsed) {
    if (!t1 || !t2 || !elapsed)
        return;

    *elapsed = t2->tv_sec - t1->tv_sec;
    *elapsed += (t2->tv_usec - t1->tv_usec) / 1e6;
}

void get_time_and_compute_duration(struct timeval* t1, struct timeval* t2, float* elapsed) {
    if (!t1 || !t2 || !elapsed)
        return;

    get_time(t2);

    compute_duration(t1, t2, elapsed);
}

void print_perf_meas(size_t buf_len, bool pfs_file) {
    int i = 0;

    printf("\nperf meas for file_type=%s, buf_size=%lu\n",
           ((pfs_file) ? "PFS_FILE" : "NON_PFS_FILE"), buf_len);

    for (i = 0; i < MAX_APIS; i++) {
        printf("%s, %f\n", apis_meas[i], perf_meas[i]);
    }
}

int pfs_perf_meas_test(const char* path_to_file, uint8_t* input_buf, size_t buf_len) {
    FILE* sfp         = NULL;
    size_t buffer_len = 0;
    int32_t ret_val   = 0;
    struct timeval t1, t2;
    float elapsed;

    if (!path_to_file || !input_buf || (buf_len == 0)) {
        printf("\nDEBUG: invalid params to %s", __func__);
        return -1;
    }

    printf("\nsizeof(path)=%lu, file-name=%s", strlen(path_to_file), path_to_file);

    get_time(&t1);
    sfp = fopen((const char*)path_to_file, "rb+");

    if (sfp != NULL)
        get_time_and_compute_duration(&t1, &t2, &elapsed);
    perf_meas[FOPEN] = elapsed;

    printf("\nDEBUG, %s:%d, after fopen to check if file exists, sfp=%p\n", __func__, __LINE__,
           sfp);

    if (sfp == NULL) {
        printf("\nDEBUG, creating new testfile in wb+ mode \n");

        get_time(&t1);
        sfp = fopen((const char*)path_to_file, "w+b");
        get_time_and_compute_duration(&t1, &t2, &elapsed);
        perf_meas[FOPEN] = elapsed;
    } else {
        fclose(sfp);
        printf("\nDEBUG, opening existing file-%s in ab+ mode\n", path_to_file);

        sfp = fopen((const char*)path_to_file, "a+b");
    }

    printf("\nDEBUG, %s:%d, after open, sfp=%p\n", __func__, __LINE__, sfp);

    if (!sfp) {
        printf("\nDEBUG, %s:%d, error sfp=%p is NULL\n", __func__, __LINE__, sfp);
        return -1;
    }

    get_time(&t1);
    buffer_len = fwrite(input_buf, sizeof(uint8_t), buf_len, sfp);
    get_time_and_compute_duration(&t1, &t2, &elapsed);
    perf_meas[FWRITE] = elapsed;
    printf("DEBUG, after fwrite, buffer_len = %d\n", (int)buffer_len);

    /*Note: skipping fflush here, and trying to measure..potential
      flush from cache..during fclose
    get_time(&t1);
    ret_val = fflush(sfp);
    get_time_and_compute_duration(&t1, &t2, &elapsed);
    perf_meas[FFLUSH] = elapsed;
    printf("DEBUG, after fflush, ret_val = %d\n", (int)ret_val);
    */

    ret_val = ferror(sfp);
    printf("DEBUG, after ferror, ret_val = %d\n", (int)ret_val);

    memset(input_buf, 0, buf_len);

    get_time(&t1);
    ret_val = fseek(sfp, 0L, SEEK_SET);
    get_time_and_compute_duration(&t1, &t2, &elapsed);
    perf_meas[FSEEK] = elapsed;
    printf("DEBUG, after fseek, ret = %d\n", (int)ret_val);

    get_time(&t1);
    buffer_len = fread(input_buf, sizeof(uint8_t), buf_len, sfp);
    get_time_and_compute_duration(&t1, &t2, &elapsed);
    perf_meas[FREAD] = elapsed;
    printf("\nDEBUG, after fread, buffer_len = %d\n", (int)buffer_len);

    // Read from File
    uint64_t file_offset = 0;
    get_time(&t1);
    file_offset = ftell(sfp);
    get_time_and_compute_duration(&t1, &t2, &elapsed);
    perf_meas[FTELL] = elapsed;
    printf("\nDEBUG: File offset = %lu\n", file_offset);

    ret_val = feof(sfp);
    printf("DEBUG, after feof, ret_val = %d\n", (int)ret_val);

    clearerr(sfp);
    printf("DEBUG, after clearerr\n");

    ret_val = feof(sfp);
    printf("DEBUG, after feof, ret_val = %d\n", (int)ret_val);

    get_time(&t1);
    ret_val = fclose(sfp);
    get_time_and_compute_duration(&t1, &t2, &elapsed);
    perf_meas[FCLOSE] = elapsed;
    printf("DEBUG, after fclose, ret_val = %d\n", (int)ret_val);

    // ret_val = remove(path_to_file);
    // printf("DEBUG, after remove, ret_val = %d\n", (int)ret_val);

    return ret_val;
}

void pfs_run_perf_meas_test(const char* path_to_file) {
    struct timeval t1, t2;
    float elapsed;
    unsigned int i;

    printf("%s: %d\n", __func__, __LINE__);

    if (!path_to_file)
        return;

    printf("runs=%lu, perf=%lu, val=%lu\n", sizeof(runs), sizeof(struct perf_run),
           sizeof(runs) / sizeof(struct perf_run));

    for (i = 0; i < sizeof(runs) / sizeof(struct perf_run); i++) {
        get_time(&t1);
        pfs_perf_meas_test(path_to_file, runs[i].ptr_to_buf, runs[i].buf_len);
        get_time_and_compute_duration(&t1, &t2, &elapsed);
        printf(
            "time taken by pfs_perf_meas_test for NON_PFS: %f sec, "
            "buf_size=%lu\n",
            elapsed, runs[i].buf_len);
        print_perf_meas(runs[i].buf_len, 0);
    }

    for (i = 0; i < sizeof(runs) / sizeof(struct perf_run); i++) {
        get_time(&t1);
        pfs_perf_meas_test(path_to_file, runs[i].ptr_to_buf, runs[i].buf_len);
        get_time_and_compute_duration(&t1, &t2, &elapsed);
        printf(
            "time taken by pfs_perf_meas_test for PFS: %f sec, "
            "buf_size=%lu\n",
            elapsed, runs[i].buf_len);
        print_perf_meas(runs[i].buf_len, 1);
    }

    return;
}
