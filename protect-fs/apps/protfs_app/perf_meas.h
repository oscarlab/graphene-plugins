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

#ifndef _PERF_MEAS_H_
#define _PERF_MEAS_H_

#include <sys/time.h>
#include "stddef.h"
#include "stdint.h"
#include "stdio.h"

/* TODO: although we can get perf measurements for
   individual apis, for varying buffer sizes for fread/fwrite etc...
   depending on the current file size...the time for fread/fwrite..
   can vary...given that it needs to update the hash values in MHT.
   So, we need to have another test wrapper..that runs
   these cases(1K,2K,4K buf sizes..etc) for various file sizes..*/
enum apis_measured { FOPEN = 0, FREAD, FWRITE, FFLUSH, FSEEK, FTELL, FCLOSE, MAX_APIS };

struct perf_run {
    uint8_t* ptr_to_buf;
    size_t buf_len;
};

void get_time(struct timeval* time);
void compute_duration(struct timeval* t1, struct timeval* t2, float* elapsed);
void get_time_and_compute_duration(struct timeval* t1, struct timeval* t2, float* elapsed);

void protfs_run_perf_meas_test(const char* path_to_file);

#endif  //_PERF_MEAS_H_
