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

#ifndef _FILEOPS_TYPEDEFS_H_
#define _FILEOPS_TYPEDEFS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>

int check_use_of_custom_key();

typedef FILE* (*fopen_f_type)(const char* filename, const char* mode);
typedef int (*fclose_f_type)(FILE* stream);
typedef size_t (*fread_f_type)(void* ptr, size_t size, size_t nmemb, FILE* stream);
typedef size_t (*fwrite_f_type)(const void* ptr, size_t size, size_t nmemb, FILE* stream);
typedef int (*fseek_f_type)(FILE* stream, long int offset, int whence);
typedef long (*ftell_f_type)(FILE* stream);
typedef int (*fflush_f_type)(FILE* stream);
typedef int (*ferror_f_type)(FILE* stream);
typedef int (*feof_f_type)(FILE* stream);
typedef void (*clearerr_f_type)(FILE* stream);
typedef int (*remove_f_type)(const char* path);

typedef void (*rewind_f_type)(FILE* stream);
typedef int (*getc_f_type)(FILE* stream);
typedef int (*ungetc_f_type)(int c, FILE* stream);

typedef void (*flockfile_f_type)(FILE* stream);
typedef void (*funlockfile_f_type)(FILE* stream);
typedef int (*ftrylockfile_f_type)(FILE* stream);

typedef char* (*fgets_f_type)(char* s, int size, FILE* stream);
typedef int (*fputs_f_type)(const char* s, FILE* stream);
typedef int (*fgetc_f_type)(FILE* stream);
typedef int (*putc_f_type)(int c, FILE* stream);

typedef int (*creat_f_type)(const char* filename, mode_t mode);
// Note: open and openat, can take additional mode param.
typedef int (*open_f_type)(const char* filename, int flags, ...);
typedef int (*openat_f_type)(int dirfd, const char* filename, int flags, ...);

typedef int (*fseeko_f_type)(FILE* stream, off_t offset, int whence);
typedef off_t (*ftello_f_type)(FILE* stream);

/* Other file stream apis */
typedef int (*fgetpos_f_type)(FILE* stream, fpos_t* pos);
typedef int (*fsetpos_f_type)(FILE* stream, const fpos_t* pos);

typedef void (*setbuf_f_type)(FILE* stream, char* buf);
typedef void (*setbuffer_f_type)(FILE* stream, char* buf, size_t size);
typedef void (*setlinebuf_f_type)(FILE* stream);
typedef int (*setvbuf_f_type)(FILE* stream, char* buf, int mode, size_t size);

typedef int (*rename_f_type)(const char* oldpath, const char* newpath);
typedef int (*renameat_f_type)(int olddirfd, const char* oldpath, int newdirfd,
                               const char* newpath);

typedef wint_t (*fgetwc_f_type)(FILE* stream);
typedef wint_t (*getwc_f_type)(FILE* stream);
typedef wchar_t* (*fgetws_f_type)(wchar_t* ws, int n, FILE* stream);
typedef wint_t (*ungetwc_f_type)(wint_t wc, FILE* stream);
typedef wint_t (*fputwc_f_type)(wchar_t wc, FILE* stream);
typedef wint_t (*putwc_f_type)(wchar_t wc, FILE* stream);
typedef int (*fputws_f_type)(const wchar_t* ws, FILE* stream);

typedef int (*vfscanf_f_type)(FILE* stream, const char* format, va_list ap);
typedef int (*vfprintf_f_type)(FILE* stream, const char* format, va_list ap);
typedef int (*vfwscanf_f_type)(FILE* /*restrict*/ stream, const wchar_t* /*restrict*/ format,
                               va_list ap);
typedef int (*vfwprintf_f_type)(FILE* /*restrict*/ stream, const wchar_t* /*restrict*/ format,
                                va_list ap);

typedef int (*fwide_f_type)(FILE* stream, int mode);

typedef int (*fileno_f_type)(FILE* stream);

typedef FILE* (*freopen_f_type)(const char* path, const char* mode, FILE* stream);

/* other apis */
typedef int (*truncate_f_type)(const char* path, off_t length);

/*64 bit apis */
typedef int (*fseeko64_f_type)(FILE* stream, off64_t offset, int whence);
typedef off64_t (*ftello64_f_type)(FILE* stream);
typedef int (*fgetpos64_f_type)(FILE* stream, fpos64_t* pos);
typedef int (*fsetpos64_f_type)(FILE* stream, const fpos64_t* pos);

/*Referencing global pointers, to prevent overloading fops library,
 * and call glibC api.*/
extern fopen_f_type fopen_fn_glb;
extern open_f_type open_fn_glb;

// Note: Below apis are common to both 32/64 bit.
extern fclose_f_type fclose_fn_glb;
extern fread_f_type fread_fn_glb;
extern fwrite_f_type fwrite_fn_glb;
extern fflush_f_type fflush_fn_glb;
extern ferror_f_type ferror_fn_glb;
extern feof_f_type feof_fn_glb;
extern clearerr_f_type clearerr_fn_glb;
extern remove_f_type remove_fn_glb;
extern fileno_f_type fileno_fn_glb;

// Note: ProtectFS apis dont have size limitation..so it uses fseeko/ftello
extern fseeko_f_type fseeko_fn_glb;
extern ftello_f_type ftello_fn_glb;

#endif  //_FILEOPS_TYPEDEFS_H_
