/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include <sys/mman.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "printf.h"
#include "block_meta.h"


#define PAGE_SIZE (size_t)(getpagesize())
#define MMAP_THRESHOLD (128 * 1024)
#define UNMAP_FAILED -1
#define MIN(a,b) (((a)<(b))?(a):(b))

void preallocate_heap(void);
void split_block(struct block_meta *best_fit, size_t size);
void defer_coalesce(void);
void *find_best_fit(size_t size);

void *os_malloc(size_t size);
void os_free(void *ptr);
void *os_calloc(size_t nmemb, size_t size);
void *os_realloc(void *ptr, size_t size);
