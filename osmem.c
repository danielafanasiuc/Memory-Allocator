// SPDX-License-Identifier: BSD-3-Clause
#include "osmem.h"
#include "block_meta.h"
#include "string.h"

struct block_meta *heap_block_start;
// preallocating the heap only at first malloc/calloc call
int is_heap_preallocated;
int is_calloc;

void preallocate_heap(void)
{
	// preallocating heap with size 128kb
	// for reducing the number of brk() system calls
	heap_block_start = sbrk(MMAP_THRESHOLD);
	DIE(heap_block_start == MAP_FAILED, "Preallocating the heap failed!");

	heap_block_start->status = STATUS_FREE;
	heap_block_start->size = MMAP_THRESHOLD - BLOCK_META_SIZE;
	heap_block_start->next = NULL;
	heap_block_start->prev = heap_block_start;
}

void split_block(struct block_meta *best_fit, size_t size)
{
	long remaining_size = (best_fit->size - size) - BLOCK_META_SIZE;
	// if the remaining size is too small and
	// data cannot be storaged, then don't split the block
	if (remaining_size < ALIGN(1)) {
		// mark the whole unsplitted block as allocated
		// and don't update the size, as it remains the same as before
		best_fit->status = STATUS_ALLOC;
		return;
	}

	// split the block
	// fill the metadata of both blocks
	best_fit->size = size;
	best_fit->status = STATUS_ALLOC;
	struct block_meta *rem_block = (struct block_meta *)((char *)best_fit + BLOCK_META_SIZE + size);

	rem_block->size = remaining_size;
	rem_block->status = STATUS_FREE;
	// put the leftover block after the initial block
	// and update the initial block
	rem_block->next = best_fit->next;
	rem_block->prev = best_fit;
	if (best_fit->next)
		best_fit->next->prev = rem_block;
	else
		heap_block_start->prev = rem_block;
	best_fit->next = rem_block;
}

void defer_coalesce(void)
{
	struct block_meta *curr_block = heap_block_start;

	while (curr_block) {
		if (curr_block->status == STATUS_FREE && curr_block->next &&
			curr_block->next->status == STATUS_FREE) {
			struct block_meta *init_block = curr_block;

			curr_block = curr_block->next;
			while (curr_block && curr_block->status == STATUS_FREE) {
				// do coalescing
				init_block->size += (curr_block->size + BLOCK_META_SIZE);
				init_block->next = curr_block->next;
				curr_block = curr_block->next;
			}
			if (init_block->next)
				init_block->next->prev = init_block;
			else
				heap_block_start->prev = init_block;
		}
		if (curr_block)
			curr_block = curr_block->next;
	}
}

void *find_best_fit(size_t size)
{
	struct block_meta *best_fit = NULL;

	// do deferred coalescing
	defer_coalesce();

	size_t best_size = MMAP_THRESHOLD + 1;
	struct block_meta *curr_block = heap_block_start;
	// search for best fit
	while (curr_block) {
		if (curr_block->status == STATUS_FREE &&
			curr_block->size >= size &&
			curr_block->size < best_size) {
			best_size = curr_block->size;
			best_fit = curr_block;
		}
		curr_block = curr_block->next;
	}

	// if there is a fit, try to split the block
	if (best_fit)
		split_block(best_fit, size);

	return best_fit;
}

void *os_malloc(size_t size)
{
	if (size <= 0)
		return NULL;

	// check if malloc or calloc for the threshold size
	size_t threshold = (is_calloc) ? PAGE_SIZE : MMAP_THRESHOLD;

	// blocks bigger than threshold are allocated using mmap(),
	// blocks smaller than threshold are allocated on the heap by using sbrk()
	size_t block_size = ALIGN(size);

	if (block_size + BLOCK_META_SIZE >= threshold) {
		// making an anonymous mapping
		struct block_meta *anon_mapped_block = mmap(NULL, block_size + BLOCK_META_SIZE, PROT_READ | PROT_WRITE,
												  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(anon_mapped_block == MAP_FAILED, "Couldn't make an anonymous mapping!");

		// fill the metadata
		anon_mapped_block->size = block_size;
		anon_mapped_block->status = STATUS_MAPPED;
		anon_mapped_block->next = anon_mapped_block;
		anon_mapped_block->prev = anon_mapped_block;

		return (char *)anon_mapped_block + BLOCK_META_SIZE;
	}

	// preallocating the heap
	if (!is_heap_preallocated) {
		is_heap_preallocated = 1;
		// using the circular doubly linked list implementation
		preallocate_heap();
	}

	// search for a best fit in the heap_free_blocks
	struct block_meta *best_fit = find_best_fit(block_size);

	// if there are no free blocks of size bigger than block_size
	if (!best_fit) {
		// increase heap size by using sbrk()
		// if the last block on the list is free
		// but the new block does not fit
		// use sbrk to increase heap and
		// update the size of the last block
		struct block_meta *last_block = heap_block_start->prev;

		if (last_block->status == STATUS_FREE) {
			size_t rem_size = block_size - last_block->size;

			void *tmp = sbrk(rem_size);

			DIE(tmp == MAP_FAILED, "Increasing of heap failed!");
			last_block->size = block_size;
			last_block->status = STATUS_ALLOC;
			return (char *)last_block + BLOCK_META_SIZE;
		}
		struct block_meta *new_block = sbrk(block_size + BLOCK_META_SIZE);

		DIE(new_block == MAP_FAILED, "Increasing of heap failed!");

		// fill the metadata
		new_block->size = block_size;
		new_block->status = STATUS_ALLOC;
		// add block in the end of the list
		new_block->prev = heap_block_start->prev;
		new_block->next = NULL;
		new_block->prev->next = new_block;
		heap_block_start->prev = new_block;
		return (char *)new_block + BLOCK_META_SIZE;
	}
	return (char *)best_fit + BLOCK_META_SIZE;
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *mem_block = (struct block_meta *)((char *)ptr - BLOCK_META_SIZE);

	DIE(mem_block->status == STATUS_FREE, "Cannot double free / free an unallocated space!");

	if (mem_block->status == STATUS_MAPPED) {
		// free an anonymous mapping
		int ret = munmap(mem_block, mem_block->size + BLOCK_META_SIZE);

		DIE(ret == UNMAP_FAILED, "Cannot unmap anonymous mapping!");
	} else {
		// mark block as free
		mem_block->status = STATUS_FREE;
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (size <= 0 || nmemb <= 0)
		return NULL;

	size *= nmemb;
	is_calloc = 1;

	char *new_ptr = os_malloc(size);

	memset(new_ptr, 0, ALIGN(size));

	is_calloc = 0;
	return new_ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	if (!size) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *mem_block = (struct block_meta *)((char *)ptr - BLOCK_META_SIZE);
	size_t init_payload_size = mem_block->size;
	size_t new_payload_size = ALIGN(size);

	if (mem_block->status == STATUS_FREE)
		return NULL;

	if (new_payload_size + BLOCK_META_SIZE <= MMAP_THRESHOLD) {
		// if the old block was mapped
		if (mem_block->status == STATUS_MAPPED) {
			char *new_ptr = os_malloc(size);

			memmove(new_ptr, ptr, MIN(new_payload_size, init_payload_size));
			os_free(ptr);
			return new_ptr;
		}

		// if the old block was on the heap
		// if the new size is smaller, try to split the block
		if (new_payload_size <= init_payload_size) {
			split_block(mem_block, new_payload_size);
			return ptr;
		}
		// coalesce with others if needed
		int is_coalesced = 0;

		if (mem_block->next && mem_block->next->status == STATUS_FREE) {
			is_coalesced = 1;
			struct block_meta *curr_block = mem_block->next;

			while (curr_block && curr_block->status == STATUS_FREE) {
				// do coalescing
				mem_block->size += (curr_block->size + BLOCK_META_SIZE);
				mem_block->next = curr_block->next;
				curr_block = curr_block->next;
				if (mem_block->size >= new_payload_size)
					break;
			}
			if (mem_block->next)
				mem_block->next->prev = mem_block;
			else
				heap_block_start->prev = mem_block;
		}
		// if the size of the block fits, try to split
		if (new_payload_size <= mem_block->size) {
			split_block(mem_block, new_payload_size);
			return ptr;
		}

		// reallocate the pointer and copy all data
		// if the block is the last in the list
		// make it bigger using sbrk()
		if (mem_block == heap_block_start->prev && !is_coalesced) {
			long rem_size = new_payload_size - mem_block->size;

			void *tmp = sbrk(rem_size);

			DIE(tmp == MAP_FAILED, "Increasing of heap failed!");
			mem_block->size = new_payload_size;
			mem_block->status = STATUS_ALLOC;
			return ptr;
		}

		char *new_ptr = os_malloc(size);

		memmove(new_ptr, ptr, MIN(new_payload_size, init_payload_size));
		os_free(ptr);
		return new_ptr;
	}

	// if the block needs to be allocated using mmap
	char *new_ptr = os_malloc(size);

	memmove(new_ptr, ptr, MIN(new_payload_size, init_payload_size));
	os_free(ptr);
	return new_ptr;
}
