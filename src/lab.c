#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <time.h>

#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif

#include "lab.h"

#define handle_error_and_die(msg) \
    do                            \
    {                             \
        perror(msg);              \
        raise(SIGKILL);           \
    } while (0)

size_t btok(size_t bytes) {
    size_t k = 0;
    size_t block_size = 1;
    while (block_size < bytes) {
        block_size <<= 1;
        k++;
    }
    return k;
}

struct avail *buddy_calc(struct buddy_pool *pool, struct avail *block) {
    uintptr_t offset = (uintptr_t)block - (uintptr_t)pool->base;
    uintptr_t buddy_offset = offset ^ (UINT64_C(1) << block->kval);
    return (struct avail *)((uintptr_t)pool->base + buddy_offset);
}

void *buddy_malloc(struct buddy_pool *pool, size_t size)
{
    if (pool == NULL || size == 0)
        return NULL;

    size_t total_size = size + sizeof(struct avail);
    size_t kval = btok(total_size);

    if (kval < SMALLEST_K)
        kval = SMALLEST_K;

    size_t i = kval;
    while (i <= pool->kval_m && pool->avail[i].next == &pool->avail[i]) {
        i++;
    }

    if (i > pool->kval_m) {
        errno = ENOMEM;
        return NULL;
    }

    while (i > kval) {
        struct avail *block = pool->avail[i].next;
        block->prev->next = block->next;
        block->next->prev = block->prev;
        i--;

        size_t block_size = UINT64_C(1) << i;
        struct avail *buddy = (struct avail *)((char *)block + block_size);

        block->kval = i;
        buddy->kval = i;
        block->tag = BLOCK_AVAIL;
        buddy->tag = BLOCK_AVAIL;

        block->next = buddy->prev = &pool->avail[i];
        block->prev = buddy;
        buddy->next = block;
        pool->avail[i].next = block;
        pool->avail[i].prev = buddy;
    }

    struct avail *final_block = pool->avail[kval].next;
    final_block->prev->next = final_block->next;
    final_block->next->prev = final_block->prev;
    final_block->tag = BLOCK_RESERVED;

    return (void *)(final_block + 1);
}

void buddy_free(struct buddy_pool *pool, void *ptr)
{
    if (ptr == NULL || pool == NULL)
        return;

    struct avail *block = (struct avail *)ptr - 1;
    block->tag = BLOCK_AVAIL;

    while (block->kval < pool->kval_m) {
        struct avail *buddy = buddy_calc(pool, block);

        if (buddy->tag != BLOCK_AVAIL || buddy->kval != block->kval)
            break;

        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;

        if (buddy < block)
            block = buddy;

        block->kval++;
    }

    block->tag = BLOCK_AVAIL;

    block->tag = BLOCK_AVAIL;
    block->next = &pool->avail[block->kval];
    block->prev = &pool->avail[block->kval];
    pool->avail[block->kval].next = block;
    pool->avail[block->kval].prev = block;

}

void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size)
{
    if (pool == NULL)
        return NULL;

    if (ptr == NULL)
        return buddy_malloc(pool, size);

    if (size == 0) {
        buddy_free(pool, ptr);
        return NULL;
    }

    struct avail *old_block = (struct avail *)ptr - 1;
    size_t old_size = UINT64_C(1) << old_block->kval;
    size_t user_old_size = old_size - sizeof(struct avail);

    void *new_ptr = buddy_malloc(pool, size);
    if (new_ptr == NULL)
        return NULL;

    size_t min_size = size < user_old_size ? size : user_old_size;
    memcpy(new_ptr, ptr, min_size);

    buddy_free(pool, ptr);
    return new_ptr;
}

void buddy_init(struct buddy_pool *pool, size_t size)
{
    size_t kval = 0;
    if (size == 0)
        kval = DEFAULT_K;
    else
        kval = btok(size);

    if (kval < MIN_K)
        kval = MIN_K;
    if (kval > MAX_K)
        kval = MAX_K - 1;

    memset(pool, 0, sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);

    pool->base = mmap(
        NULL,
        pool->numbytes,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    if (MAP_FAILED == pool->base) {
        handle_error_and_die("buddy_init avail array mmap failed");
    }

    for (size_t i = 0; i <= kval; i++) {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    pool->avail[kval].next = pool->avail[kval].prev = (struct avail *)pool->base;
    struct avail *m = pool->avail[kval].next;
    m->tag = BLOCK_AVAIL;
    m->kval = kval;
    m->next = m->prev = &pool->avail[kval];
}

void buddy_destroy(struct buddy_pool *pool)
{
    int rval = munmap(pool->base, pool->numbytes);
    if (-1 == rval) {
        handle_error_and_die("buddy_destroy avail array");
    }
    memset(pool, 0, sizeof(struct buddy_pool));
}

#define UNUSED(x) (void)x

static void printb(unsigned long int b)
{
    size_t bits = sizeof(b) * 8;
    unsigned long int curr = UINT64_C(1) << (bits - 1);
    for (size_t i = 0; i < bits; i++) {
        printf("%c", (b & curr) ? '1' : '0');
        curr >>= 1L;
    }
}
