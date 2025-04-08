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
        raise(SIGKILL);          \
    } while (0)

/**
 * @brief Convert bytes to the correct K value
 *
 * @param bytes the number of bytes
 * @return size_t the K value that will fit bytes
 */
size_t btok(size_t bytes) {
    size_t k = 0;
    size_t block_size = 1;
    while (block_size < bytes) {
        block_size <<= 1;  // multiply by 2 using bit shifting
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

    // Find block or split
    size_t i = kval;
    while (i <= pool->kval_m && pool->avail[i].next == &pool->avail[i]) {
        i++;
    }

    if (i > pool->kval_m) {
        errno = ENOMEM;
        return NULL;
    }

    // Split down from level i to kval
    while (i > kval) {
        struct avail *block = pool->avail[i].next;

        // Remove from free list
        block->prev->next = block->next;
        block->next->prev = block->prev;

        i--;

        // Split the block
        size_t block_size = UINT64_C(1) << i;
        struct avail *buddy = (struct avail *)((char *)block + block_size);

        block->kval = i;
        buddy->kval = i;
        block->tag = BLOCK_AVAIL;
        buddy->tag = BLOCK_AVAIL;

        // Insert both blocks into the lower level
        block->next = buddy->prev = &pool->avail[i];
        block->prev = buddy;
        buddy->next = block;
        pool->avail[i].next = block;
        pool->avail[i].prev = buddy;
    }

    // Finally, allocate block
    struct avail *final_block = pool->avail[kval].next;

    // Remove from free list
    final_block->prev->next = final_block->next;
    final_block->next->prev = final_block->prev;

    final_block->tag = BLOCK_RESERVED;

    return (void *)(final_block + 1); // skip header
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

        // Buddy must be removed from the list
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;

        // Merge: use lower address
        if (buddy < block)
            block = buddy;

        block->kval++;
    }

    // Insert block into avail[kval]
    size_t kval = block->kval;
    block->next = pool->avail[kval].next;
    block->prev = &pool->avail[kval];
    pool->avail[kval].next->prev = block;
    pool->avail[kval].next = block;
}


/**
 * @brief This is a simple version of realloc.
 *
 * @param poolThe memory pool
 * @param ptr  The user memory
 * @param size the new size requested
 * @return void* pointer to the new user memory
 */
void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size)
{
    //Required for Grad Students
    //Optional for Undergrad Students
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

    //make sure pool struct is cleared out
    memset(pool,0,sizeof(struct buddy_pool));
    pool->kval_m = kval;
    pool->numbytes = (UINT64_C(1) << pool->kval_m);
    //Memory map a block of raw memory to manage
    pool->base = mmap(
        NULL,                               /*addr to map to*/
        pool->numbytes,                     /*length*/
        PROT_READ | PROT_WRITE,             /*prot*/
        MAP_PRIVATE | MAP_ANONYMOUS,        /*flags*/
        -1,                                 /*fd -1 when using MAP_ANONYMOUS*/
        0                                   /* offset 0 when using MAP_ANONYMOUS*/
    );
    if (MAP_FAILED == pool->base)
    {
        handle_error_and_die("buddy_init avail array mmap failed");
    }

    //Set all blocks to empty. We are using circular lists so the first elements just point
    //to an available block. Thus the tag, and kval feild are unused burning a small bit of
    //memory but making the code more readable. We mark these blocks as UNUSED to aid in debugging.
    for (size_t i = 0; i <= kval; i++)
    {
        pool->avail[i].next = pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    //Add in the first block
    pool->avail[kval].next = pool->avail[kval].prev = (struct avail *)pool->base;
    struct avail *m = pool->avail[kval].next;
    m->tag = BLOCK_AVAIL;
    m->kval = kval;
    m->next = m->prev = &pool->avail[kval];
}

void buddy_destroy(struct buddy_pool *pool)
{
    int rval = munmap(pool->base, pool->numbytes);
    if (-1 == rval)
    {
        handle_error_and_die("buddy_destroy avail array");
    }
    //Zero out the array so it can be reused it needed
    memset(pool,0,sizeof(struct buddy_pool));
}

#define UNUSED(x) (void)x

/**
 * This function can be useful to visualize the bits in a block. This can
 * help when figuring out the buddy_calc function!
 */
static void printb(unsigned long int b)
{
     size_t bits = sizeof(b) * 8;
     unsigned long int curr = UINT64_C(1) << (bits - 1);
     for (size_t i = 0; i < bits; i++)
     {
          if (b & curr)
          {
               printf("1");
          }
          else
          {
               printf("0");
          }
          curr >>= 1L;
     }
}
