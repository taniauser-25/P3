#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <sys/errno.h>
#else
#include <errno.h>
#endif

#include "harness/unity.h"
#include "../src/lab.h"

void setUp(void) {
  // set stuff up here
}

void tearDown(void) {
  // clean stuff up here
}

void check_buddy_pool_full(struct buddy_pool *pool)
{
  for (size_t i = 0; i < pool->kval_m; i++) {
    assert(pool->avail[i].next == &pool->avail[i]);
    assert(pool->avail[i].prev == &pool->avail[i]);
    assert(pool->avail[i].tag == BLOCK_UNUSED);
    assert(pool->avail[i].kval == i);
  }

  assert(pool->avail[pool->kval_m].next->tag == BLOCK_AVAIL);
  assert(pool->avail[pool->kval_m].next->next == &pool->avail[pool->kval_m]);
  assert(pool->avail[pool->kval_m].prev->prev == &pool->avail[pool->kval_m]);
  assert(pool->avail[pool->kval_m].next == pool->base);
}

void check_buddy_pool_empty(struct buddy_pool *pool)
{
  for (size_t i = 0; i <= pool->kval_m; i++) {
    assert(pool->avail[i].next == &pool->avail[i]);
    assert(pool->avail[i].prev == &pool->avail[i]);
    assert(pool->avail[i].tag == BLOCK_UNUSED);
    assert(pool->avail[i].kval == i);
  }
}

void test_buddy_malloc_one_byte(void)
{
  fprintf(stderr, "->Test allocating and freeing 1 byte\n");
  struct buddy_pool pool;
  int kval = MIN_K;
  size_t size = UINT64_C(1) << kval;
  buddy_init(&pool, size);
  void *mem = buddy_malloc(&pool, 1);
  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

void test_buddy_malloc_one_large(void)
{
  fprintf(stderr, "->Testing size that will consume entire memory pool\n");
  struct buddy_pool pool;
  size_t bytes = UINT64_C(1) << MIN_K;
  buddy_init(&pool, bytes);

  size_t ask = bytes - sizeof(struct avail);
  void *mem = buddy_malloc(&pool, ask);
  assert(mem != NULL);

  struct avail *tmp = (struct avail *)mem - 1;
  assert(tmp->kval == MIN_K);
  assert(tmp->tag == BLOCK_RESERVED);
  check_buddy_pool_empty(&pool);

  void *fail = buddy_malloc(&pool, 5);
  assert(fail == NULL);
  assert(errno == ENOMEM);

  buddy_free(&pool, mem);
  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

void test_buddy_init(void)
{
  fprintf(stderr, "->Testing buddy init\n");
  for (size_t i = MIN_K; i <= DEFAULT_K; i++) {
    size_t size = UINT64_C(1) << i;
    struct buddy_pool pool;
    buddy_init(&pool, size);
    check_buddy_pool_full(&pool);
    buddy_destroy(&pool);
  }
}

void test_buddy_multiple_allocs(void) {
  struct buddy_pool pool;
  buddy_init(&pool, UINT64_C(1) << DEFAULT_K);

  void *a = buddy_malloc(&pool, 64);
  void *b = buddy_malloc(&pool, 128);
  void *c = buddy_malloc(&pool, 256);
  TEST_ASSERT_NOT_NULL(a);
  TEST_ASSERT_NOT_NULL(b);
  TEST_ASSERT_NOT_NULL(c);

  buddy_free(&pool, b);
  buddy_free(&pool, a);
  buddy_free(&pool, c);

  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

void test_buddy_invalid_inputs(void) {
  struct buddy_pool pool;
  buddy_init(&pool, UINT64_C(1) << DEFAULT_K);

  void *null_test = buddy_malloc(NULL, 100);
  TEST_ASSERT_NULL(null_test);

  void *zero_test = buddy_malloc(&pool, 0);
  TEST_ASSERT_NULL(zero_test);

  buddy_free(&pool, NULL); // should not crash

  buddy_destroy(&pool);
}

void test_buddy_reuse_after_free(void) {
  struct buddy_pool pool;
  buddy_init(&pool, UINT64_C(1) << DEFAULT_K);

  void *ptr1 = buddy_malloc(&pool, 512);
  TEST_ASSERT_NOT_NULL(ptr1);
  buddy_free(&pool, ptr1);

  void *ptr2 = buddy_malloc(&pool, 512);
  TEST_ASSERT_NOT_NULL(ptr2);
  buddy_free(&pool, ptr2);

  check_buddy_pool_full(&pool);
  buddy_destroy(&pool);
}

void test_buddy_realloc(void) {
  struct buddy_pool pool;
  buddy_init(&pool, UINT64_C(1) << DEFAULT_K);

  // Realloc with NULL (should act as malloc)
  void *a = buddy_realloc(&pool, NULL, 64);
  TEST_ASSERT_NOT_NULL(a);

  // Write some data
  memset(a, 0x42, 64);

  // Realloc to a larger size
  void *b = buddy_realloc(&pool, a, 128);
  TEST_ASSERT_NOT_NULL(b);

  // Ensure data is preserved
  char *data = (char *)b;
  for (int i = 0; i < 64; i++) {
    TEST_ASSERT_EQUAL_HEX8(0x42, data[i]);
  }

  // Realloc to 0 (should free)
  void *c = buddy_realloc(&pool, b, 0);
  TEST_ASSERT_NULL(c);

  buddy_destroy(&pool);
}


int main(void) {
  time_t t;
  unsigned seed = (unsigned)time(&t);
  fprintf(stderr, "Random seed:%d\n", seed);
  srand(seed);
  printf("Running memory tests.\n");

  UNITY_BEGIN();
  RUN_TEST(test_buddy_init);
  RUN_TEST(test_buddy_malloc_one_byte);
  RUN_TEST(test_buddy_malloc_one_large);
  RUN_TEST(test_buddy_multiple_allocs);
  RUN_TEST(test_buddy_invalid_inputs);
  RUN_TEST(test_buddy_reuse_after_free);
  RUN_TEST(test_buddy_realloc);
  return UNITY_END();
}
