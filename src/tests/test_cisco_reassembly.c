/*
 * This file is part of OpenLI.
 *
 * OpenLI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * OpenLI is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for details.
 *
 * You should have received a copy of the GNU General Public License along
 * with OpenLI. If not, see <http://www.gnu.org/licenses/>.
 */
#undef NDEBUG
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../collector/cisco_reassembly.h"

static uint8_t udp[1512];
static const struct timeval stamp = {100, 7};

static void put16(uint8_t *p, unsigned value) {
    p[0] = value >> 8;
    p[1] = value;
}

static size_t fragment(uint8_t *ip, unsigned id, unsigned offset,
        unsigned length, int more) {
    memset(ip, 0, 20);
    ip[0] = 0x45;
    put16(ip + 2, length + 20);
    put16(ip + 4, id);
    put16(ip + 6, offset / 8 | (more ? 8192 : 0));
    ip[9] = 17;
    ip[12] = ip[16] = 192;
    ip[14] = ip[18] = 2;
    ip[15] = 1;
    ip[19] = 2;
    memcpy(ip + 20, udp + offset, length);
    return length + 20;
}

/* On completion, compare every transport byte and the chosen capture time. */
static int feed(cisco_reassembly_t *cache, const uint8_t *ip, size_t length,
        uint8_t context[CISCO_REASS_CONTEXT], uint64_t now) {
    struct timeval first;
    uint8_t *result = NULL;
    size_t result_length = 0;
    int complete = cisco_reassembly_feed(cache, ip, length, context, now,
            stamp, &result, &result_length, &first);

    if (complete) {
        assert(result != NULL);
        assert(result_length == sizeof(udp));
        assert(memcmp(result, udp, sizeof(udp)) == 0);
        assert(first.tv_sec == stamp.tv_sec && first.tv_usec == stamp.tv_usec);
        free(result);
    } else {
        assert(result == NULL && result_length == 0);
    }
    return complete;
}

static void test_order_and_duplicates(void) {
    uint8_t a[1600], b[1600], context[CISCO_REASS_CONTEXT] = {0};
    size_t n = fragment(a, 1, 0, 1112, 1);
    size_t m = fragment(b, 1, 1112, 400, 0);
    cisco_reassembly_t *cache = cisco_reassembly_create();
    assert(cache);

    assert(!feed(cache, a, n, context, 0));
    assert(!feed(cache, a, n, context, 0));
    assert(feed(cache, b, m, context, 0));
    assert(!feed(cache, b, m, context, 0));
    assert(!feed(cache, a, n, context, 0));

    n = fragment(a, 2, 0, 816, 1);
    m = fragment(b, 2, 816, 696, 0);
    assert(!feed(cache, b, m, context, 0));
    assert(!feed(cache, b, m, context, 0));
    assert(feed(cache, a, n, context, 0));

    n = fragment(a, 3, 0, 512, 1);
    assert(!feed(cache, a, n, context, 0));
    n = fragment(a, 3, 1024, 488, 0);
    assert(!feed(cache, a, n, context, 0));
    n = fragment(a, 3, 512, 512, 1);
    assert(feed(cache, a, n, context, 0));
    cisco_reassembly_destroy(cache);
}

static void test_invalid(void) {
    uint8_t a[1600], b[1600], context[CISCO_REASS_CONTEXT] = {0};
    size_t n, m;
    cisco_reassembly_t *cache = cisco_reassembly_create();
    assert(cache);

    /* Conflicting exact range, and a partial overlap, poison their keys. */
    n = fragment(a, 10, 0, 1112, 1);
    m = fragment(b, 10, 1112, 400, 0);
    assert(!feed(cache, a, n, context, 0));
    a[100] ^= 1;
    assert(!feed(cache, a, n, context, 0));
    assert(!feed(cache, b, m, context, 0));
    n = fragment(a, 11, 0, 1112, 1);
    m = fragment(b, 11, 1104, 408, 0);
    assert(!feed(cache, a, n, context, 0));
    assert(!feed(cache, b, m, context, 0));

    /* Truncation, invalid IHL, non-final alignment, offset overflow, UDP size. */
    for (unsigned scenario = 0; scenario < 5; scenario++) {
        n = fragment(a, 20 + scenario, 0, 1112, 1);
        m = fragment(b, 20 + scenario, 1112, 400, 0);
        switch (scenario) {
            case 0: n--; break;
            case 1: a[0] = 0x44; break;
            case 2: put16(a + 2, n - 1); n--; break;
            case 3: put16(a + 6, 0x3fff); break;
            case 4: a[24] ^= 1; break;
        }
        assert(!feed(cache, a, n, context, 0));
        assert(!feed(cache, b, m, context, 0));
    }
    cisco_reassembly_destroy(cache);
}

static void test_expiry_and_isolation(void) {
    uint8_t a[1600], b[1600], context[CISCO_REASS_CONTEXT] = {0};
    size_t n = fragment(a, 30, 0, 1112, 1);
    size_t m = fragment(b, 30, 1112, 400, 0);
    cisco_reassembly_t *cache = cisco_reassembly_create();
    cisco_reassembly_t *other = cisco_reassembly_create();
    assert(cache && other);

    assert(!feed(cache, a, n, context, 0));
    assert(!feed(other, b, m, context, 0));
    context[0] = 1;
    assert(!feed(cache, b, m, context, 0));
    context[0] = 0;
    assert(feed(cache, b, m, context, 0));
    assert(!feed(cache, a, n, context, 0));
    cisco_reassembly_expire(cache, 31);
    assert(!feed(cache, a, n, context, 31));
    /* Missing final expires; a subsequent final cannot use the old first. */
    assert(!feed(cache, b, m, context, 62));
    assert(feed(cache, a, n, context, 62));
    cisco_reassembly_destroy(cache);
    cisco_reassembly_destroy(other);
}

static void test_limits(void) {
    uint8_t a[1600], b[1600], context[CISCO_REASS_CONTEXT] = {0};
    size_t n, m;
    cisco_reassembly_t *cache = cisco_reassembly_create();
    assert(cache);

    for (unsigned i = 0; i < CISCO_REASS_ACTIVE; i++) {
        n = fragment(a, 100 + i, 0, 1112, 1);
        assert(!feed(cache, a, n, context, 0));
    }
    n = fragment(a, 800, 0, 1112, 1);
    m = fragment(b, 800, 1112, 400, 0);
    assert(!feed(cache, a, n, context, 0));
    assert(!feed(cache, b, m, context, 0));
    cisco_reassembly_expire(cache, 31);
    assert(!feed(cache, a, n, context, 31));
    assert(feed(cache, b, m, context, 31));
    cisco_reassembly_destroy(cache);

    cache = cisco_reassembly_create();
    assert(cache);
    for (unsigned i = 0; i < CISCO_REASS_FRAGMENTS; i++) {
        n = fragment(a, 810, i * 8, 8, 1);
        assert(!feed(cache, a, n, context, 0));
    }
    m = fragment(b, 810, 1024, 488, 0);
    assert(!feed(cache, b, m, context, 0));
    cisco_reassembly_destroy(cache);

    cache = cisco_reassembly_create();
    assert(cache);
    for (unsigned i = 0; i < CISCO_REASS_SLOTS; i++) {
        n = fragment(a, 1000 + i, 0, 1112, 1);
        assert(!feed(cache, a, n - 1, context, 0));
    }
    n = fragment(a, 9000, 0, 1112, 1);
    m = fragment(b, 9000, 1112, 400, 0);
    assert(!feed(cache, a, n, context, 0));
    assert(!feed(cache, b, m, context, 0));
    cisco_reassembly_expire(cache, 31);
    assert(!feed(cache, a, n, context, 31));
    assert(feed(cache, b, m, context, 31));
    cisco_reassembly_destroy(cache);
}

struct thread_arg {
    cisco_reassembly_t *cache;
    unsigned offset;
    int complete;
};

static void *thread_fragment(void *value) {
    struct thread_arg *arg = value;
    uint8_t ip[1600], context[CISCO_REASS_CONTEXT] = {0};
    size_t length = fragment(ip, 42, arg->offset,
            arg->offset ? 400 : 1112, arg->offset == 0);
    arg->complete = feed(arg->cache, ip, length, context, 0);
    return NULL;
}

static void test_threads(void) {
    pthread_t threads[2];
    cisco_reassembly_t *cache = cisco_reassembly_create();
    struct thread_arg args[2] = {{cache, 0, 0}, {cache, 1112, 0}};
    assert(cache);
    for (unsigned i = 0; i < 2; i++)
        assert(pthread_create(&threads[i], NULL, thread_fragment, &args[i]) == 0);
    for (unsigned i = 0; i < 2; i++)
        assert(pthread_join(threads[i], NULL) == 0);
    assert(args[0].complete + args[1].complete == 1);
    cisco_reassembly_destroy(cache);
}

int main(void) {
    for (unsigned i = 0; i < sizeof(udp); i++)
        udp[i] = i % 251;
    put16(udp + 4, sizeof(udp));
    test_order_and_duplicates();
    test_invalid();
    test_expiry_and_isolation();
    test_limits();
    test_threads();
    puts("PASS: bounded Cisco transport reassembly");
    return 0;
}
