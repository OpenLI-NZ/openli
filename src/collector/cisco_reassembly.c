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
#include "cisco_reassembly.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PAYLOAD 65515U
struct segment { unsigned offset, length, more; };
struct assembly {
    uint8_t key[11 + CISCO_REASS_CONTEXT];
    uint8_t *data;
    uint64_t deadline;
    struct timeval stamp;
    unsigned used, dead, count, bytes, end, first_ihl;
    struct segment *segments;
};
struct cisco_reassembly {
    pthread_mutex_t mutex;
    uint64_t clock;
    struct assembly slots[CISCO_REASS_SLOTS];
};
static unsigned be16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
static void reject(struct assembly *s) {
    free(s->data);
    s->data = NULL;
    free(s->segments);
    s->segments = NULL;
    s->dead = 1;
}
cisco_reassembly_t *cisco_reassembly_create(void) {
    cisco_reassembly_t *c = calloc(1, sizeof(*c));
    if (c && pthread_mutex_init(&c->mutex, NULL)) { free(c); return NULL; }
    return c;
}
void cisco_reassembly_destroy(cisco_reassembly_t *c) {
    unsigned i;
    if (!c) return;
    for (i = 0; i < CISCO_REASS_SLOTS; i++) reject(&c->slots[i]);
    pthread_mutex_destroy(&c->mutex);
    free(c);
}
void cisco_reassembly_expire(cisco_reassembly_t *c, uint64_t now) {
    unsigned i;
    if (!c) return;
    pthread_mutex_lock(&c->mutex);
    for (i = 0; i < CISCO_REASS_SLOTS; i++) {
        struct assembly *s = &c->slots[i];
        if (s->used && now >= s->deadline) {
            reject(s);
            memset(s, 0, sizeof(*s));
        }
    }
    pthread_mutex_unlock(&c->mutex);
}
int cisco_reassembly_feed(cisco_reassembly_t *c, const uint8_t *ip,
        size_t captured, const uint8_t context[CISCO_REASS_CONTEXT],
        uint64_t now, struct timeval stamp, uint8_t **udp, size_t *length,
        struct timeval *first_stamp) {
    struct assembly *s = NULL, *empty = NULL;
    uint8_t key[11 + CISCO_REASS_CONTEXT];
    unsigned i, active = 0, h, total, flags, off, more, n, end;
    int result = 0;
    *udp = NULL;
    *length = 0;
    if (!c || !ip || captured < 20 || (ip[0] >> 4) != 4 || ip[9] != 17)
        return 0;
    flags = be16(ip + 6);
    if (!(flags & 0x3fff)) return 0;
    memcpy(key, ip + 12, 8);
    memcpy(key + 8, ip + 4, 2);
    key[10] = ip[9];
    memcpy(key + 11, context, CISCO_REASS_CONTEXT);
    h = (ip[0] & 15) * 4;
    total = be16(ip + 2);
    off = (flags & 8191) * 8;
    more = !!(flags & 8192);
    pthread_mutex_lock(&c->mutex);
    if (now < c->clock) now = c->clock;
    c->clock = now;
    for (i = 0; i < CISCO_REASS_SLOTS; i++) {
        struct assembly *a = &c->slots[i];
        if (a->used && now >= a->deadline) {
            reject(a);
            memset(a, 0, sizeof(*a));
        }
        if (a->data) active++;
        if (a->used && memcmp(a->key, key, sizeof(key)) == 0) s = a;
        if (!a->used && !empty) empty = a;
    }
    /* Capacity exhaustion drops new groups, never evicts a live tombstone. */
    if (!s) {
        if (!empty) goto done;
        s = empty;
        s->used = 1;
        s->deadline = now + CISCO_REASS_SECONDS;
        s->stamp = stamp;
        memcpy(s->key, key, sizeof(key));
    }
    if (s->dead) goto done;
    if (h < 20 || h > captured || total <= h || total > captured ||
            (flags & 0xc000)) goto invalid;
    n = total - h;
    end = off + n;
    if ((more && (n % 8)) || end > MAX_PAYLOAD ||
            (s->end && (end > s->end || (more && end >= s->end))) ||
            (!more && s->end && s->end != end)) goto invalid;
    if (!off) {
        if (s->first_ihl && s->first_ihl != h) goto invalid;
        s->first_ihl = h;
    }
    if (s->first_ihl && end > 65535U - s->first_ihl) goto invalid;
    for (i = 0; i < s->count; i++) {
        struct segment *f = &s->segments[i];
        if (!more && f->offset + f->length > end) goto invalid;
        if (off == f->offset && n == f->length && more == f->more &&
                memcmp(s->data + off, ip + h, n) == 0) goto done;
        /* Only exact, byte-identical fragment duplicates are accepted.
         * Every other overlap quarantines the entire key. */
        if (off < f->offset + f->length && f->offset < end) goto invalid;
    }
    if (s->count == CISCO_REASS_FRAGMENTS) goto invalid;
    if (!s->data) {
        if (active >= CISCO_REASS_ACTIVE) goto invalid;
        s->data = malloc(MAX_PAYLOAD);
        s->segments = calloc(CISCO_REASS_FRAGMENTS, sizeof(struct segment));
        if (!s->data || !s->segments) goto invalid;
    }
    memcpy(s->data + off, ip + h, n);
    s->segments[s->count++] = (struct segment){off, n, more};
    s->bytes += n;
    if (!more) s->end = end;
    if (s->first_ihl && s->end && s->bytes == s->end) {
        if (s->end > 65535U - s->first_ihl || s->end < 8 ||
                be16(s->data + 4) != s->end) goto invalid;
        *udp = s->data;
        *length = s->end;
        *first_stamp = s->stamp;
        s->data = NULL;
        reject(s);
        result = 1;
    }
    goto done;
invalid:
    reject(s);
done:
    pthread_mutex_unlock(&c->mutex);
    return result;
}
