/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * OpenLI is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * OpenLI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#ifndef OPENLI_AGENCY_H_
#define OPENLI_AGENCY_H_

#include <libtrace/linked_list.h>

#define DEFAULT_AGENCY_KEEPALIVE_WAIT (30)
#define DEFAULT_AGENCY_KEEPALIVE_FREQ (300)

#define DEFAULT_DIGEST_HASH_TIMEOUT 1
#define DEFAULT_DIGEST_SIGN_TIMEOUT 300
#define DEFAULT_DIGEST_HASH_PDULIMIT 1000
#define DEFAULT_DIGEST_SIGN_HASHLIMIT 15
#define DEFAULT_DIGEST_HASH_METHOD OPENLI_DIGEST_HASH_ALGO_SHA256

typedef enum {
    OPENLI_DIGEST_HASH_ALGO_SHA1 = 1,
    OPENLI_DIGEST_HASH_ALGO_SHA256 = 2,
    OPENLI_DIGEST_HASH_ALGO_SHA384 = 3,
    OPENLI_DIGEST_HASH_ALGO_SHA512 = 4,
} openli_integrity_hash_method_t;

typedef struct liagency {

    char *hi2_ipstr;
    char *hi2_portstr;
    char *hi3_ipstr;
    char *hi3_portstr;
    char *agencyid;
    char *agencycc;
    uint32_t keepalivefreq;
    uint32_t keepalivewait;

    openli_integrity_hash_method_t digest_hash_method;
    uint8_t digest_required;
    uint32_t digest_hash_timeout;
    uint32_t digest_hash_pdulimit;
    uint32_t digest_sign_timeout;
    uint32_t digest_sign_hashlimit;
} liagency_t;

#define agency_equal(a, b) \
    ((strcmp(a->hi2_ipstr, b->hi2_ipstr) == 0) && \
     (strcmp(a->hi2_portstr, b->hi2_portstr) == 0) && \
     (strcmp(a->hi3_ipstr, b->hi3_ipstr) == 0) && \
     (strcmp(a->hi3_portstr, b->hi3_portstr) == 0) && \
     (strcmp(a->agencyid, b->agencyid) == 0) && \
     a->keepalivefreq == b->keepalivefreq && \
     a->keepalivewait == b->keepalivewait && \
     a->digest_required == b->digest_required && \
         ((!a->digest_required) || ( \
             a->digest_hash_timeout == b->digest_hash_timeout && \
             a->digest_hash_pdulimit == b->digest_hash_pdulimit && \
             a->digest_sign_timeout == b->digest_sign_timeout && \
             a->digest_sign_hashlimit == b->digest_sign_hashlimit && \
             a->digest_hash_method == b->digest_hash_method)) && \
     ((a->agencycc == NULL && b->agencycc == NULL) || \
        (a->agencycc != NULL && b->agencycc != NULL && \
         strcmp(a->agencycc, b->agencycc) == 0)))

#endif

openli_integrity_hash_method_t map_digest_hash_method_string(char *str);
void free_liagency(liagency_t *ag);

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
