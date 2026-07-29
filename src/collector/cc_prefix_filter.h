/*
 * Copyright (c) 2026 Pawel Jablonski
 *
 * This file is part of OpenLI.
 *
 * OpenLI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 */

#ifndef OPENLI_CC_PREFIX_FILTER_H_
#define OPENLI_CC_PREFIX_FILTER_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define OPENLI_CC_PREFIX_FILTER_MAX_GROUPS 64

typedef struct openli_cc_prefix_filter openli_cc_prefix_filter_t;

typedef enum openli_cc_prefix_filter_result {
    OPENLI_CC_PREFIX_FILTER_OK = 0,
    OPENLI_CC_PREFIX_FILTER_DUPLICATE = 1,
    OPENLI_CC_PREFIX_FILTER_INVALID_ARGUMENT = -1,
    OPENLI_CC_PREFIX_FILTER_NO_MEMORY = -2,
    OPENLI_CC_PREFIX_FILTER_OVERLAP = -3,
    OPENLI_CC_PREFIX_FILTER_FINALISED = -4
} openli_cc_prefix_filter_result_t;

/*
 * Allocate an empty prefix filter. Prefixes may be added until
 * openli_cc_prefix_filter_finalise() is called.
 */
openli_cc_prefix_filter_t *openli_cc_prefix_filter_create(void);

/*
 * Destroy a filter. The filter must no longer be referenced by packet
 * processing threads when this function is called.
 */
void openli_cc_prefix_filter_destroy(openli_cc_prefix_filter_t *filter);

/*
 * Add a binary IPv4 or IPv6 prefix to a filter group.
 *
 * family must be AF_INET or AF_INET6. address must point to struct in_addr
 * or struct in6_addr respectively. group_id must be in the range 0..63.
 * Host bits in address are cleared before the prefix is inserted.
 *
 * Prefixes belonging to different groups may not overlap. Re-adding the
 * exact same prefix to the same group returns
 * OPENLI_CC_PREFIX_FILTER_DUPLICATE.
 */
openli_cc_prefix_filter_result_t openli_cc_prefix_filter_add(
        openli_cc_prefix_filter_t *filter, int family, const void *address,
        uint8_t prefix_length, uint8_t group_id);

/*
 * Prevent further modifications to filter. After successful finalisation,
 * concurrent lookups are safe because the Patricia tries are immutable.
 */
openli_cc_prefix_filter_result_t openli_cc_prefix_filter_finalise(
        openli_cc_prefix_filter_t *filter);

/*
 * Return the group mask for the longest prefix matching address.
 *
 * A return value of zero means that no configured prefix matched. The
 * filter must have been finalised before this function is called. Invalid
 * arguments also return zero.
 */
uint64_t openli_cc_prefix_filter_match(
        const openli_cc_prefix_filter_t *filter, int family,
        const void *address);

/* Return the number of configured prefixes for an address family. */
size_t openli_cc_prefix_filter_count(
        const openli_cc_prefix_filter_t *filter, int family);

/* Return non-zero after the filter has been finalised. */
int openli_cc_prefix_filter_is_finalised(
        const openli_cc_prefix_filter_t *filter);

const char *openli_cc_prefix_filter_result_string(
        openli_cc_prefix_filter_result_t result);

#endif