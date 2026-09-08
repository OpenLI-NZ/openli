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

#include "intercept.h"

typedef enum openli_cc_prefix_filter_result {
    OPENLI_CC_PREFIX_FILTER_OK = 0,
    OPENLI_CC_PREFIX_FILTER_DUPLICATE = 1,
    OPENLI_CC_PREFIX_FILTER_INVALID_ARGUMENT = -1,
    OPENLI_CC_PREFIX_FILTER_NO_MEMORY = -2,
    OPENLI_CC_PREFIX_FILTER_OVERLAP = -3,
} openli_cc_prefix_filter_result_t;

/*
 * Allocate an empty prefix filter.
 *
 * Parameter 'shared' is the value that will used as the initial
 * reference count (i.e. the number of threads that will have
 * access to this set of filters.
 */
openli_cc_prefix_filter_t *openli_cc_prefix_filter_create(char *liid,
        int shared);

/*
 * Destroy the filter group, regardless of its reference count. Do NOT
 * call this if you've pushed the filter group to worker threads; only
 * use to clean up memory if an error occurs while populating the
 * filter group.
 */
void openli_cc_prefix_filter_destroy(openli_cc_prefix_filter_t *filter);

/*
 * Reduces the reference counter for a filter group. If the counter
 * reaches zero, this method will also destroy the filter group
 * automatically.
 */
void openli_cc_prefix_filter_release(openli_cc_prefix_filter_t *filter);

/* Add a IPv4 or IPv6 prefix, expressed as CIDR string, to a filter group.
 *
 * The inserted prefix must not overlap with any prefixes already in the
 * filter group. Re-adding the exact same prefix to the same group returns
 * OPENLI_CC_PREFIX_FILTER_DUPLICATE.
 */
openli_cc_prefix_filter_result_t openli_cc_prefix_filter_add_cidr(
        openli_cc_prefix_filter_t *filter, char *cidr);

/*
 * Return the group mask for the longest prefix matching address.
 *
 * A return value of zero means that no configured prefix matched. Invalid
 * arguments also return zero.
 */
uint64_t openli_cc_prefix_filter_match(
        const openli_cc_prefix_filter_t *filter, int family,
        const void *address);

/*
 * Safely extract source and destination addresses from an IPv4 or IPv6
 * packet beginning at l3, and return the union of their matching group masks.
 * Returns zero for NULL, truncated, malformed, or non-IP input.
 */
uint64_t openli_cc_prefix_filter_match_l3(
        const openli_cc_prefix_filter_t *filter, const void *l3,
        uint32_t l3len);

const char *openli_cc_prefix_filter_result_string(
        openli_cc_prefix_filter_result_t result);

#endif
