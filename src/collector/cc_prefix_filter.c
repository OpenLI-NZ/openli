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

#include "cc_prefix_filter.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "patricia.h"

struct openli_cc_prefix_filter {
    patricia_tree_t *ipv4;
    patricia_tree_t *ipv6;
    size_t ipv4_count;
    size_t ipv6_count;
    int finalised;
};

static int family_parameters(int family, uint8_t *maximum_bits,
        size_t *address_length) {
    if (family == AF_INET) {
        *maximum_bits = 32;
        *address_length = sizeof(struct in_addr);
        return 0;
    }

    if (family == AF_INET6) {
        *maximum_bits = 128;
        *address_length = sizeof(struct in6_addr);
        return 0;
    }

    return -1;
}

static patricia_tree_t *tree_for_family(
        const openli_cc_prefix_filter_t *filter, int family) {
    if (family == AF_INET) {
        return filter->ipv4;
    }
    if (family == AF_INET6) {
        return filter->ipv6;
    }
    return NULL;
}

static size_t *count_for_family(openli_cc_prefix_filter_t *filter,
        int family) {
    if (family == AF_INET) {
        return &filter->ipv4_count;
    }
    if (family == AF_INET6) {
        return &filter->ipv6_count;
    }
    return NULL;
}

static void initialise_prefix(prefix_t *prefix, int family,
        const void *address, uint8_t prefix_length) {
    memset(prefix, 0, sizeof(*prefix));
    prefix->family = (u_short)family;
    prefix->bitlen = prefix_length;

    if (family == AF_INET) {
        memcpy(&prefix->add.sin, address, sizeof(prefix->add.sin));
    } else {
        memcpy(&prefix->add.sin6, address, sizeof(prefix->add.sin6));
    }
}

static void clear_host_bits(void *address, size_t address_length,
        uint8_t prefix_length) {
    uint8_t *bytes = address;
    size_t whole_bytes = prefix_length / 8;
    uint8_t remaining_bits = prefix_length % 8;
    size_t first_host_byte;

    if (remaining_bits != 0) {
        bytes[whole_bytes] &= (uint8_t)(0xffU << (8 - remaining_bits));
        first_host_byte = whole_bytes + 1;
    } else {
        first_host_byte = whole_bytes;
    }

    if (first_host_byte < address_length) {
        memset(bytes + first_host_byte, 0,
                address_length - first_host_byte);
    }
}

static int prefix_bits_equal(const prefix_t *left, const prefix_t *right,
        uint8_t bits) {
    const uint8_t *left_bytes = prefix_touchar(left);
    const uint8_t *right_bytes = prefix_touchar(right);
    size_t whole_bytes = bits / 8;
    uint8_t remaining_bits = bits % 8;
    uint8_t mask;

    if (whole_bytes > 0 &&
            memcmp(left_bytes, right_bytes, whole_bytes) != 0) {
        return 0;
    }

    if (remaining_bits == 0) {
        return 1;
    }

    mask = (uint8_t)(0xffU << (8 - remaining_bits));
    return (left_bytes[whole_bytes] & mask) ==
            (right_bytes[whole_bytes] & mask);
}

static int prefixes_overlap(const prefix_t *left, const prefix_t *right) {
    uint8_t comparison_bits;

    if (left->family != right->family) {
        return 0;
    }

    comparison_bits = left->bitlen < right->bitlen ?
            left->bitlen : right->bitlen;
    return prefix_bits_equal(left, right, comparison_bits);
}

static uint64_t node_group_mask(const patricia_node_t *node) {
    const uint64_t *mask;

    if (node == NULL || node->data == NULL) {
        return 0;
    }

    mask = PATRICIA_DATA_GET(node, uint64_t);
    return *mask;
}

static openli_cc_prefix_filter_result_t check_existing_prefixes(
        patricia_tree_t *tree, const prefix_t *candidate,
        uint64_t group_mask) {
    patricia_node_t *node;

    PATRICIA_WALK(tree->head, node) {
        uint64_t existing_mask;

        if (prefixes_overlap(node->prefix, candidate)) {
            existing_mask = node_group_mask(node);
            if (node->prefix->bitlen == candidate->bitlen &&
                    prefix_bits_equal(node->prefix, candidate,
                            candidate->bitlen) &&
                    existing_mask == group_mask) {
                return OPENLI_CC_PREFIX_FILTER_DUPLICATE;
            }

            if (existing_mask != group_mask) {
                return OPENLI_CC_PREFIX_FILTER_OVERLAP;
            }
        }
    } PATRICIA_WALK_END;

    return OPENLI_CC_PREFIX_FILTER_OK;
}

openli_cc_prefix_filter_t *openli_cc_prefix_filter_create(void) {
    openli_cc_prefix_filter_t *filter;

    filter = calloc(1, sizeof(*filter));
    if (filter == NULL) {
        return NULL;
    }

    filter->ipv4 = New_Patricia(32);
    if (filter->ipv4 == NULL) {
        free(filter);
        return NULL;
    }

    filter->ipv6 = New_Patricia(128);
    if (filter->ipv6 == NULL) {
        Destroy_Patricia(filter->ipv4, free);
        free(filter);
        return NULL;
    }

    return filter;
}

void openli_cc_prefix_filter_destroy(openli_cc_prefix_filter_t *filter) {
    if (filter == NULL) {
        return;
    }

    Destroy_Patricia(filter->ipv4, free);
    Destroy_Patricia(filter->ipv6, free);
    free(filter);
}

openli_cc_prefix_filter_result_t openli_cc_prefix_filter_add(
        openli_cc_prefix_filter_t *filter, int family, const void *address,
        uint8_t prefix_length, uint8_t group_id) {
    uint8_t normalised[sizeof(struct in6_addr)];
    uint8_t maximum_bits;
    size_t address_length;
    size_t *prefix_count;
    patricia_tree_t *tree;
    patricia_node_t *node;
    prefix_t prefix;
    uint64_t group_mask;
    uint64_t *stored_mask;
    openli_cc_prefix_filter_result_t result;

    if (filter == NULL || address == NULL ||
            group_id >= OPENLI_CC_PREFIX_FILTER_MAX_GROUPS) {
        return OPENLI_CC_PREFIX_FILTER_INVALID_ARGUMENT;
    }

    if (filter->finalised) {
        return OPENLI_CC_PREFIX_FILTER_FINALISED;
    }

    if (family_parameters(family, &maximum_bits, &address_length) != 0 ||
            prefix_length > maximum_bits) {
        return OPENLI_CC_PREFIX_FILTER_INVALID_ARGUMENT;
    }

    memset(normalised, 0, sizeof(normalised));
    memcpy(normalised, address, address_length);
    clear_host_bits(normalised, address_length, prefix_length);
    initialise_prefix(&prefix, family, normalised, prefix_length);

    tree = tree_for_family(filter, family);
    prefix_count = count_for_family(filter, family);
    group_mask = UINT64_C(1) << group_id;

    result = check_existing_prefixes(tree, &prefix, group_mask);
    if (result != OPENLI_CC_PREFIX_FILTER_OK) {
        return result;
    }

    stored_mask = malloc(sizeof(*stored_mask));
    if (stored_mask == NULL) {
        return OPENLI_CC_PREFIX_FILTER_NO_MEMORY;
    }
    *stored_mask = group_mask;

    node = patricia_lookup(tree, &prefix);
    if (node == NULL) {
        free(stored_mask);
        return OPENLI_CC_PREFIX_FILTER_NO_MEMORY;
    }

    if (node->data != NULL) {
        free(stored_mask);
        return OPENLI_CC_PREFIX_FILTER_DUPLICATE;
    }

    PATRICIA_DATA_SET(node, stored_mask);
    (*prefix_count)++;
    return OPENLI_CC_PREFIX_FILTER_OK;
}

openli_cc_prefix_filter_result_t openli_cc_prefix_filter_finalise(
        openli_cc_prefix_filter_t *filter) {
    if (filter == NULL) {
        return OPENLI_CC_PREFIX_FILTER_INVALID_ARGUMENT;
    }

    filter->finalised = 1;
    return OPENLI_CC_PREFIX_FILTER_OK;
}

uint64_t openli_cc_prefix_filter_match(
        const openli_cc_prefix_filter_t *filter, int family,
        const void *address) {
    uint8_t maximum_bits;
    size_t address_length;
    patricia_tree_t *tree;
    patricia_node_t *node;
    prefix_t prefix;

    if (filter == NULL || address == NULL || !filter->finalised) {
        return 0;
    }

    if (family_parameters(family, &maximum_bits, &address_length) != 0) {
        return 0;
    }

    tree = tree_for_family(filter, family);
    if (tree == NULL) {
        return 0;
    }

    if ((family == AF_INET && filter->ipv4_count == 0) ||
            (family == AF_INET6 && filter->ipv6_count == 0)) {
        return 0;
    }

    (void)address_length;
    initialise_prefix(&prefix, family, address, maximum_bits);
    node = patricia_search_best2(tree, &prefix, 1);
    return node_group_mask(node);
}

uint64_t openli_cc_prefix_filter_match_l3(
        const openli_cc_prefix_filter_t *filter, const void *l3,
        uint32_t l3len) {
    const uint8_t *packet = (const uint8_t *)l3;
    const void *src;
    const void *dst;
    uint64_t mask;
    uint8_t version;

    if (filter == NULL || packet == NULL || l3len == 0) {
        return 0;
    }

    version = packet[0] >> 4;
    if (version == 4) {
        uint8_t ihl;

        if (l3len < 20) {
            return 0;
        }
        ihl = (packet[0] & 0x0f) * 4;
        if (ihl < 20 || l3len < ihl) {
            return 0;
        }
        src = packet + 12;
        dst = packet + 16;
        mask = openli_cc_prefix_filter_match(filter, AF_INET, src);
        mask |= openli_cc_prefix_filter_match(filter, AF_INET, dst);
        return mask;
    }

    if (version == 6) {
        if (l3len < 40) {
            return 0;
        }
        src = packet + 8;
        dst = packet + 24;
        mask = openli_cc_prefix_filter_match(filter, AF_INET6, src);
        mask |= openli_cc_prefix_filter_match(filter, AF_INET6, dst);
        return mask;
    }

    return 0;
}

size_t openli_cc_prefix_filter_count(
        const openli_cc_prefix_filter_t *filter, int family) {
    if (filter == NULL) {
        return 0;
    }

    if (family == AF_INET) {
        return filter->ipv4_count;
    }
    if (family == AF_INET6) {
        return filter->ipv6_count;
    }
    return 0;
}

int openli_cc_prefix_filter_is_finalised(
        const openli_cc_prefix_filter_t *filter) {
    return filter != NULL && filter->finalised;
}

const char *openli_cc_prefix_filter_result_string(
        openli_cc_prefix_filter_result_t result) {
    switch (result) {
        case OPENLI_CC_PREFIX_FILTER_OK:
            return "success";
        case OPENLI_CC_PREFIX_FILTER_DUPLICATE:
            return "duplicate prefix";
        case OPENLI_CC_PREFIX_FILTER_INVALID_ARGUMENT:
            return "invalid argument";
        case OPENLI_CC_PREFIX_FILTER_NO_MEMORY:
            return "out of memory";
        case OPENLI_CC_PREFIX_FILTER_OVERLAP:
            return "prefix overlaps another group";
        case OPENLI_CC_PREFIX_FILTER_FINALISED:
            return "filter is already finalised";
        default:
            return "unknown prefix filter result";
    }
}