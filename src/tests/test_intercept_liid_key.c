/*
 *
 * Copyright (c) 2026 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * OpenLI was originally developed by the University of Waikato WAND
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

/* Unit tests for set_intercept_liid_key() */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "intercept.h"

static int failures = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
            failures ++; \
        } \
    } while (0)

static void reset_common(intercept_common_t *common, const char *liid,
        const char *authcc) {

    memset(common, 0, sizeof(intercept_common_t));
    if (liid) {
        common->liid = strdup(liid);
    }
    if (authcc) {
        common->authcc = strdup(authcc);
    }
}

static void clear_common(intercept_common_t *common) {
    free(common->liid);
    free(common->authcc);
    free(common->liid_key);
}

int main(void) {
    intercept_common_t common;
    char errbuf[256];
    int ret;

    reset_common(&common, "LIID1", "NZ");
    ret = set_intercept_liid_key(&common, errbuf, sizeof(errbuf));
    TEST_ASSERT(ret == 1, "derivation for a valid LIID + authCC failed");
    TEST_ASSERT(common.liid_key != NULL &&
            strcmp(common.liid_key, "NZ-LIID1") == 0,
            "derived key does not match expected '<authcc>-<liid>' form");
    TEST_ASSERT(common.liid_key_len == (int)strlen("NZ-LIID1"),
            "derived key length is incorrect");

    free(common.authcc);
    common.authcc = strdup("AU");
    ret = set_intercept_liid_key(&common, errbuf, sizeof(errbuf));
    TEST_ASSERT(ret == 1, "re-derivation after an authCC change failed");
    TEST_ASSERT(strcmp(common.liid_key, "AU-LIID1") == 0,
            "re-derived key was not updated to use the new authCC");
    clear_common(&common);

    reset_common(&common, "LI-ID-2", "NZ");
    ret = set_intercept_liid_key(&common, errbuf, sizeof(errbuf));
    TEST_ASSERT(ret == 1, "derivation for an LIID containing '-' failed");
    TEST_ASSERT(strcmp(common.liid_key, "NZ-LI-ID-2") == 0,
            "derived key mangled an LIID containing '-'");
    clear_common(&common);

    reset_common(&common, "D", "AB-C");
    ret = set_intercept_liid_key(&common, errbuf, sizeof(errbuf));
    TEST_ASSERT(ret == -1, "an authCC containing '-' was not rejected");
    TEST_ASSERT(common.liid_key == NULL,
            "a key was derived despite the authCC being invalid");
    clear_common(&common);

    reset_common(&common, "LIID3", NULL);
    ret = set_intercept_liid_key(&common, errbuf, sizeof(errbuf));
    TEST_ASSERT(ret == -1, "a missing authCC was not rejected");
    clear_common(&common);

    reset_common(&common, NULL, "NZ");
    ret = set_intercept_liid_key(&common, errbuf, sizeof(errbuf));
    TEST_ASSERT(ret == -1, "a missing LIID was not rejected");
    clear_common(&common);

    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
