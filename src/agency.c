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
#include <stdlib.h>
#include <string.h>

#include "agency.h"

openli_integrity_hash_method_t map_digest_hash_method_string(char *str) {
    if (str == NULL) {
        return DEFAULT_DIGEST_HASH_METHOD;
    }
    if (strcasecmp("sha-1", str) == 0) {
        return OPENLI_DIGEST_HASH_ALGO_SHA1;
    } else if (strcasecmp("sha-256", str) == 0) {
        return OPENLI_DIGEST_HASH_ALGO_SHA256;
    } else if (strcasecmp("sha-384", str) == 0) {
        return OPENLI_DIGEST_HASH_ALGO_SHA384;
    } else if (strcasecmp("sha-512", str) == 0) {
        return OPENLI_DIGEST_HASH_ALGO_SHA512;
    }
    return DEFAULT_DIGEST_HASH_METHOD;
}

liagency_t *copy_liagency(liagency_t *lea) {
    liagency_t *copy;

    if (!lea) return NULL;

    copy = calloc(1, sizeof(liagency_t));

    if (!copy) {
        return NULL;
    }

    /* copy in all the non-string variables */
    memcpy(copy, lea, sizeof(liagency_t));

    /* then overwrite the string pointers with strdup copies */
    if (lea->agencyid) {
        copy->agencyid = strdup(lea->agencyid);
    }
    if (lea->agencycc) {
        copy->agencycc = strdup(lea->agencycc);
    }
    if (lea->hi2_portstr) {
        copy->hi2_portstr = strdup(lea->hi2_portstr);
    }
    if (lea->hi2_ipstr) {
        copy->hi2_ipstr = strdup(lea->hi2_ipstr);
    }
    if (lea->hi3_portstr) {
        copy->hi3_portstr = strdup(lea->hi3_portstr);
    }
    if (lea->hi3_ipstr) {
        copy->hi3_ipstr = strdup(lea->hi3_ipstr);
    }
    if (lea->encryptkey_len > 0) {
        // should be covered by the original memcpy, but just to be safe
        memcpy(copy->encryptkey, lea->encryptkey, lea->encryptkey_len);
    }
    return copy;
}

void free_liagency(liagency_t *lea) {
	if (lea->hi2_ipstr) {
		free(lea->hi2_ipstr);
	}
	if (lea->hi2_portstr) {
		free(lea->hi2_portstr);
	}
	if (lea->hi3_ipstr) {
		free(lea->hi3_ipstr);
	}
	if (lea->hi3_portstr) {
		free(lea->hi3_portstr);
	}
	if (lea->agencyid) {
		free(lea->agencyid);
	}
    if (lea->agencycc) {
        free(lea->agencycc);
    }
	free(lea);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
