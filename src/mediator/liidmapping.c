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

#include <Judy.h>
#include <string.h>
#include <libtrace.h>
#include "liidmapping.h"
#include "logger.h"

/** Finds an LIID in an LIID map and returns its corresponding agency
 *
 *  @param map          The LIID map to search
 *  @param liidstr      The LIID to look for (as a string)
 *
 *  @return the LIID mapping entry for the LIID, if it is in the map. Returns
 *          NULL if the given LIID is not present in the map.
 */
liid_map_entry_t *lookup_liid_agency_mapping(liid_map_t *map, char *liidstr) {
    PWord_t jval;

    JSLG(jval, map->liid_array, (unsigned char *)liidstr);
    if (jval == NULL) {
        return NULL;
    }
    return (liid_map_entry_t *)(*jval);
}

/** Frees any memory allocated for an LIID->agency mapping
 *
 *  @param m        The LIID map entry to be freed
 */
void destroy_liid_mapping(liid_map_entry_t *m) {
    free(m->liid);
    free(m);
}

/** Removes an LIID->agency mapping from an LIID map and frees any memory
 *  allocated for that mapping.
 *
 *  @param map          The LIID map to remove the mapping from
 *  @param m            The LIID map entry to be removed
 *
 */
void remove_liid_agency_mapping(liid_map_t *map, liid_map_entry_t *m) {
    int err;

    JSLD(err, map->liid_array, (unsigned char *)m->liid);
    destroy_liid_mapping(m);
}

/** Flags an LIID->agency mapping as withdrawn.
 *
 *  Withdrawn mappings are deleted (along with their corresponding queues)
 *  once any outstanding messages in their queue have been processed.
 *
 *  @param map          The LIID map to search for the mapping
 *  @param liidstr      The LIID to be withdrawn
 *
 */
void withdraw_liid_agency_mapping(liid_map_t *map, char *liidstr) {
    PWord_t jval;
    liid_map_entry_t *m;

    JSLG(jval, map->liid_array, (unsigned char *)liidstr);
    if (jval == NULL) {
        return;
    }

    m = (liid_map_entry_t *)(*jval);
    m->withdrawn = 1;

    logger(LOG_INFO,
            "OpenLI Mediator: flagged agency mapping for LIID %s as withdrawn.",
            m->liid);
}

/** Adds a new LIID->agency mapping to an LIID map.
 *
 *  @param map          The LIID map to add the new mapping to
 *  @param toadd        Structure containing the LIID for the new mapping
 *                      (as a string), as well as encryption requirements for
 *                      the corresponding intercept
 *
 *  @return -1 if an error occurs, 0 if the LIID already existed and was not
 *          withdrawn, 1 if a new LIID->agency mapping was created or an
 *          existing mapping has been reactivated.
 */
int add_liid_agency_mapping(liid_map_t *map, added_liid_t *toadd) {

    PWord_t jval;
	liid_map_entry_t *m;

    JSLG(jval, map->liid_array, (unsigned char *)(toadd->liid));
    if (jval != NULL) {
        int ret = 0;

        /* We've seen this LIID before? Possibly a re-announcement? */
        m = (liid_map_entry_t *)(*jval);

        /* If it was withdrawn, reset it to being active */
        if (m->withdrawn != 0) {
            m->withdrawn = 0;
            ret = 1;
        } else {
            ret = 0;
        }
        memcpy(m->encryptkey, toadd->encryptkey, OPENLI_MAX_ENCRYPTKEY_LEN);
        m->encrypt = toadd->encrypt;
        m->encryptkey_len = toadd->encryptkey_len;
        m->unconfirmed = 0;
        m->ccqueue_deleted = 0;
        m->iriqueue_deleted = 0;
        return ret;
    }

    m = (liid_map_entry_t *)calloc(1, sizeof(liid_map_entry_t));
    if (m == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: OOM when allocating memory for new LIID.");
        return -1;
    }

    m->withdrawn = 0;
    m->unconfirmed = 0;
    m->liid = strdup(toadd->liid);
    m->ccqueue_deleted = 0;
    m->iriqueue_deleted = 0;
    m->encrypt = toadd->encrypt;
    m->encryptkey_len = toadd->encryptkey_len;
    memcpy(m->encryptkey, toadd->encryptkey, OPENLI_MAX_ENCRYPTKEY_LEN);

    /* Create a new entry in the mapping array */
    JSLI(jval, map->liid_array, (unsigned char *)(m->liid));
    if (jval == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: OOM when allocating memory for new LIID.");
        return -1;
    }
    *jval = (Word_t)m;

	return 1;
}

/** Callback method for setting the "unconfirmed" flag for an LIID map
 *  entry. Designed for use in combination with foreach_liid_agency_mapping().
 *
 *  @param m        The LIID map entry to be marked as unconfirmed
 *  @param arg      A user-provided argument (unused)
 *
 *  @return 0 always
 */
int set_liid_as_unconfirmed(liid_map_entry_t *m, void *arg UNUSED) {
    m->unconfirmed = 1;
    return 0;
}

/** Runs a user-provided function against all LIIDs in the map.
 *
 *  @param map      The map to iterate over
 *  @param arg      A user-provided argument that will be passed into each
 *                  invocation of the user function
 *  @param torun    The function to run for each existing LIID.
 *
 *  The torun() function must accept two arguments:
 *    - an liid_map_entry_t * that will point to an LIID mapping
 *    - a void * that will point to the user-provided argument
 *
 *  The torun() function must return 1 if the mapping should be deleted after
 *  the function has completed, or 0 if it should be retained in the map.
 */
int foreach_liid_agency_mapping(liid_map_t *map, void *arg,
        int (*torun)(liid_map_entry_t *, void *)) {

    unsigned char index[1024];
    liid_map_entry_t *m;
    PWord_t jval;
    int r, jrc;
    int err = 0;

    index[0] = '\0';

	/* Iterate all known LIIDs */
	JSLF(jval, map->liid_array, index);
	while (jval != NULL) {
		m = (liid_map_entry_t *)(*jval);

        if (m) {
            r = torun(m, arg);
            if (r == 1) {
                /* if torun() returns 1, delete the mapping */
                JSLD(jrc, map->liid_array, index);
                destroy_liid_mapping(m);
            } else if (r == -1) {
                err = 1;
            }
        }
        JSLN(jval, map->liid_array, index);
	}

    if (err) {
        return -1;
    }
    return 0;
}

/** Removes all current LIID->agency mappings from the LIID map.
 *
 *  @param map          The LIID map to remove the mappings from
 */
void purge_liid_map(liid_map_t *map) {

    unsigned char index[1024];
    liid_map_entry_t *m;
    Word_t bytes;
    PWord_t jval;

    index[0] = '\0';

	/* Remove all known LIIDs */
	JSLF(jval, map->liid_array, index);
	while (jval != NULL) {
		m = (liid_map_entry_t *)(*jval);
        JSLN(jval, map->liid_array, index);
        destroy_liid_mapping(m);
	}
	JSLFA(bytes, map->liid_array);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
