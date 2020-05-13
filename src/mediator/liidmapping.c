/*
 *
 * Copyright (c) 2018-2020 The University of Waikato, Hamilton, New Zealand.
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
#include "liidmapping.h"
#include "med_epoll.h"
#include "logger.h"

liid_map_entry_t *lookup_liid_agency_mapping(liid_map_t *map, char *liidstr) {
    PWord_t jval;

    JSLG(jval, map->liid_array, (unsigned char *)liidstr);
    if (jval == NULL) {
        return NULL;
    }
    return (liid_map_entry_t *)(*jval);
}

void remove_liid_agency_mapping(liid_map_t *map, char *liidstr) {
    int err;

    logger(LOG_DEBUG, "OpenLI Mediator: removed agency mapping for LIID %s.",
            liidstr);
    JSLD(err, map->liid_array, (unsigned char *)liidstr);
}

int add_liid_agency_mapping(liid_map_t *map, char *liidstr,
        mediator_agency_t *agency) {

    PWord_t jval;
	liid_map_entry_t *m;
	int err;

    JSLG(jval, map->liid_array, (unsigned char *)liidstr);
    if (jval != NULL) {
        /* We've seen this LIID before? Possibly a re-announcement? */
        m = (liid_map_entry_t *)(*jval);

        if (m->ceasetimer) {
            /* was scheduled to be ceased, so halt the timer */
            halt_mediator_timer(m->ceasetimer);
        }
        free(m->liid);
    } else {
        /* Create a new entry in the mapping array */
        JSLI(jval, map->liid_array, (unsigned char *)liidstr);
        if (jval == NULL) {
            logger(LOG_INFO, "OpenLI Mediator: OOM when allocating memory for new LIID.");
            return -1;
        }

        m = (liid_map_entry_t *)malloc(sizeof(liid_map_entry_t));
        if (m == NULL) {
            logger(LOG_INFO, "OpenLI Mediator: OOM when allocating memory for new LIID.");
            return -1;
        }
        *jval = (Word_t)m;

        /* If this was previously a "unknown" LIID, we can now remove
         * it from our missing LIID list -- if it gets withdrawn later,
         * we will then alert again about it being missing. */
        JSLG(jval, map->missing_liids, (unsigned char *)liidstr);
        if (jval != NULL) {
            JSLD(err, map->missing_liids, (unsigned char *)liidstr);
        }
    }
    m->liid = liidstr;
    m->agency = agency;
    m->ceasetimer = NULL;

	if (agency) {
        logger(LOG_DEBUG, "OpenLI Mediator: added %s -> %s to LIID map",
                m->liid, m->agency->agencyid);
    } else {
        logger(LOG_INFO, "OpenLI Mediator: added %s -> pcapdisk to LIID map",
                m->liid);
    }
	return 0;
}

int add_missing_liid(liid_map_t *map, char *liidstr) {
    PWord_t jval;

    JSLI(jval, map->missing_liids, (unsigned char *)liidstr);
    if (jval == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: OOM when allocating memory for missing LIID.");
        return -1;
    }

    if ((*jval) == 0) {
        logger(LOG_INFO, "OpenLI Mediator: was unable to find LIID %s in its set of mappings.", liidstr);
    }

    (*jval) = 1;
    return 0;
}

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

		/* If we had a timer running for the removal of a withdrawn LIID,
		 * make sure we stop that cleanly.
		 */
		if (m->ceasetimer) {
			destroy_mediator_timer(m->ceasetimer);
		}
		JSLN(jval, map->liid_array, index);
		free(m->liid);
		free(m);
	}
	JSLFA(bytes, map->liid_array);
}

void purge_missing_liids(liid_map_t *map) {
    Word_t bytes;

    JSLFA(bytes, map->missing_liids);
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
