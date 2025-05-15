/*
 *
 * Copyright (c) 2025 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * This code has been developed by Searchlight Ltd.
 * For further information please see https://searchlight.nz/
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

#include <uthash.h>

#include "logger.h"
#include "agency.h"
#include "coll_recv_thread.h"
#include "liidmapping.h"

int update_integrity_check_state_lea(integrity_check_state_t **map,
        liagency_t *lea) {

    integrity_check_state_t *found = NULL;

    HASH_FIND(hh, *map, lea->agencyid, strlen(lea->agencyid), found);

    if (found) {
        free_liagency(found->config);
        found->config = lea;

        /* For now, I'll just let any current timers expire rather
         * than trying to adjust them to suit the new config. After that,
         * any future timers will be based off the new options (although
         * realistically, the likelihood of having to modify an existing
         * agencies integrity check config is very very small).
         */
         return 0;
    }

    found = calloc(1, sizeof(integrity_check_state_t));
    found->agencyid = strdup(lea->agencyid);
    found->config = lea;

    /* TODO init the actual digest state once I decide what it is going
     * to look like */

    HASH_ADD_KEYPTR(hh, *map, found->agencyid, strlen(found->agencyid),
            found);

    return 1;
}

void free_integrity_check_state(integrity_check_state_t *ics) {

    if (ics->agencyid) {
        free(ics->agencyid);
    }
    if (ics->config) {
        free_liagency(ics->config);
    }

    /* TODO free digest state for all observed streams */

    free(ics);
}

void remove_integrity_check_state(integrity_check_state_t **map,
        char *agencyid) {

    integrity_check_state_t *found;

    HASH_FIND(hh, *map, agencyid, strlen(agencyid), found);
    if (!found) {
        return;
    }

    HASH_DELETE(hh, *map, found);
    free_integrity_check_state(found);

}
