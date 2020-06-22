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

#ifndef OPENLI_LIID_AGENCY_MAPPING_H_
#define OPENLI_LIID_AGENCY_MAPPING_H_

#include <Judy.h>
#include "med_epoll.h"
#include "handover.h"

typedef struct liidmapping liid_map_entry_t;

/** Records an association between an LIID and the agency that should receive
 *  the intercepted records for that LIID
 */
struct liidmapping {
    /** The LIID, as a string */
    char *liid;

    /** The agency that should receive this LIID */
    mediator_agency_t *agency;

    /** The epoll timer event for a scheduled removal of this mapping */
    med_epoll_ev_t *ceasetimer;
};

/** The map used to track which LIIDs should be sent to which agencies */
typedef struct liid_map {
    /** A map of known LIID->agency mappings */
	Pvoid_t liid_array;
    /** A set of LIIDs which have no known corresponding agency (yet) */
	Pvoid_t missing_liids;
} liid_map_t;

/** Finds an LIID in an LIID map and returns its corresponding agency
 *
 *  @param map          The LIID map to search
 *  @param liidstr      The LIID to look for (as a string)
 *
 *  @return the LIID mapping entry for the LIID, if it is in the map. Returns
 *          NULL if the given LIID is not present in the map.
 */
liid_map_entry_t *lookup_liid_agency_mapping(liid_map_t *map, char *liidstr);

/** Adds an LIID to the set of LIIDs without agencies in an LIID map.
 *
 *  @param map          The LIID map to add the missing LIID to
 *  @param liidstr      The LIID that has no corresponding agency (as a string)
 *
 *  @return -1 if an error occurs (e.g. OOM), 0 if successful.
 */
int add_missing_liid(liid_map_t *map, char *liidstr);

/** Removes an LIID->agency mapping from an LIID map.
 *
 *  @param map          The LIID map to remove the mapping from
 *  @param liidstr      The LIID that is to be removed from the map (as a
 *                      string)
 *
 */
void remove_liid_agency_mapping(liid_map_t *map, char *liidstr);

/** Adds a new LIID->agency mapping to an LIID map.
 *
 *  @param map          The LIID map to add the new mapping to
 *  @param liidstr      The LIID for the new mapping (as a string)
 *  @param agency       The agency that requested the LIID
 *
 *  @return -1 if an error occurs, 0 if the addition is successful
 */
int add_liid_agency_mapping(liid_map_t *map, char *liidstr,
        mediator_agency_t *agency);

/** Removes all current LIID->agency mappings from the LIID map.
 *
 *  @param map          The LIID map to remove the mappings from
 */
void purge_liid_map(liid_map_t *map);

/** Removes all entries from the missing LIID map
 *
 *  @param map          The LIID map to purge missing LIIDs from
 */
void purge_missing_liids(liid_map_t *map);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
