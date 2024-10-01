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

#ifndef OPENLI_LIID_AGENCY_MAPPING_H_
#define OPENLI_LIID_AGENCY_MAPPING_H_

#include <Judy.h>
#include <amqp.h>

typedef struct liidmapping liid_map_entry_t;

/** Records an association between an LIID and the agency that should receive
 *  the intercepted records for that LIID
 */
struct liidmapping {
    /** The LIID, as a string */
    char *liid;

    /** Flag that indicates whether this mapping is unconfirmed by the
     *  provisioner.
     */
    uint8_t unconfirmed;

    /** Flag that indicates whether this mapping has been withdrawn by the
     *  provisioner.
     */
    uint8_t withdrawn;

    /** Flag that indicates whether the internal CC queue for this LIID has
     *  been deleted by the mediator.
     */
    uint8_t ccqueue_deleted;

    /** Flag that indicates whether the internal IRI queue for this LIID has
     *  been deleted by the mediator.
     */
    uint8_t iriqueue_deleted;
};

/** The map used to track which LIIDs should be sent to which agencies */
typedef struct liid_map {
    /** A map of known LIID->agency mappings */
	Pvoid_t liid_array;
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

/** Removes an LIID->agency mapping from an LIID map.
 *
 *  @param map          The LIID map to remove the mapping from
 *  @param m            The LIID map entry to be removed
 *
 */
void remove_liid_agency_mapping(liid_map_t *map, liid_map_entry_t *m);

/** Adds a new LIID->agency mapping to an LIID map.
 *
 *  @param map          The LIID map to add the new mapping to
 *  @param liidstr      The LIID for the new mapping (as a string)
 *
 *  @return -1 if an error occurs, 0 if the LIID already existed, 1 if
 *          a new LIID->agency mapping was created
 */
int add_liid_agency_mapping(liid_map_t *map, char *liidstr);

/** Flags an LIID->agency mapping as withdrawn.
 *
 *  Withdrawn mappings are deleted (along with their corresponding queues)
 *  once any outstanding messages in their queue have been processed.
 *
 *  @param map          The LIID map to search for the mapping
 *  @param liidstr      The LIID to be withdrawn
 *
 */
void withdraw_liid_agency_mapping(liid_map_t *map, char *liidstr);

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
 *
 *  @return -1 if any of the function iterations return -1 (i.e. an error).
 *  Otherwise will return 0.
 */
int foreach_liid_agency_mapping(liid_map_t *map, void *arg,
        int (*torun)(liid_map_entry_t *, void *));

/** Removes all current LIID->agency mappings from the LIID map.
 *
 *  @param map          The LIID map to remove the mappings from
 */
void purge_liid_map(liid_map_t *map);

/** Callback method for setting the "unconfirmed" flag for an LIID map
 *  entry. Designed for use in combination with foreach_liid_agency_mapping().
 *
 *  @param m        The LIID map entry to be marked as unconfirmed
 *  @param arg      A user-provided argument (unused)
 *
 *  @return 0 always
 */
int set_liid_as_unconfirmed(liid_map_entry_t *m, void *arg);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
