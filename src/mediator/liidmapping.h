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

struct liidmapping {
    char *liid;
    mediator_agency_t *agency;
    med_epoll_ev_t *ceasetimer;
};

typedef struct liid_map {
	Pvoid_t liid_array;
	Pvoid_t missing_liids;
} liid_map_t;

liid_map_entry_t *lookup_liid_agency_mapping(liid_map_t *map, char *liidstr);
int add_missing_liid(liid_map_t *map, char *liidstr);
void remove_liid_agency_mapping(liid_map_t *map, char *liidstr);
int add_liid_agency_mapping(liid_map_t *map, char *liidstr,
        mediator_agency_t *agency);
void purge_liid_map(liid_map_t *map);
void purge_missing_liids(liid_map_t *map);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
