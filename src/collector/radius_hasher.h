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

#ifndef OPENLI_RADIUS_HASHER_H_
#define OPENLI_RADIUS_HASHER_H_

#include <libtrace/libtrace_radius.h>
#include <Judy.h>
#include <libtrace/hash_toeplitz.h>
#include <libtrace.h>

typedef struct hash_radius_conf {
    /* judy array */
    Pvoid_t jarray;

    /* toeplitz config used on non radius packets */
    toeplitz_conf_t toeplitz;

} hash_radius_conf_t;

void hash_radius_init_config(hash_radius_conf_t *conf, bool bidirectional);

uint64_t hash_radius_packet(const libtrace_packet_t *packet, void *conf);

void hash_radius_cleanup(hash_radius_conf_t *conf);


#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

