/*
 *
 * Copyright (c) 2023 The University of Waikato, Hamilton, New Zealand.
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

#ifndef OPENLI_LOCATION_H_
#define OPENLI_LOCATION_H_

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct e_utran_cell_id {
    char mcc[4];
    char mnc[4];
    uint32_t tac;
    uint32_t eci;
} e_utran_cell_id_t;

enum {
    OPENLI_LOC_ENCODING_UMTS_HI2,
    OPENLI_LOC_ENCODING_EPS,
    OPENLI_LOC_ENCODING_WLAN,
    OPENLI_LOC_ENCODING_ETSI_671_HI2,
    OPENLI_LOC_ENCODING_3GPP_33128,
};

typedef enum {
    OPENLI_LOC_UNKNOWN = 0x00,
    OPENLI_LOC_CGI = 0x01,
    OPENLI_LOC_SAI = 0x02,
    OPENLI_LOC_RAI = 0x04,
    OPENLI_LOC_TAI = 0x08,
    OPENLI_LOC_ECGI = 0x10,
    OPENLI_LOC_LAI = 0x20,
    OPENLI_LOC_MACRO_ENODE_B_ID = 0x40,
    OPENLI_LOC_EXT_MACRO_ENODE_B_ID = 0x80,
} openli_location_type_t;

typedef struct openli_location {
    openli_location_type_t loc_type;

    char encoded[8];
} openli_location_t;

int parse_e_utran_fdd_field(const char *field, openli_location_t *loc);
#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
