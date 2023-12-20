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

#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include "location.h"

static void encode_e_utran_cell_id(char *encspace, e_utran_cell_id_t *cell) {

    encspace[0] = ((cell->mcc[0] - '0') & 0x0f) +
            (((cell->mcc[1] - '0') & 0x0f) << 4);
    encspace[1] = ((cell->mcc[2] - '0') & 0x0f);

    if (cell->mnc[2] == '\0') {
        encspace[1] += (0xf0);
    } else {
        encspace[1] += (((cell->mnc[2] - '0') & 0x0f) << 4);
    }

    encspace[2] = ((cell->mnc[0] - '0') & 0x0f) +
            (((cell->mnc[1] - '0') & 0x0f) << 4);

    encspace[3] = (cell->eci >> 24) & 0x0f;
    encspace[4] = (cell->eci >> 16) & 0xff;
    encspace[5] = (cell->eci >> 8) & 0xff;
    encspace[6] = cell->eci & 0xff;
}

static inline uint8_t mnc_three_digits(const char *mcc, const char *mnc) {
    /* TODO */
    return 0;
}

int parse_e_utran_fdd_field(const char *field, openli_location_t *loc) {
    int step = 0;
    const char *ptr = NULL;
    char tacbuf[5];
    char ecibuf[8];

    e_utran_cell_id_t cellid;

    if (strlen(field) < 6) {
        return -1;
    }

    ptr = strchr(field, '=');
    if (ptr == NULL) {
        return -1;
    }
    ptr ++;

    memcpy(cellid.mcc, ptr, 3);
    cellid.mcc[3] = '\0';

    if (mnc_three_digits(cellid.mcc, ptr + 3)) {
        memcpy(cellid.mnc, ptr + 3, 3);
        step = 6;
    } else {
        memcpy(cellid.mnc, ptr + 3, 2);
        step = 5;
        cellid.mnc[2] = '\0';
    }
    cellid.mnc[3] = '\0';

    if (strlen(field) < step + 11) {
        /* not enough characters, must be an invalid field */
        return -1;
    }

    ptr += step;

    /* 4 digit TAC when EPC, 6 digit TAC when 5GCN */
    memcpy(tacbuf, ptr, 4);
    tacbuf[4] = '\0';
    ptr += 4;

    /* TAC (and ECI) are expressed as hex digits */
    cellid.tac = strtol(tacbuf, NULL, 16);

    /* ECI is 7 digits */
    memcpy(ecibuf, ptr, 7);
    ecibuf[7] = '\0';
    cellid.eci = strtol(ecibuf, NULL, 16);

    encode_e_utran_cell_id(loc->encoded, &cellid);
    loc->loc_type = OPENLI_LOC_ECGI;
    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
