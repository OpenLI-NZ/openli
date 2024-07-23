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
#include <arpa/inet.h>
#include <libtrace.h>

#include "location.h"
#include "logger.h"

#define ENCODE_MNC_MMC(src, encspace) \
    encspace[0] = ((src->mcc[0] - '0') & 0x0f) +                     \
            (((src->mcc[1] - '0') & 0x0f) << 4);                     \
    encspace[1] = ((src->mcc[2] - '0') & 0x0f);                      \
                                                                     \
    if (src->mnc[2] == '\0') {                                       \
        encspace[1] += (0xf0);                                       \
    } else {                                                         \
        encspace[1] += (((src->mnc[2] - '0') & 0x0f) << 4);          \
    }                                                                \
                                                                     \
    encspace[2] = ((src->mnc[0] - '0') & 0x0f) +                     \
            (((src->mnc[1] - '0') & 0x0f) << 4);                     \


static void encode_e_utran_cell_id(openli_location_t **loc,
        int *loc_cnt, e_utran_cell_id_t *cell) {

    char *encspace;
    openli_location_t *l;

    *loc = calloc(2, sizeof(openli_location_t));
    *loc_cnt = 2;

    /* Encode TAI */
    l = &((*loc)[0]);
    encspace = l->encoded;

    ENCODE_MNC_MMC(cell, encspace);

    encspace[3] = (cell->tac >> 8) & 0xff;
    encspace[4] = (cell->tac) & 0xff;
    l->enc_len = 5;
    l->loc_type = OPENLI_LOC_TAI;

    /* Encode ECGI */
    l = &((*loc)[1]);
    encspace = l->encoded;
    ENCODE_MNC_MMC(cell, encspace);

    encspace[3] = (cell->eci >> 24) & 0x0f;
    encspace[4] = (cell->eci >> 16) & 0xff;
    encspace[5] = (cell->eci >> 8) & 0xff;
    encspace[6] = cell->eci & 0xff;

    l->enc_len = 7;
    l->loc_type = OPENLI_LOC_ECGI;
}

static inline uint8_t mnc_three_digits(const char *mcc UNUSED,
        const char *mnc UNUSED) {
    /* TODO */
    return 0;
}

int parse_e_utran_fdd_field(const char *field, openli_location_t **loc,
        int *loc_cnt) {

    size_t step = 0;
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

    encode_e_utran_cell_id(loc, loc_cnt, &cellid);
    return 0;
}

int encode_user_location_information(char *uli, int space, int *uli_len,
        openli_location_t *locations, uint8_t location_cnt,
        uint32_t location_types) {

    uint16_t used = 0;
    uint8_t *ptr = (uint8_t *)uli;
    uint8_t i;
    uint32_t n = 1;

    memset(uli, 0, space);

    if (location_types > 255) {
        logger(LOG_INFO, "OpenLI: invalid location type flags: %u\n",
                location_types);
        return -1;
    }
    *ptr = (uint8_t)(location_types);
    ptr ++;
    used ++;

    while (n <= OPENLI_LOC_EXT_MACRO_ENODE_B_ID) {
        /* not the quickest approach, but shouldn't really matter for now */
        if ((location_types & n) == n) {
            for (i = 0; i < location_cnt; i++) {
                if (locations[i].loc_type != n) {
                    continue;
                }
                if (space - used < locations[i].enc_len) {
                    logger(LOG_INFO, "OpenLI: ran out of space when encoding user location information");
                    return -1;
                }
                memcpy(ptr, locations[i].encoded, locations[i].enc_len);
                used += locations[i].enc_len;
                ptr += locations[i].enc_len;
                break;
            }
        }
        n *= 2;
    }

    *uli_len = used;
    return 1;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
