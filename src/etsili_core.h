/*
 *
 * Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
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
#ifndef OPENLI_ETSILI_CORE_H_
#define OPENLI_ETSILI_CORE_H_

#include <stdlib.h>
#include <inttypes.h>
#include <libwandder.h>

#define ENC_USEQUENCE(enc) wandder_encode_next(enc, WANDDER_TAG_SEQUENCE, \
        WANDDER_CLASS_UNIVERSAL_CONSTRUCT, WANDDER_TAG_SEQUENCE, NULL, 0)

#define ENC_CSEQUENCE(enc, x) wandder_encode_next(enc, WANDDER_TAG_SEQUENCE, \
        WANDDER_CLASS_CONTEXT_CONSTRUCT, x, NULL, 0)



typedef struct wandder_etsipshdr_data {

    char *liid;
    int liid_len;
    char *authcc;
    int authcc_len;
    char *operatorid;
    int operatorid_len;
    char *networkelemid;
    int networkelemid_len;
    char *delivcc;
    int delivcc_len;
    char *intpointid;
    int intpointid_len;

} wandder_etsipshdr_data_t;

uint8_t *encode_etsi_ipcc(uint32_t *enclen, wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, uint64_t cin, uint64_t seqno,
        struct timeval *tv, void *ipcontents, uint32_t iplen);

uint8_t *encode_etsi_keepalive(uint32_t *enclen, wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, uint64_t seqno);


#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
