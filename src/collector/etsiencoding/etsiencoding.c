/*
 *
 * Copyright (c) 2023 Searchlight NZ
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

#include <libwandder_etsili.h>
#include <assert.h>
#include "etsili_core.h"
#include "logger.h"
#include "intercept.h"
#include "etsiencoding.h"

static inline uint8_t encode_pspdu_sequence(uint8_t *space, uint8_t space_len,
        uint32_t contentsize, char *liid, uint16_t liidlen) {

    uint8_t len_space_req = DERIVE_INTEGER_LENGTH(contentsize);
    int i;
    uint16_t l;

    if (liidlen > space_len - 8) {
        logger(LOG_INFO,
                "OpenLI: invalid LIID for PSPDU: %s (%u %u)", liid, liidlen, space_len);
        return 0;
    }

    l = htons(liidlen);
    memcpy(space, &l, sizeof(uint16_t));
    memcpy(space + 2, liid, liidlen);
    space += (2 + liidlen);

    *space = (uint8_t)((WANDDER_CLASS_UNIVERSAL_CONSTRUCT << 5) |
            WANDDER_TAG_SEQUENCE);
    space ++;

    if (len_space_req == 1) {
        *space = (uint8_t)contentsize;
        return 2 + (2 + liidlen);
    }

    *space = len_space_req | 0x80;
    space ++;

    for (i = len_space_req - 1; i >= 0; i--) {
        *(space + i) = (contentsize & 0xff);
        contentsize = contentsize >> 8;
    }

    return len_space_req + 2 + (2 + liidlen);
}

void encode_ipaddress(wandder_encoder_t *encoder, etsili_ipaddress_t *addr) {

    uint32_t addrlen = 4;
    uint32_t iptype = addr->iptype;
    uint32_t assign = addr->assignment;
    uint32_t prefbits = addr->v6prefixlen;

    if (addr->ipvalue == NULL) {
        return; // ???
    }

    if (addr->iptype == ETSILI_IPADDRESS_VERSION_6) {
        addrlen = 16;
    }

    // iP-Type
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(iptype), sizeof(iptype));

    ENC_CSEQUENCE(encoder, 2);      // iP-value
    if (addr->valtype == ETSILI_IPADDRESS_REP_BINARY) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, addr->ipvalue, addrlen);
    } else {
        wandder_encode_next(encoder, WANDDER_TAG_IA5,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, addr->ipvalue,
            strlen((char *)(addr->ipvalue)));
    }

    wandder_encode_endseq(encoder);     // ends iP-value

    // iP-assignment
    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 3, &(assign), sizeof(assign));

    // iPv6PrefixLength
    if (addr->v6prefixlen > 0) {
        wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(prefbits), sizeof(prefbits));
    }

    // iPv4SubnetMask
    if (addr->v4subnetmask > 0) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 5, &(addr->v4subnetmask),
            sizeof(addr->v4subnetmask));
    }

    free(addr->ipvalue);
    addr->ipvalue = NULL;
}


int create_etsi_encoded_result(openli_encoded_result_t *res,
        encoded_header_template_t *hdr_tplate,
        uint8_t *body_content, uint16_t bodylen,
        uint8_t *trailing, uint16_t traillen,
        openli_encoding_job_t *job) {

    uint8_t pspdu[108];
    uint8_t pspdu_len;

    /* Create a msgbody by concatenating hdr_tplate and body, plus
     * a preceding pS-PDU sequence with the appropriate length...
     */
    pspdu_len = encode_pspdu_sequence(pspdu, sizeof(pspdu),
            hdr_tplate->header_len + bodylen, job->liid,
            job->preencoded[OPENLI_PREENCODE_LIID].vallen);

    if (pspdu_len == 0) {
        return -1;
    }

    res->msgbody = calloc(1, sizeof(wandder_encoded_result_t));
    res->msgbody->encoder = NULL;
    res->msgbody->len = pspdu_len + hdr_tplate->header_len + bodylen;

    res->msgbody->encoded = malloc(res->msgbody->len);
    res->msgbody->alloced = res->msgbody->len;
    res->msgbody->next = NULL;

    memcpy(res->msgbody->encoded, pspdu, pspdu_len);
    memcpy(res->msgbody->encoded + pspdu_len, hdr_tplate->header,
            hdr_tplate->header_len);
    memcpy(res->msgbody->encoded + pspdu_len + hdr_tplate->header_len,
            body_content, bodylen);

    /* Set the remaining msg->header properties */
    res->header.magic = htonl(OPENLI_PROTO_MAGIC);
    res->header.bodylen = htons(res->msgbody->len);
    res->header.internalid = 0;

    switch(job->origreq->type) {
        case OPENLI_EXPORT_IPCC:
        case OPENLI_EXPORT_IPMMCC:
        case OPENLI_EXPORT_UMTSCC:
        case OPENLI_EXPORT_EMAILCC:
        case OPENLI_EXPORT_EPSCC:
            res->header.intercepttype = htons(OPENLI_PROTO_ETSI_CC);
            break;
        case OPENLI_EXPORT_IPIRI:
        case OPENLI_EXPORT_IPMMIRI:
        case OPENLI_EXPORT_UMTSIRI:
        case OPENLI_EXPORT_EPSIRI:
        case OPENLI_EXPORT_EMAILIRI:
            res->header.intercepttype = htons(OPENLI_PROTO_ETSI_IRI);
            break;
    }

    res->ipcontents = trailing;
    res->ipclen = traillen;

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
