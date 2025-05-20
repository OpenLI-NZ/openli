/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
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

void encode_etsili_pshdr(wandder_encoder_t *encoder,
        wandder_etsipshdr_data_t *hdrdata, int64_t cin,
        int64_t seqno, struct timeval *tv) {

    uint32_t tvclass = 1;       // timeOfInterception

    /* hdrdata should be pretty static for each ETSI LI record, so
     * you can populate it once and repeatedly use it.
     * CIN, seqno and tv will change for each record, so I've made them
     * into separate parameters.
     */

    ENC_USEQUENCE(encoder);             // starts outermost sequence

    ENC_CSEQUENCE(encoder, 1);
    wandder_encode_next(encoder, WANDDER_TAG_OID,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0,
            (uint8_t *)WANDDER_ETSILI_PSDOMAINID,
            sizeof(WANDDER_ETSILI_PSDOMAINID));
    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, hdrdata->liid,
            hdrdata->liid_len);
    wandder_encode_next(encoder, WANDDER_TAG_PRINTABLE,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, hdrdata->authcc,
            hdrdata->authcc_len);

    ENC_CSEQUENCE(encoder, 3);

    ENC_CSEQUENCE(encoder, 0);
    wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, hdrdata->operatorid,
            hdrdata->operatorid_len);

    if (hdrdata->networkelemid) {
        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, hdrdata->networkelemid,
                hdrdata->networkelemid_len);
    }
    wandder_encode_endseq(encoder);

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(cin),
            sizeof(int64_t));
    wandder_encode_next(encoder, WANDDER_TAG_PRINTABLE,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 2, hdrdata->delivcc,
            hdrdata->delivcc_len);
    wandder_encode_endseq(encoder);

    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(seqno),
            sizeof(int64_t));
    /*
    wandder_encode_next(encoder, WANDDER_TAG_GENERALTIME,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 5, tv,
            sizeof(struct timeval));
    */

    if (hdrdata->intpointid) {
        wandder_encode_next(encoder, WANDDER_TAG_PRINTABLE,
                WANDDER_CLASS_CONTEXT_PRIMITIVE, 6, hdrdata->intpointid,
                hdrdata->intpointid_len);
    }

    ENC_CSEQUENCE(encoder, 7);
    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 0, &(tv->tv_sec),
            sizeof(tv->tv_sec));
    wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 1, &(tv->tv_usec),
            sizeof(tv->tv_usec));
    wandder_encode_endseq(encoder);

    wandder_encode_next(encoder, WANDDER_TAG_ENUM,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 8, &tvclass, sizeof(tvclass));
    wandder_encode_endseq(encoder);
}


void encode_ipaddress(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, etsili_ipaddress_t *addr) {

    uint32_t addrlen = 4;
    uint32_t iptype = addr->iptype;
    uint32_t assign = addr->assignment;
    uint32_t prefbits = addr->v6prefixlen;

    wandder_encode_job_t *jobarray[2];
    int joblen = 0;

    if (addr->ipvalue == NULL) {
        return; // ???
    }

    // iP-Type
    if (iptype == ETSILI_IPADDRESS_VERSION_4) {
	jobarray[0] = &(precomputed[OPENLI_PREENCODE_IPTYPE_IPV4]);
    } else if (iptype == ETSILI_IPADDRESS_VERSION_6) {
	jobarray[0] = &(precomputed[OPENLI_PREENCODE_IPTYPE_IPV6]);
    } else {
        free(addr->ipvalue);
        return;
    }
    wandder_encode_next_preencoded(encoder, jobarray, 1);
        
    if (addr->iptype == ETSILI_IPADDRESS_VERSION_6) {
        addrlen = 16;
    }

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
    if (assign == ETSILI_IPADDRESS_ASSIGNED_STATIC) {
	jobarray[0] = &(precomputed[OPENLI_PREENCODE_IPASSIGN_STATIC]);
    } else if (assign == ETSILI_IPADDRESS_ASSIGNED_DYNAMIC) {
	jobarray[0] = &(precomputed[OPENLI_PREENCODE_IPASSIGN_DYNAMIC]);
    } else {
	jobarray[0] = &(precomputed[OPENLI_PREENCODE_IPASSIGN_UNKNOWN]);
    }
    joblen = 1;

    // iPv6PrefixLength
    if (addr->v6prefixlen == 48) {
	jobarray[1] = &(precomputed[OPENLI_PREENCODE_IPV6_PREFIX_48]);
	joblen ++;
    } else if (addr->v6prefixlen == 64) {
	jobarray[1] = &(precomputed[OPENLI_PREENCODE_IPV6_PREFIX_64]);
	joblen ++;
    } else if (addr->v6prefixlen > 0) {
	if (joblen > 0) {
	    wandder_encode_next_preencoded(encoder, jobarray, joblen);
	    joblen = 0;
	}
        wandder_encode_next(encoder, WANDDER_TAG_INTEGER,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 4, &(prefbits), sizeof(prefbits));
    }

    // iPv4SubnetMask
    if (addr->v4subnetmask == 32) {
	jobarray[joblen] = &(precomputed[OPENLI_PREENCODE_IPV4_NETMASK_32]);
	joblen ++;
    } else if (addr->v4subnetmask > 0) {
	if (joblen > 0) {
	    wandder_encode_next_preencoded(encoder, jobarray, joblen);
	    joblen = 0;
	}

        wandder_encode_next(encoder, WANDDER_TAG_OCTETSTRING,
            WANDDER_CLASS_CONTEXT_PRIMITIVE, 5, &(addr->v4subnetmask),
            sizeof(addr->v4subnetmask));
    }
    if (joblen > 0) {
	wandder_encode_next_preencoded(encoder, jobarray, joblen);
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
