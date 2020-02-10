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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <libtrace.h>
#include <libwandder.h>
#include <libwandder_etsili.h>

#include "logger.h"
#include "collector.h"
#include "intercept.h"
#include "etsili_core.h"
#include "ipiri.h"
#include "internetaccess.h"

static void free_ipiri_parameters(etsili_generic_t *params) {

    etsili_generic_t *oldp, *tmp;

    HASH_ITER(hh, params, oldp, tmp) {
        HASH_DELETE(hh, params, oldp);
        if (oldp->itemnum == IPIRI_CONTENTS_POP_IDENTIFIER) {
            ipiri_free_id((ipiri_id_t *)(oldp->itemptr));
        }
        release_etsili_generic(oldp);
    }

}

int sort_generics(etsili_generic_t *a, etsili_generic_t *b) {
    if (a->itemnum < b->itemnum) {
        return -1;
    }
    if (a->itemnum > b->itemnum) {
        return 1;
    }

    return 0;
}

static inline void encode_ipiri_shared(wandder_encoder_t *encoder,
        etsili_generic_freelist_t *freegenerics,
        openli_ipiri_job_t *job,
        etsili_iri_type_t *iritype_p,
        etsili_generic_t **params_p) {

    etsili_generic_t *np, *params = NULL;
    etsili_iri_type_t iritype;
    etsili_ipaddress_t targetip;
    int64_t ipversion = 0;
    params = job->customparams;

    if (job->special == OPENLI_IPIRI_ENDWHILEACTIVE) {
        uint32_t evtype = IPIRI_END_WHILE_ACTIVE;
        iritype = ETSILI_IRI_REPORT;

        np = create_etsili_generic(freegenerics,
                IPIRI_CONTENTS_ACCESS_EVENT_TYPE, sizeof(uint32_t),
                (uint8_t *)(&evtype));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum),
                np);
    } else if (job->special == OPENLI_IPIRI_STARTWHILEACTIVE) {
        uint32_t evtype = IPIRI_START_WHILE_ACTIVE;
        iritype = ETSILI_IRI_BEGIN;

        np = create_etsili_generic(freegenerics,
                IPIRI_CONTENTS_ACCESS_EVENT_TYPE, sizeof(uint32_t),
                (uint8_t *)(&evtype));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum),
                np);
    } else if (job->special == OPENLI_IPIRI_SILENTLOGOFF) {
        uint32_t evtype = IPIRI_ACCESS_END;     // unsure if correct?
        iritype = ETSILI_IRI_END;

        np = create_etsili_generic(freegenerics,
                IPIRI_CONTENTS_ACCESS_EVENT_TYPE, sizeof(uint32_t),
                (uint8_t *)(&evtype));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum),
                np);

        /* TODO probably need to set an endReason in here, but not sure
         * what is the right reason to use.
         */
    } else {
        iritype = job->iritype;
    }


    np = create_etsili_generic(freegenerics,
            IPIRI_CONTENTS_INTERNET_ACCESS_TYPE, sizeof(uint32_t),
            (uint8_t *)&(job->access_tech));
    HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

    if (job->username) {
        np = create_etsili_generic(freegenerics,
                IPIRI_CONTENTS_TARGET_USERNAME, strlen(job->username),
                job->username);
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum),
                np);
    }

    if (job->ipfamily != 0) {
        uint8_t etsiipmethod = ETSILI_IPADDRESS_ASSIGNED_UNKNOWN;

        switch(job->ipassignmentmethod) {
            case OPENLI_IPIRI_IPMETHOD_UNKNOWN:
                etsiipmethod = ETSILI_IPADDRESS_ASSIGNED_UNKNOWN;
                break;
            case OPENLI_IPIRI_IPMETHOD_STATIC:
                etsiipmethod = ETSILI_IPADDRESS_ASSIGNED_STATIC;
                break;
            case OPENLI_IPIRI_IPMETHOD_DYNAMIC:
                etsiipmethod = ETSILI_IPADDRESS_ASSIGNED_DYNAMIC;
                break;
        }

        if (job->ipfamily == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)&(job->assignedip);
            etsili_create_ipaddress_v4(
                    (uint32_t *)(&(in->sin_addr.s_addr)),
                    job->assignedip_prefixbits,
                    etsiipmethod, &targetip);
            ipversion = IPIRI_IPVERSION_4;
        } else if (job->ipfamily == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)
                    &(job->assignedip);
            etsili_create_ipaddress_v6(
                    (uint8_t *)(&(in6->sin6_addr.s6_addr)),
                    job->assignedip_prefixbits,
                    etsiipmethod, &targetip);
            ipversion = IPIRI_IPVERSION_6;
        }

        if (ipversion == IPIRI_IPVERSION_4 || ipversion == IPIRI_IPVERSION_6) {
            np = create_etsili_generic(freegenerics,
                    IPIRI_CONTENTS_IPVERSION, sizeof(int64_t),
                    (uint8_t *)(&ipversion));
            HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum),
                    np);

            np = create_etsili_generic(freegenerics,
                    IPIRI_CONTENTS_TARGET_IPADDRESS,
                    sizeof(etsili_ipaddress_t), (uint8_t *)(&targetip));
            HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum),
                    np);
        }
    }

    if (job->sessionstartts.tv_sec > 0) {
        np = create_etsili_generic(freegenerics,
                IPIRI_CONTENTS_STARTTIME,
                sizeof(struct timeval), (uint8_t *)&(job->sessionstartts));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum),
                np);
    }

    reset_wandder_encoder(encoder);

    *iritype_p = iritype;
    *params_p = params;

}

int encode_ipiri(wandder_encoder_t *encoder,
        etsili_generic_freelist_t *freegenerics,
        wandder_encode_job_t *precomputed,
        openli_ipiri_job_t *job, uint32_t seqno,
        openli_encoded_result_t *res) {

    
    etsili_generic_t *params = NULL;
    etsili_iri_type_t iritype;
    struct timeval tv;
    int ret = 0;
    uint32_t liidlen = precomputed[OPENLI_PREENCODE_LIID].vallen;

    encode_ipiri_shared(encoder,
        freegenerics,
        job,
        &iritype,
        &params);

    gettimeofday(&tv, NULL);

    memset(res, 0, sizeof(openli_encoded_result_t));
    res->msgbody = encode_etsi_ipiri(encoder, precomputed,
            (int64_t)(job->cin), (int64_t)seqno, iritype, &tv, params);

    res->ipcontents = NULL;
    res->ipclen = 0;
    res->header.magic = htonl(OPENLI_PROTO_MAGIC);
    res->header.bodylen = htons(res->msgbody->len + liidlen + sizeof(uint16_t));
    res->header.intercepttype = htons(OPENLI_PROTO_ETSI_IRI);
    res->header.internalid = 0;

    free_ipiri_parameters(params);
    return ret;
}

int ipiri_create_id_printable(char *idstr, int length, ipiri_id_t *iriid) {

    if (length <= 0) {
        return -1;
    }

    if (length > 128) {
        logger(LOG_INFO, "OpenLI: Printable IPIRI ID is too long, truncating to 128 characters.");
        length = 128;
    }

    iriid->type = IPIRI_ID_PRINTABLE;
    iriid->content.printable = (char *)malloc(length + 1);
    memcpy(iriid->content.printable, idstr, length);

    if (iriid->content.printable[length - 1] != '\0') {
        iriid->content.printable[length] = '\0';
    }
    return 0;
}

int ipiri_create_id_mac(uint8_t *macaddr, ipiri_id_t *iriid) {
    /* TODO */
    return -1;
}

int ipiri_create_id_ipv4(uint32_t addrnum, uint8_t slashbits,
        ipiri_id_t *iriid) {
    /* TODO */
    return -1;
}

void ipiri_free_id(ipiri_id_t *iriid) {
    if (iriid->type == IPIRI_ID_PRINTABLE) {
        free(iriid->content.printable);
    }
}

#ifdef HAVE_BER_ENCODING
int encode_ipiri_ber(
        openli_ipiri_job_t *job,
        etsili_generic_freelist_t *freegenerics,
        uint32_t seqno, struct timeval *tv,
        openli_encoded_result_t *res,
        wandder_etsili_child_t *child, 
        wandder_encoder_t *encoder) {

    memset(res, 0, sizeof(openli_encoded_result_t));

    etsili_generic_t *params = NULL;
    etsili_iri_type_t iritype;
    struct timeval current_tv;
    int ret = 0;
    uint32_t liidlen = (uint32_t)((size_t)child->owner->preencoded[WANDDER_PREENCODE_LIID_LEN]);

    encode_ipiri_shared(encoder,
        freegenerics,
        job,
        &iritype,
        &params);

    gettimeofday(&current_tv, NULL);

    memset(res, 0, sizeof(openli_encoded_result_t));

    wandder_encode_etsi_ipiri_ber (
            (int64_t)(job->cin),
            (int64_t)seqno,
            &current_tv,
            params,
            iritype,
            child);

    res->msgbody = malloc(sizeof(wandder_encoded_result_t));
    res->msgbody->encoder = NULL;
    res->msgbody->encoded = child->buf;
    res->msgbody->len = child->len;
    res->msgbody->alloced = child->alloc_len;
    res->msgbody->next = NULL;

    res->ipcontents = NULL;
    res->ipclen = 0;
    
    res->header.magic = htonl(OPENLI_PROTO_MAGIC);
    res->header.bodylen = htons(res->msgbody->len + liidlen + sizeof(uint16_t));
    res->header.intercepttype = htons(OPENLI_PROTO_ETSI_IRI);
    res->header.internalid = 0;

    free_ipiri_parameters(params);
    return ret;
}
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
