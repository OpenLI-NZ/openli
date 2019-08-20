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
#include "ipmmiri.h"

int encode_ipmmiri(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, openli_ipmmiri_job_t *job,
        uint32_t seqno, openli_encoded_result_t *res, struct timeval *ts) {

    uint32_t liidlen = precomputed[OPENLI_PREENCODE_LIID].vallen;
    reset_wandder_encoder(encoder);

    memset(res, 0, sizeof(openli_encoded_result_t));

    if (job->ipmmiri_style == OPENLI_IPMMIRI_SIP) {
        if (job->content == NULL) {
            logger(LOG_INFO, "OpenLI: trying to create SIP IRI but packet has no SIP payload?");
            return -1;
        }

        res->msgbody = encode_etsi_sipiri(encoder, precomputed,
                (int64_t)(job->cin), (int64_t)seqno, job->iritype, ts,
                job->ipsrc, job->ipdest, job->ipfamily, job->content,
                job->contentlen);
        res->ipcontents = (uint8_t *)(job->content);
        res->ipclen = job->contentlen;
    }
    /* TODO style == H323 */

    res->header.magic = htonl(OPENLI_PROTO_MAGIC);
    res->header.bodylen = htons(res->msgbody->len + liidlen + sizeof(uint16_t));
    res->header.intercepttype = htons(OPENLI_PROTO_ETSI_IRI);
    res->header.internalid = 0;

    return 0;
}

int encode_ipmmiri_ber(wandder_buf_t **preencoded_ber,
        openli_ipmmiri_job_t *job, uint32_t seqno, struct timeval *tv,
        openli_encoded_result_t *res, wandder_etsili_top_t *top, 
        wandder_encoder_t *encoder, wandder_encode_job_t *precomputed) {

    uint32_t liidlen = precomputed[OPENLI_PREENCODE_LIID].vallen;
    reset_wandder_encoder(encoder);

    memset(res, 0, sizeof(openli_encoded_result_t));

    if (job->ipmmiri_style == OPENLI_IPMMIRI_SIP) {
        if (job->content == NULL) {
            logger(LOG_INFO, "OpenLI: trying to create SIP IRI but packet has no SIP payload?");
            return -1;
        }

        // res->msgbody = encode_etsi_sipiri(encoder, precomputed,
        //         (int64_t)(job->cin), (int64_t)seqno, job->iritype, ts,
        //         job->ipsrc, job->ipdest, job->ipfamily, job->content,
        //         job->contentlen);


        wandder_encode_etsi_ipmmiri_ber(
            preencoded_ber,     //preencode
            (int64_t)job->cin,  //cin
            (int64_t)seqno,     //seqno
            tv,                 //tv
            job->content,       //content
            job->contentlen,    //contentlen
            job->iritype,       //iritype
            job->ipsrc,
            job->ipdest,
            job->ipfamily,
            top);               //top

        res->msgbody = malloc(sizeof(wandder_encoded_result_t));

        res->msgbody->encoder = NULL;
        res->msgbody->encoded = top->buf;
        res->msgbody->len = top->len;
        res->msgbody->alloced = top->len;
        res->msgbody->next = NULL;

        res->ipcontents = (uint8_t *)(job->content);
        res->ipclen = job->contentlen;
    }
    /* TODO style == H323 */

    res->header.magic = htonl(OPENLI_PROTO_MAGIC);
    res->header.bodylen = htons(res->msgbody->len + liidlen + sizeof(uint16_t));
    res->header.intercepttype = htons(OPENLI_PROTO_ETSI_IRI);
    res->header.internalid = 0;

    return 0;
}




// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
