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
#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <libtrace.h>
#include <libtrace_parallel.h>
#include <libwandder.h>
#include <libwandder_etsili.h>

#include "logger.h"
#include "collector.h"
#include "collector_publish.h"
#include "etsili_core.h"
#include "util.h"
#include "umtscc.h"


int encode_umtscc(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, openli_ipcc_job_t *job,
        uint32_t seqno, struct timeval *tv,  openli_encoded_result_t *msg) {

    uint32_t liidlen = precomputed[OPENLI_PREENCODE_LIID].vallen;
    reset_wandder_encoder(encoder);

    memset(msg, 0, sizeof(openli_encoded_result_t));
    msg->msgbody = encode_etsi_umtscc(encoder, precomputed, (int64_t)job->cin,
            (int64_t)seqno, tv, job->ipcontent, job->ipclen, job->dir);

    msg->ipcontents = (uint8_t *)job->ipcontent;
    msg->ipclen = job->ipclen;
    msg->header.magic = htonl(OPENLI_PROTO_MAGIC);
    msg->header.bodylen = htons(msg->msgbody->len + liidlen + sizeof(uint16_t));
    msg->header.intercepttype = htons(OPENLI_PROTO_ETSI_CC);
    msg->header.internalid = 0;
    return 0;
}


#ifdef HAVE_BER_ENCODING

int encode_umtscc_ber(
        openli_ipcc_job_t *job, uint32_t seqno, struct timeval *tv,
        openli_encoded_result_t *msg, wandder_etsili_child_t *child, wandder_encoder_t *encoder) {

    uint32_t liidlen = (uint32_t)((size_t)child->owner->preencoded[WANDDER_PREENCODE_LIID_LEN]);

    memset(msg, 0, sizeof(openli_encoded_result_t));

    wandder_encode_etsi_umtscc_ber (
            job->cin,
            (int64_t)seqno,
            tv,
            job->ipcontent,
            job->ipclen,
            job->dir,
            child);

    msg->msgbody = malloc(sizeof(wandder_encoded_result_t));

    msg->msgbody->encoder = NULL;
    msg->msgbody->encoded = child->buf;
    msg->msgbody->len = child->len;
    msg->msgbody->alloced = child->alloc_len;
    msg->msgbody->next = NULL;

    msg->ipcontents = NULL;
    msg->ipclen = 0;

    msg->header.magic = htonl(OPENLI_PROTO_MAGIC);
    msg->header.bodylen = htons(msg->msgbody->len + liidlen + sizeof(uint16_t));
    msg->header.intercepttype = htons(OPENLI_PROTO_ETSI_CC);
    msg->header.internalid = 0;

    return 0;
}
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
