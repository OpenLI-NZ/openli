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

#include <libwandder.h>
#include <libwandder_etsili.h>

#include "logger.h"
#include "umtsiri.h"
#include "etsili_core.h"

static void free_umtsiri_parameters(etsili_generic_t *params) {

    etsili_generic_t *oldp, *tmp;

    HASH_ITER(hh, params, oldp, tmp) {
        HASH_DELETE(hh, params, oldp);
        release_etsili_generic(oldp);
    }

}

int encode_umtsiri(wandder_encoder_t *encoder,
        etsili_generic_freelist_t *freegenerics,
        wandder_encode_job_t *precomputed,
        openli_mobiri_job_t *job, uint32_t seqno,
        openli_encoded_result_t *res) {

    struct timeval tv;
    uint32_t liidlen = precomputed[OPENLI_PREENCODE_LIID].vallen;

    reset_wandder_encoder(encoder);
    gettimeofday(&tv, NULL);

    memset(res, 0, sizeof(openli_encoded_result_t));
    res->msgbody = encode_etsi_umtsiri(encoder, precomputed, (int64_t)job->cin,
            (int64_t)seqno, job->iritype, &tv, job->customparams);

    res->ipcontents = NULL;
    res->ipclen = 0;
    res->header.magic = htonl(OPENLI_PROTO_MAGIC);
    res->header.bodylen = htons(res->msgbody->len + liidlen + sizeof(uint16_t));
    res->header.intercepttype = htons(OPENLI_PROTO_ETSI_IRI);
    res->header.internalid = 0;

    free_umtsiri_parameters(job->customparams);
    return 0;
}

int create_mobiri_job_from_session(collector_sync_t *sync,
        access_session_t *sess, ipintercept_t *ipint, uint8_t special) {

    openli_export_recv_t *irimsg;
    int ret;

    irimsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    irimsg->type = OPENLI_EXPORT_UMTSIRI;
    irimsg->destid = ipint->common.destid;
    irimsg->data.mobiri.liid = strdup(ipint->common.liid);
    irimsg->data.mobiri.cin = sess->cin;
    irimsg->data.mobiri.iritype = ETSILI_IRI_NONE;
    irimsg->data.mobiri.customparams = NULL;

    ret = sess->plugin->generate_iri_from_session(sess->plugin, sess,
            &(irimsg->data.mobiri.customparams),
            &(irimsg->data.mobiri.iritype), sync->freegenerics, special);
    if (ret == -1) {
        logger(LOG_INFO,
                "OpenLI: error whle creating UMTSIRI from existing session %s.",
                irimsg->data.mobiri.liid);
        free(irimsg->data.mobiri.liid);
        free(irimsg);
        return -1;
    }

    if (irimsg->data.mobiri.iritype == ETSILI_IRI_NONE) {
            free(irimsg->data.mobiri.liid);
            free(irimsg);
            return 0;
    }

    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->mobiri_created ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);
    publish_openli_msg(sync->zmq_pubsocks[ipint->common.seqtrackerid], irimsg);

    return 1;
}

int create_mobiri_job_from_packet(collector_sync_t *sync,
        access_session_t *sess, ipintercept_t *ipint, access_plugin_t *p,
        void *parseddata) {

    openli_export_recv_t *irimsg;
    int ret;

    irimsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    irimsg->type = OPENLI_EXPORT_UMTSIRI;
    irimsg->destid = ipint->common.destid;
    irimsg->data.mobiri.liid = strdup(ipint->common.liid);
    irimsg->data.mobiri.cin = sess->cin;
    irimsg->data.mobiri.iritype = ETSILI_IRI_NONE;
    irimsg->data.mobiri.customparams = NULL;

    if (p) {
        ret = p->generate_iri_data(p, parseddata,
                &(irimsg->data.mobiri.customparams),
                &(irimsg->data.mobiri.iritype),
                sync->freegenerics, 0);
        if (ret == -1) {
            logger(LOG_INFO,
                    "OpenLI: error whle creating UMTSIRI from session state change for %s.",
                    irimsg->data.mobiri.liid);
            free(irimsg->data.mobiri.liid);
            free(irimsg);
            return -1;
        }
    }

    if (irimsg->data.mobiri.iritype == ETSILI_IRI_NONE) {
            free(irimsg->data.mobiri.liid);
            free(irimsg);
            return 0;
    }

    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->mobiri_created ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);
    publish_openli_msg(sync->zmq_pubsocks[ipint->common.seqtrackerid], irimsg);

    return 1;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
