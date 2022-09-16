/*
 *
 * Copyright (c) 2018-2022 The University of Waikato, Hamilton, New Zealand.
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

#include <uthash.h>

#include "util.h"
#include "logger.h"
#include "collector_base.h"
#include "collector_publish.h"
#include "email_worker.h"
#include "netcomms.h"
#include "intercept.h"

static inline email_user_intercept_list_t *is_address_interceptable(
        openli_email_worker_t *state, char *emailaddr) {

    email_user_intercept_list_t *active = NULL;

    HASH_FIND(hh, state->alltargets, emailaddr, strlen(emailaddr), active);
    return active;
}

static openli_export_recv_t *create_emailiri_job(char *liid,
        emailsession_t *sess, uint8_t iritype, uint8_t emailev,
        uint8_t status, uint32_t destid, uint64_t timestamp) {

    openli_export_recv_t *msg = NULL;
    etsili_email_iri_content_t *content;
    size_t liidlen = strlen(liid);
    int i;
    email_participant_t *recip, *tmp;

    msg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    if (msg == NULL) {
        return msg;
    }

    msg->type = OPENLI_EXPORT_EMAILIRI;
    msg->destid = destid;
    msg->ts.tv_sec = (time_t)(timestamp / 1000.0);
    msg->ts.tv_usec = ((time_t)(timestamp % 1000)) * 1000;

    content = &(msg->data.emailiri.content);

    msg->data.emailiri.liid = strdup(liid);
    msg->data.emailiri.cin = sess->cin;
    msg->data.emailiri.iritype = iritype;
    content->eventtype = emailev;
    content->serveraddr = calloc(1, sizeof(struct sockaddr_storage));
    memcpy(content->serveraddr, sess->serveraddr,
            sizeof(struct sockaddr_storage));
    content->clientaddr = calloc(1, sizeof(struct sockaddr_storage));
    memcpy(content->clientaddr, sess->clientaddr,
            sizeof(struct sockaddr_storage));
    content->server_octets = sess->server_octets;
    content->client_octets = sess->client_octets;
    content->protocol = sess->protocol;
    content->recipient_count = HASH_CNT(hh, sess->participants);
    content->sender = strdup(sess->sender.emailaddr);

    content->recipients = calloc(content->recipient_count,
            sizeof(char *));
    i = 0;
    HASH_ITER(hh, sess->participants, recip, tmp) {
        content->recipients[i] = strdup(recip->emailaddr);
        i++;
    }
    content->status = status;
    content->messageid = NULL;

    return msg;

}

static void create_emailiris_for_intercept_list(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t iri_type, uint8_t email_ev,
        uint8_t status, email_user_intercept_list_t *active) {

    openli_export_recv_t *irijob = NULL;
    email_intercept_ref_t *ref, *tmp;

    HASH_ITER(hh, active->intlist, ref, tmp) {
        irijob = create_emailiri_job(ref->em->common.liid, sess,
                iri_type, email_ev, status, ref->em->common.destid,
                sess->login_time);
        if (irijob == NULL) {
            continue;
        }
        pthread_mutex_lock(state->stats_mutex);
        state->stats->emailiri_created ++;
        pthread_mutex_unlock(state->stats_mutex);
        publish_openli_msg(
                state->zmq_pubsocks[ref->em->common.seqtrackerid], irijob);
    }

}

static int generate_email_login_iri(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t success) {

    email_user_intercept_list_t *active;
    email_participant_t *recip, *tmp;
    uint8_t email_ev;
    uint8_t iri_type;
    uint8_t status;

    if (success) {
        email_ev = ETSILI_EMAIL_EVENT_LOGON;
        iri_type = ETSILI_IRI_BEGIN;
        status = ETSILI_EMAIL_STATUS_SUCCESS;
    } else {
        email_ev = ETSILI_EMAIL_EVENT_LOGON_FAILURE;
        iri_type = ETSILI_IRI_REPORT;
        status = ETSILI_EMAIL_STATUS_FAILED;
    }

    active = is_address_interceptable(state, sess->sender.emailaddr);
    if (active) {
        create_emailiris_for_intercept_list(state, sess, iri_type,
                email_ev, status, active);
    }

    HASH_ITER(hh, sess->participants, recip, tmp) {
        if (strcmp(recip->emailaddr, sess->sender.emailaddr) == 0) {
            continue;
        }

        active = is_address_interceptable(state, recip->emailaddr);
        if (!active) {
            continue;
        }

        create_emailiris_for_intercept_list(state, sess, iri_type,
                email_ev, status, active);
    }

    return 0;
}

int generate_email_login_success_iri(openli_email_worker_t *state,
        emailsession_t *sess) {
    return generate_email_login_iri(state, sess, 1);
}

int generate_email_login_failure_iri(openli_email_worker_t *state,
        emailsession_t *sess) {
    return generate_email_login_iri(state, sess, 0);
}



// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
