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
#include "etsili_core.h"
#include "emailiri.h"

static inline email_user_intercept_list_t *is_address_interceptable(
        openli_email_worker_t *state, char *emailaddr) {

    email_user_intercept_list_t *active = NULL;

    HASH_FIND(hh, state->alltargets, emailaddr, strlen(emailaddr), active);
    return active;
}

void free_email_iri_content(etsili_email_iri_content_t *content) {

    int i;

    if (content->recipients) {
        for (i = 0; i < content->recipient_count; i++) {
            free(content->recipients[i]);
        }
        free(content->recipients);
    }

    if (content->sender) {
        free(content->sender);
    }
    if (content->clientaddr) {
        free(content->clientaddr);
    }
    if (content->serveraddr) {
        free(content->serveraddr);
    }
    if (content->messageid) {
        free(content->messageid);
    }

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

    msg->data.emailiri.customparams = NULL;
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
        uint8_t status, email_user_intercept_list_t *active, uint64_t ts) {

    openli_export_recv_t *irijob = NULL;
    email_intercept_ref_t *ref, *tmp;

    HASH_ITER(hh, active->intlist, ref, tmp) {
        if (ts < ref->em->common.tostart_time * 1000) {
            continue;
        }

        if (ref->em->common.toend_time > 0 &&
                ts > ref->em->common.toend_time * 1000) {
            continue;
        }

        irijob = create_emailiri_job(ref->em->common.liid, sess,
                iri_type, email_ev, status, ref->em->common.destid, ts);
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

static inline int generate_iris_for_participants(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t email_ev, uint8_t iri_type,
        uint8_t status, uint64_t timestamp) {

    email_user_intercept_list_t *active;
    email_participant_t *recip, *tmp;

    active = is_address_interceptable(state, sess->sender.emailaddr);
    if (active) {
        create_emailiris_for_intercept_list(state, sess, iri_type,
                email_ev, status, active, timestamp);
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
                email_ev, status, active, timestamp);
    }

    return 0;
}

static int generate_email_login_iri(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t success) {

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

    return generate_iris_for_participants(state, sess, email_ev, iri_type,
            status, sess->login_time);
}

int generate_email_send_iri(openli_email_worker_t *state,
        emailsession_t *sess) {

    return generate_iris_for_participants(state, sess, ETSILI_EMAIL_EVENT_SEND,
            ETSILI_IRI_CONTINUE, ETSILI_EMAIL_STATUS_SUCCESS, sess->event_time);

}

int generate_email_logoff_iri(openli_email_worker_t *state,
        emailsession_t *sess) {

    return generate_iris_for_participants(state, sess,
            ETSILI_EMAIL_EVENT_LOGOFF, ETSILI_IRI_END,
            ETSILI_EMAIL_STATUS_SUCCESS, sess->event_time);

}

int generate_email_login_success_iri(openli_email_worker_t *state,
        emailsession_t *sess) {
    return generate_email_login_iri(state, sess, 1);
}

int generate_email_login_failure_iri(openli_email_worker_t *state,
        emailsession_t *sess) {
    return generate_email_login_iri(state, sess, 0);
}

static inline void emailiri_free_recipients(
        etsili_email_recipients_t *recipients) {

    int i;
    for (i = 0; i < recipients->count; i++) {
        free(recipients->addresses[i]);
    }
    free(recipients->addresses);
}

static inline void emailiri_populate_recipients(
        etsili_email_recipients_t *recipients,
        uint32_t count, char **reciplist) {

    int i;

    recipients->count = count;
    recipients->addresses = calloc(count, sizeof(char *));
    for (i = 0; i < count; i++) {
        recipients->addresses[i] = reciplist[i];
        reciplist[i] = NULL;
    }

}

void free_emailiri_parameters(etsili_generic_t *params) {

    etsili_email_recipients_t *recipients = NULL;
    etsili_generic_t *oldp, *tmp;

    HASH_ITER(hh, params, oldp, tmp) {
        HASH_DELETE(hh, params, oldp);
        if (oldp->itemnum == EMAILIRI_CONTENTS_RECIPIENTS) {
            recipients = (etsili_email_recipients_t *)oldp->itemptr;
            emailiri_free_recipients(recipients);
        }

        release_etsili_generic(oldp);
    }
}

void prepare_emailiri_parameters(etsili_generic_freelist_t *freegenerics,
        openli_emailiri_job_t *job, etsili_generic_t **params_p) {

    etsili_generic_t *np, *params = *params_p;
    etsili_email_recipients_t recipients;
    etsili_ipaddress_t encip;
    uint32_t port;

    memset(&recipients, 0, sizeof(recipients));

    if (job->content.recipient_count > 0) {
        emailiri_populate_recipients(&recipients, job->content.recipient_count,
                job->content.recipients);
        np = create_etsili_generic(freegenerics, EMAILIRI_CONTENTS_RECIPIENTS,
                sizeof(etsili_email_recipients_t), (uint8_t *)(&recipients));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);
    }

    np = create_etsili_generic(freegenerics, EMAILIRI_CONTENTS_TOTAL_RECIPIENTS,
            sizeof(job->content.recipient_count),
            (uint8_t *)&(job->content.recipient_count));
    HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

    np = create_etsili_generic(freegenerics, EMAILIRI_CONTENTS_EVENT_TYPE,
            sizeof(job->content.eventtype),
            (uint8_t *)&(job->content.eventtype));
    HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

    np = create_etsili_generic(freegenerics, EMAILIRI_CONTENTS_PROTOCOL_ID,
            sizeof(job->content.protocol),
            (uint8_t *)&(job->content.protocol));
    HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

    np = create_etsili_generic(freegenerics, EMAILIRI_CONTENTS_STATUS,
            sizeof(job->content.status),
            (uint8_t *)&(job->content.status));
    HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

    np = create_etsili_generic(freegenerics, EMAILIRI_CONTENTS_SENDER,
            strlen(job->content.sender), (uint8_t *)(job->content.sender));
    HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

    if (job->content.messageid) {
        np = create_etsili_generic(freegenerics, EMAILIRI_CONTENTS_MESSAGE_ID,
                strlen(job->content.messageid),
                (uint8_t *)(job->content.messageid));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);
    }

    np = create_etsili_generic(freegenerics,
            EMAILIRI_CONTENTS_SERVER_OCTETS_SENT,
            sizeof(job->content.server_octets),
            (uint8_t *)&(job->content.server_octets));
    HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

    np = create_etsili_generic(freegenerics,
            EMAILIRI_CONTENTS_CLIENT_OCTETS_SENT,
            sizeof(job->content.client_octets),
            (uint8_t *)&(job->content.client_octets));
    HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

    if (job->content.serveraddr &&
            job->content.serveraddr->ss_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)
                (job->content.serveraddr);
        port = ntohs(in->sin_port);

        etsili_create_ipaddress_v4(
                (uint32_t *)(&(in->sin_addr.s_addr)), 32,
                ETSILI_IPADDRESS_ASSIGNED_UNKNOWN, &encip);
        np = create_etsili_generic(freegenerics,
                EMAILIRI_CONTENTS_SERVER_ADDRESS,
                sizeof(etsili_ipaddress_t), (uint8_t *)(&encip));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

        np = create_etsili_generic(freegenerics,
                EMAILIRI_CONTENTS_SERVER_PORT, sizeof(port), (uint8_t *)&port);
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

    } else if (job->content.serveraddr &&
            job->content.serveraddr->ss_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)
                (job->content.serveraddr);
        port = ntohs(in6->sin6_port);

        etsili_create_ipaddress_v6(
                (uint8_t *)(&(in6->sin6_addr.s6_addr)), 128,
                ETSILI_IPADDRESS_ASSIGNED_UNKNOWN, &encip);
        np = create_etsili_generic(freegenerics,
                EMAILIRI_CONTENTS_SERVER_ADDRESS,
                sizeof(etsili_ipaddress_t), (uint8_t *)(&encip));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

        np = create_etsili_generic(freegenerics,
                EMAILIRI_CONTENTS_SERVER_PORT, sizeof(port), (uint8_t *)&port);
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);
    }

    if (job->content.clientaddr &&
            job->content.clientaddr->ss_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)
                (job->content.clientaddr);
        port = ntohs(in->sin_port);

        etsili_create_ipaddress_v4(
                (uint32_t *)(&(in->sin_addr.s_addr)), 32,
                ETSILI_IPADDRESS_ASSIGNED_UNKNOWN, &encip);
        np = create_etsili_generic(freegenerics,
                EMAILIRI_CONTENTS_CLIENT_ADDRESS,
                sizeof(etsili_ipaddress_t), (uint8_t *)(&encip));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

        np = create_etsili_generic(freegenerics,
                EMAILIRI_CONTENTS_CLIENT_PORT, sizeof(port), (uint8_t *)&port);
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);
    } else if (job->content.clientaddr &&
            job->content.clientaddr->ss_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)
                (job->content.clientaddr);
        port = ntohs(in6->sin6_port);

        etsili_create_ipaddress_v6(
                (uint8_t *)(&(in6->sin6_addr.s6_addr)), 128,
                ETSILI_IPADDRESS_ASSIGNED_UNKNOWN, &encip);
        np = create_etsili_generic(freegenerics,
                EMAILIRI_CONTENTS_CLIENT_ADDRESS,
                sizeof(etsili_ipaddress_t), (uint8_t *)(&encip));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);

        np = create_etsili_generic(freegenerics,
                EMAILIRI_CONTENTS_CLIENT_PORT, sizeof(port), (uint8_t *)&port);
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);
    }

    *params_p = params;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
