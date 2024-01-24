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

static void add_recipients(emailsession_t *sess,
        etsili_email_iri_content_t *content, const char **tgtaddrs,
        int tgtaddr_count) {

    int i;

    /* XXX removing non-target recipients when the target is also a
     * recipient is possibly a country-specific requirement, so we
     * may need to make this a configurable option in the future...
     */
    content->recipient_count = tgtaddr_count;
    content->recipients = calloc(content->recipient_count, sizeof(char *));

    for (i = 0; i < tgtaddr_count; i++) {
        content->recipients[i] = strdup(tgtaddrs[i]);
    }

}

static openli_export_recv_t *create_emailiri_job(char *liid,
        emailsession_t *sess, uint8_t iritype, uint8_t emailev,
        uint8_t status, uint32_t destid, uint64_t timestamp,
        const char **tgtaddrs, int tgtaddr_count) {

    openli_export_recv_t *msg = NULL;
    etsili_email_iri_content_t *content;
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
    if (sess->serveraddr) {
        content->serveraddr = calloc(1, sizeof(struct sockaddr_storage));
        memcpy(content->serveraddr, sess->serveraddr,
                sizeof(struct sockaddr_storage));
    } else {
        content->serveraddr = NULL;
    }

    if (sess->clientaddr) {
        content->clientaddr = calloc(1, sizeof(struct sockaddr_storage));
        memcpy(content->clientaddr, sess->clientaddr,
                sizeof(struct sockaddr_storage));
    } else {
        content->clientaddr = NULL;
    }
    content->server_octets = sess->server_octets;
    content->client_octets = sess->client_octets;
    content->protocol = sess->protocol;
    content->sender_validity = sess->sender_validated_etsivalue;

    if (sess->sender.emailaddr) {
        content->sender = strdup(sess->sender.emailaddr);
    } else {
        content->sender = NULL;
    }

    if (sess->protocol == OPENLI_EMAIL_TYPE_SMTP &&
            (emailev == ETSILI_EMAIL_EVENT_LOGON ||
             emailev == ETSILI_EMAIL_EVENT_LOGON_FAILURE ||
             emailev == ETSILI_EMAIL_EVENT_LOGOFF)) {
        /* don't add recipients to SMTP logon or logoff events */
    } else {
        add_recipients(sess, content, tgtaddrs, tgtaddr_count);
    }

    content->status = status;
    content->messageid = NULL;

    if (content->recipient_count <= 0 &&
            (emailev == ETSILI_EMAIL_EVENT_RECEIVE ||
             emailev == ETSILI_EMAIL_EVENT_PARTIAL_DOWNLOAD ||
             emailev == ETSILI_EMAIL_EVENT_DOWNLOAD)) {
        /* receive event but no recipients that we haven't already sent this
         * IRI for, so just bin it.
         */
        free_published_message(msg);
        return NULL;
    }

    return msg;

}

static void create_emailiris_for_intercept_list(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t iri_type, uint8_t email_ev,
        uint8_t status, email_intercept_ref_t *intlist, uint64_t ts,
        const char *key, const char *tgtaddr, uint8_t full_recip_list) {

    openli_export_recv_t *irijob = NULL;
    email_intercept_ref_t *ref, *tmp;
    email_target_t *found;
    char fullkey[4096];
    PWord_t pval;
    const char **fulltgtaddrs = NULL;
    const char **tgtaddrs = NULL;
    const char **usetargets = NULL;
    int usetarget_count = 0;
    int fulltgtaddr_count = 0;
    int tgtaddr_count = 0, i;
    email_participant_t *recip, *tmp2;

    fulltgtaddr_count = HASH_CNT(hh, sess->participants);
    fulltgtaddrs = calloc(HASH_CNT(hh, sess->participants), sizeof(char *));

    i = 0;
    HASH_ITER(hh, sess->participants, recip, tmp2) {
        fulltgtaddrs[i] = recip->emailaddr;
        i++;
    }

    HASH_ITER(hh, intlist, ref, tmp) {
        if (ref->em->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_CCONLY) {
            continue;
        }

        if (ts < ref->em->common.tostart_time * 1000) {
            continue;
        }

        if (ref->em->common.toend_time > 0 &&
                ts > ref->em->common.toend_time * 1000) {
            continue;
        }

        if (key != NULL) {
            snprintf(fullkey, 4096, "%s-%s", ref->em->common.liid, key);
            JSLG(pval, sess->iris_sent, fullkey);
            if (pval) {
                /* We've already sent this particular IRI for this intercept.
                 * Avoid sending a duplicate.
                 */
                continue;
            }
            JSLI(pval, sess->iris_sent, fullkey);
            *pval = 1;
        }

        if (email_ev == ETSILI_EMAIL_EVENT_RECEIVE ||
                email_ev == ETSILI_EMAIL_EVENT_PARTIAL_DOWNLOAD ||
                email_ev == ETSILI_EMAIL_EVENT_DOWNLOAD) {
            /* only include recipients that are also intercept targets
             *
             * exceptions:
             *  - the target address that we matched on is NOT present in
             *    the participant list (i.e. one of the recipients is actually
             *    an alias, but we do not know which one)
             */
            if (full_recip_list) {
                usetargets = fulltgtaddrs;
                usetarget_count = fulltgtaddr_count;
            } else {
                if (!tgtaddrs) {
                    tgtaddrs = calloc(fulltgtaddr_count, sizeof(char *));
                }
                tgtaddr_count = 0;

                HASH_ITER(hh, sess->participants, recip, tmp2) {
                    found = NULL;
                    HASH_FIND(hh, ref->em->targets, recip->emailaddr,
                            strlen(recip->emailaddr), found);
                    if (found) {
                        tgtaddrs[tgtaddr_count] = recip->emailaddr;
                        tgtaddr_count ++;
                    }
                }
                usetargets = tgtaddrs;
                usetarget_count = tgtaddr_count;
            }

        } else if (email_ev == ETSILI_EMAIL_EVENT_SEND ||
                email_ev == ETSILI_EMAIL_EVENT_UPLOAD ||
                email_ev == ETSILI_EMAIL_EVENT_LOGON ||
                email_ev == ETSILI_EMAIL_EVENT_LOGON_FAILURE ||
                email_ev == ETSILI_EMAIL_EVENT_LOGOFF) {
            usetargets = fulltgtaddrs;
            usetarget_count = fulltgtaddr_count;
        } else {
            usetargets = NULL;
            usetarget_count = 0;
        }

        irijob = create_emailiri_job(ref->em->common.liid, sess,
                iri_type, email_ev, status, ref->em->common.destid, ts,
                usetargets, usetarget_count);
        if (irijob == NULL) {
            continue;
        }
        pthread_mutex_lock(state->stats_mutex);
        state->stats->emailiri_created ++;
        pthread_mutex_unlock(state->stats_mutex);
        publish_openli_msg(
                state->zmq_pubsocks[ref->em->common.seqtrackerid], irijob);
    }
    if (tgtaddrs) {
        free(tgtaddrs);
    }
    if (fulltgtaddrs) {
        free(fulltgtaddrs);
    }

}

static inline int generate_iris_for_participants(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t email_ev, uint8_t iri_type,
        uint8_t status, uint64_t timestamp) {

    email_address_set_t *active_addr = NULL;
    email_target_set_t *active_tgt = NULL;
    email_participant_t *recip, *tmp;
    email_intercept_ref_t *intlist = NULL;

    const char *tgtaddr = NULL;
    char senderkey[1024];
    char recipkey[1024];

    sess->iricount ++;
    snprintf(senderkey, 1024, "iri-%d-sender", sess->iricount);
    snprintf(recipkey, 1024, "iri-%d-recipient", sess->iricount);

    if (email_ev != ETSILI_EMAIL_EVENT_RECEIVE) {
        if (sess->sender.emailaddr) {
            active_addr = is_address_interceptable(state,
                    sess->sender.emailaddr);
        }
        if (active_addr) {
            intlist = active_addr->intlist;
            tgtaddr = active_addr->emailaddr;
        } else if (sess->ingest_target_id &&
                sess->ingest_direction == OPENLI_EMAIL_DIRECTION_OUTBOUND) {
            active_tgt = is_targetid_interceptable(state,
                    sess->ingest_target_id);

            if (active_tgt) {
                intlist = active_tgt->intlist;
                tgtaddr = active_tgt->origaddress;
            }
        }

        if (intlist) {
            /* If the sender is a target, we'll need to include all recipients
             * in the recipient list.
             */
            create_emailiris_for_intercept_list(state, sess, iri_type,
                    email_ev, status, intlist, timestamp, senderkey,
                    tgtaddr, 1);
        }

    }

    /* Don't generate login / logoff IRIs for SMTP recipients */
    if (sess->protocol == OPENLI_EMAIL_TYPE_SMTP && (
            email_ev == ETSILI_EMAIL_EVENT_LOGON ||
            email_ev == ETSILI_EMAIL_EVENT_LOGON_FAILURE ||
            email_ev == ETSILI_EMAIL_EVENT_LOGOFF)) {
        return 0;
    }

    if (email_ev != ETSILI_EMAIL_EVENT_SEND) {
        /* Look for the TARGET_ID first.
         * If we have a match, check if the original address is in the
         * participant list. If not, it's an alias situation and we need
         * to include all recipients in our IRI.
         *
         * If there's no match, or if the match is explicitly included
         * as a recipient, then we just want to include recipients who
         * are named as target addresses in the intercept configuration.
         */
        if (sess->ingest_direction == OPENLI_EMAIL_DIRECTION_INBOUND &&
                sess->ingest_target_id != NULL) {
            active_tgt = is_targetid_interceptable(state,
                    sess->ingest_target_id);
            if (active_tgt) {
                HASH_FIND(hh, sess->participants, active_tgt->origaddress,
                        strlen(active_tgt->origaddress), recip);
                if (!recip) {
                    /* one of the recipients is an alias for this intercept
                     * target, but we don't know which one so we have to
                     * include them all
                     */
                    create_emailiris_for_intercept_list(state, sess, iri_type,
                            email_ev, status, active_tgt->intlist, timestamp,
                            recipkey, active_tgt->origaddress, 1);
                }
            }
        }

        HASH_ITER(hh, sess->participants, recip, tmp) {
            active_addr = is_address_interceptable(state, recip->emailaddr);
            if (active_addr) {
                create_emailiris_for_intercept_list(state, sess, iri_type,
                        email_ev, status, active_addr->intlist, timestamp,
                        recipkey, active_addr->emailaddr, 0);
            }
        }
    }

    return 0;
}

static int generate_iris_for_mailbox(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t email_ev, uint8_t iri_type,
        uint8_t status, uint64_t timestamp, const char *mailbox) {

    email_address_set_t *active_addr = NULL;
    email_target_set_t *active_tgt = NULL;
    email_intercept_ref_t *intlist = NULL;

    char *tgtaddr = NULL;
    char irikey[1024];

    active_addr = is_address_interceptable(state, mailbox);
    if (!active_addr) {
        active_tgt = is_targetid_interceptable(state, sess->ingest_target_id);
        if (active_tgt) {
            tgtaddr = active_tgt->origaddress;
            intlist = active_tgt->intlist;
        }
    } else {
        intlist = active_addr->intlist;
        tgtaddr = active_addr->emailaddr;
    }

    if (intlist) {
        sess->iricount ++;
        snprintf(irikey, 1024, "iri-%d-mailbox", sess->iricount);
        create_emailiris_for_intercept_list(state, sess, iri_type, email_ev,
                status, intlist, timestamp, irikey, tgtaddr, 0);
    }
    return 0;
}

static int generate_email_login_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *participant, uint8_t success) {

    uint8_t email_ev;
    uint8_t iri_type;
    uint8_t status;

    char *tgtaddr = NULL;
    email_address_set_t *active_addr = NULL;
    email_target_set_t *active_tgt = NULL;
    email_participant_t *recip, *tmp;
    email_intercept_ref_t *intlist = NULL;

    active_addr = is_address_interceptable(state, participant);
    if (!active_addr) {
        active_tgt = is_targetid_interceptable(state, sess->ingest_target_id);
        if (sess->ingest_direction == OPENLI_EMAIL_DIRECTION_INBOUND) {
            /* only generate login events for targets who are sending mail */
            return 0;
        }
        if (active_tgt) {
            intlist = active_tgt->intlist;
            tgtaddr = active_tgt->origaddress;
        }
    } else {
        intlist = active_addr->intlist;
        tgtaddr = active_addr->emailaddr;
    }

    if (success) {
        email_ev = ETSILI_EMAIL_EVENT_LOGON;
        iri_type = ETSILI_IRI_BEGIN;
        status = ETSILI_EMAIL_STATUS_SUCCESS;
    } else {
        email_ev = ETSILI_EMAIL_EVENT_LOGON_FAILURE;
        iri_type = ETSILI_IRI_REPORT;
        status = ETSILI_EMAIL_STATUS_FAILED;
    }

    create_emailiris_for_intercept_list(state, sess, iri_type, email_ev,
            status, intlist, sess->login_time, participant, tgtaddr, 0);
    return 0;
}

int generate_email_logoff_iri_for_user(openli_email_worker_t *state,
        emailsession_t *sess, const char *address) {

    email_address_set_t *active_addr = NULL;
    email_target_set_t *active_tgt = NULL;
    email_intercept_ref_t *intlist = NULL;
    char *tgtaddr = NULL;

    active_addr = is_address_interceptable(state, address);

    if (!active_addr) {
        active_tgt = is_targetid_interceptable(state, sess->ingest_target_id);
        if (sess->ingest_direction == OPENLI_EMAIL_DIRECTION_INBOUND) {
            /* only generate login events for targets who are sending mail */
            return 0;
        }
        intlist = active_tgt->intlist;
        tgtaddr = active_tgt->origaddress;
    } else {
        intlist = active_addr->intlist;
        tgtaddr = active_addr->emailaddr;
    }

    if (intlist) {
        create_emailiris_for_intercept_list(state, sess,
                ETSILI_IRI_END, ETSILI_EMAIL_EVENT_LOGOFF,
                ETSILI_EMAIL_STATUS_SUCCESS, intlist, sess->event_time,
                NULL, tgtaddr, 0);
    }

    return 0;
}

int generate_email_send_iri(openli_email_worker_t *state,
        emailsession_t *sess) {

    return generate_iris_for_participants(state, sess, ETSILI_EMAIL_EVENT_SEND,
            ETSILI_IRI_CONTINUE, ETSILI_EMAIL_STATUS_SUCCESS, sess->event_time);

}

int generate_email_receive_iri(openli_email_worker_t *state,
        emailsession_t *sess) {

    return generate_iris_for_participants(state, sess,
            ETSILI_EMAIL_EVENT_RECEIVE,
            ETSILI_IRI_CONTINUE, ETSILI_EMAIL_STATUS_SUCCESS, sess->event_time);

}

int generate_email_partial_download_success_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *mailbox) {

    return generate_iris_for_mailbox(state, sess,
            ETSILI_EMAIL_EVENT_PARTIAL_DOWNLOAD,
            ETSILI_IRI_REPORT, ETSILI_EMAIL_STATUS_SUCCESS, sess->event_time,
            mailbox);

}

int generate_email_partial_download_failure_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *mailbox) {

    return generate_iris_for_mailbox(state, sess,
            ETSILI_EMAIL_EVENT_PARTIAL_DOWNLOAD,
            ETSILI_IRI_REPORT, ETSILI_EMAIL_STATUS_FAILED, sess->event_time,
            mailbox);
}

int generate_email_upload_success_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *mailbox) {

    return generate_iris_for_mailbox(state, sess,
            ETSILI_EMAIL_EVENT_UPLOAD,
            ETSILI_IRI_REPORT, ETSILI_EMAIL_STATUS_SUCCESS, sess->event_time,
            mailbox);

}

int generate_email_upload_failure_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *mailbox) {

    return generate_iris_for_mailbox(state, sess,
            ETSILI_EMAIL_EVENT_UPLOAD,
            ETSILI_IRI_REPORT, ETSILI_EMAIL_STATUS_FAILED, sess->event_time,
            mailbox);
}

int generate_email_download_success_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *mailbox) {

    return generate_iris_for_mailbox(state, sess,
            ETSILI_EMAIL_EVENT_DOWNLOAD,
            ETSILI_IRI_REPORT, ETSILI_EMAIL_STATUS_SUCCESS, sess->event_time,
            mailbox);

}

int generate_email_download_failure_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *mailbox) {

    return generate_iris_for_mailbox(state, sess,
            ETSILI_EMAIL_EVENT_DOWNLOAD,
            ETSILI_IRI_REPORT, ETSILI_EMAIL_STATUS_FAILED, sess->event_time,
            mailbox);
}

int generate_email_logoff_iri(openli_email_worker_t *state,
        emailsession_t *sess) {

    return generate_iris_for_participants(state, sess,
            ETSILI_EMAIL_EVENT_LOGOFF, ETSILI_IRI_END,
            ETSILI_EMAIL_STATUS_SUCCESS, sess->event_time);

}

int generate_email_login_success_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *participant) {
    return generate_email_login_iri(state, sess, participant, 1);
}

int generate_email_login_failure_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *participant) {
    return generate_email_login_iri(state, sess, participant, 0);
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

    if (job->content.protocol == OPENLI_EMAIL_TYPE_SMTP) {
        np = create_etsili_generic(freegenerics,
                EMAILIRI_CONTENTS_SENDER_VALIDITY,
                sizeof(job->content.sender_validity),
                (uint8_t *)&(job->content.sender_validity));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);
    }

    if (job->content.sender) {
        np = create_etsili_generic(freegenerics, EMAILIRI_CONTENTS_SENDER,
                strlen(job->content.sender), (uint8_t *)(job->content.sender));
        HASH_ADD_KEYPTR(hh, params, &(np->itemnum), sizeof(np->itemnum), np);
    }

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
