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

#include "email_worker.h"
#include "intercept.h"
#include "util.h"
#include "logger.h"
#include "etsili_core.h"

static inline email_user_intercept_list_t *is_address_interceptable(
        openli_email_worker_t *state, char *emailaddr) {

    email_user_intercept_list_t *active = NULL;

    HASH_FIND(hh, state->alltargets, emailaddr, strlen(emailaddr), active);
    return active;
}

static openli_export_recv_t *create_emailcc_job(char *liid,
        emailsession_t *sess, uint32_t destid, uint64_t timestamp,
        uint8_t *content, int content_len, uint8_t format, uint8_t dir) {

    openli_export_recv_t *msg = NULL;
    size_t liidlen = strlen(liid);

    msg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    if (msg == NULL) {
        return msg;
    }
    msg->type = OPENLI_EXPORT_EMAILCC;
    msg->destid = destid;
    msg->ts.tv_sec = (time_t)(timestamp / 1000.0);
    msg->ts.tv_usec = ((time_t)(timestamp % 1000)) * 1000;

    msg->data.emailcc.format = format;
    msg->data.emailcc.dir = dir;
    msg->data.emailcc.liid = strdup(liid);
    msg->data.emailcc.cin = sess->cin;
    msg->data.emailcc.cc_content_len = content_len;

    msg->data.emailcc.cc_content = (uint8_t *)malloc(content_len);
    memcpy(msg->data.emailcc.cc_content, content, content_len);

    return msg;
}

static void create_emailccs_for_intercept_list(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t *content, int content_len,
        uint8_t format, email_user_intercept_list_t *active,
        uint64_t timestamp, uint8_t dir) {

    openli_export_recv_t *ccjob = NULL;
    email_intercept_ref_t *ref, *tmp;

    HASH_ITER(hh, active->intlist, ref, tmp) {

        if (ref->em->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_IRIONLY) {
            continue;
        }

        if (timestamp < ref->em->common.tostart_time * 1000) {
            continue;
        }
        if (ref->em->common.toend_time > 0 &&
                timestamp > ref->em->common.toend_time * 1000) {
            continue;
        }
        ccjob = create_emailcc_job(ref->em->common.liid, sess,
                ref->em->common.destid, timestamp, content, content_len,
                format, dir);
        if (ccjob == NULL) {
            continue;
        }
        pthread_mutex_lock(state->stats_mutex);
        state->stats->emailcc_created ++;
        pthread_mutex_unlock(state->stats_mutex);
        publish_openli_msg(
                state->zmq_pubsocks[ref->em->common.seqtrackerid], ccjob);

    }
}

int generate_email_cc_from_smtp_payload(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t *content, int content_len,
        uint64_t timestamp) {

    email_user_intercept_list_t *active = NULL;
    email_participant_t *recip, *tmp;

    if (sess->sender.emailaddr) {
        active = is_address_interceptable(state, sess->sender.emailaddr);
    }

    if (active) {
        create_emailccs_for_intercept_list(state, sess, content, content_len,
                ETSILI_EMAIL_CC_FORMAT_APP, active, timestamp,
                ETSI_DIR_FROM_TARGET);
    }

    HASH_ITER(hh, sess->participants, recip, tmp) {
        if (sess->sender.emailaddr != NULL &&
                strcmp(recip->emailaddr, sess->sender.emailaddr) == 0) {
            continue;
        }

        active = is_address_interceptable(state, recip->emailaddr);
        if (!active) {
            continue;
        }

        create_emailccs_for_intercept_list(state, sess, content, content_len,
                ETSILI_EMAIL_CC_FORMAT_APP, active, timestamp,
                ETSI_DIR_TO_TARGET);
    }

    return 0;
}

int generate_email_cc_from_imap_payload(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t *content, int content_len,
        uint64_t timestamp, uint8_t etsidir) {

    email_user_intercept_list_t *active = NULL;
    email_participant_t *recip, *tmp;

    /* IMAP is purely a mail receiving protocol so sender should be
     * irrelevant.
     */

    HASH_ITER(hh, sess->participants, recip, tmp) {
        active = is_address_interceptable(state, recip->emailaddr);
        if (!active) {
            continue;
        }

        create_emailccs_for_intercept_list(state, sess, content, content_len,
                ETSILI_EMAIL_CC_FORMAT_APP, active, timestamp,
                etsidir);
    }

    return 0;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
