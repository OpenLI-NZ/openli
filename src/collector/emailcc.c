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

static openli_export_recv_t *create_emailcc_job(char *liid,
        emailsession_t *sess, uint32_t destid, uint64_t timestamp,
        uint8_t *content, int content_len, uint8_t format, uint8_t dir) {

    openli_export_recv_t *msg = NULL;

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
        uint8_t format, email_intercept_ref_t *intlist,
        uint64_t timestamp, uint8_t dir, const char *key, uint8_t deflated) {

    openli_export_recv_t *ccjob = NULL;
    email_intercept_ref_t *ref, *tmp;
    char fullkey[4096];

    PWord_t pval;

    HASH_ITER(hh, intlist, ref, tmp) {

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

        if (key != NULL) {
            snprintf(fullkey, 4096, "%s-%s", ref->em->common.liid, key);
            JSLG(pval, sess->ccs_sent, fullkey);
            if (pval != NULL) {
                /* We've already sent this particular CC for this intercept, but
                 * it has reached us again (probably because the target has
                 * multiple addresses and more than one has turned up as a
                 * recipient for this session.
                 *
                 * Don't send a duplicate CC in that case
                 */
                continue;
            }
            JSLI(pval, sess->ccs_sent, fullkey);
            *pval = 1;
        }


        /* Once the compressed data handler is set for a session, let's not
         * change it. If the user changes either the default setting or the
         * setting specific to this intercept, we'll apply the changes on
         * any NEW sessions but I don't think it is a good idea to mix and
         * match behaviour within the same session.
         */
        if (sess->handle_compress == OPENLI_EMAILINT_DELIVER_COMPRESSED_NOT_SET)
        {
            if (ref->em->delivercompressed ==
                    OPENLI_EMAILINT_DELIVER_COMPRESSED_DEFAULT) {
                sess->handle_compress = state->default_compress_delivery;
            } else {
                sess->handle_compress = ref->em->delivercompressed;
            }
        }

        if (sess->handle_compress == OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS) {

            if (sess->compressed && deflated == 0) {
                continue;
            }
        } else if (sess->handle_compress ==
                OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED) {
            if (sess->compressed && deflated == 1) {
                continue;
            }
        } else {
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
        uint64_t timestamp, const char *address, uint8_t dir,
        int command_index) {

    email_address_set_t *active_addr = NULL;
    email_target_set_t *active_tgt = NULL;
    email_intercept_ref_t *intlist = NULL;

    email_participant_t *recip, *tmp;
    char key[1024];
    const char *part_type;

    if (address == NULL || sess->sender.emailaddr == NULL) {
        return 0;
    }
    active_addr = is_address_interceptable(state, address);
    if (!active_addr) {
        active_tgt = is_targetid_interceptable(state, address);
        if (active_tgt) {
            intlist = active_tgt->intlist;
        }
    } else {
        intlist = active_addr->intlist;
    }

    if (intlist) {
        if (strcmp(address, sess->sender.emailaddr) == 0) {
            part_type = "sender";
        } else if (sess->ingest_target_id &&
                strcmp(address, sess->ingest_target_id) == 0) {
            if (sess->ingest_direction == OPENLI_EMAIL_DIRECTION_OUTBOUND) {
                part_type = "sender";
            } else {
                part_type = "recipient";
            }
        } else {
            part_type = "recipient";
        }
        snprintf(key, 1024, "%d-%u", command_index, dir);
        create_emailccs_for_intercept_list(state, sess, content,
                content_len, ETSILI_EMAIL_CC_FORMAT_APP, intlist, timestamp,
                dir, key, 0);
    }

    return 0;
}

int generate_email_cc_from_pop3_payload(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t *content, int content_len,
        uint64_t timestamp, uint8_t etsidir) {

    email_address_set_t *active = NULL;
    email_participant_t *recip, *tmp;

    /* POP3 is purely a mail receiving protocol so sender should be
     * irrelevant.
     */

    HASH_ITER(hh, sess->participants, recip, tmp) {
        active = is_address_interceptable(state, recip->emailaddr);
        if (!active) {
            continue;
        }

        create_emailccs_for_intercept_list(state, sess, content, content_len,
                ETSILI_EMAIL_CC_FORMAT_APP, active->intlist, timestamp,
                etsidir, NULL, 0);
    }

    return 0;
}


int generate_email_cc_from_imap_payload(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t *content, int content_len,
        uint64_t timestamp, uint8_t etsidir, uint8_t deflated) {

    email_address_set_t *active = NULL;
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
                ETSILI_EMAIL_CC_FORMAT_APP, active->intlist, timestamp,
                etsidir, NULL, deflated);
    }

    return 0;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
