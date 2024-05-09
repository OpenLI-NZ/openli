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


#ifndef OPENLI_EMAIL_WORKER_H_
#define OPENLI_EMAIL_WORKER_H_

#include <uthash.h>
#include <Judy.h>

#include "util.h"
#include "reassembler.h"
#include "intercept.h"
#include "collector_base.h"

typedef enum {
    OPENLI_EMAIL_TYPE_UNKNOWN = 0,
    OPENLI_EMAIL_TYPE_SMTP = 1,
    OPENLI_EMAIL_TYPE_POP3 = 2,
    OPENLI_EMAIL_TYPE_IMAP = 3,
} openli_email_type_t;

enum {
    OPENLI_EMAIL_DIRECTION_UNKNOWN,
    OPENLI_EMAIL_DIRECTION_OUTBOUND,
    OPENLI_EMAIL_DIRECTION_INBOUND
};

enum {
    OPENLI_EMAIL_PACKET_SENDER_UNKNOWN,
    OPENLI_EMAIL_PACKET_SENDER_SERVER,
    OPENLI_EMAIL_PACKET_SENDER_CLIENT,
};

typedef enum {
    OPENLI_IMAP_STATE_INIT = 0,
    OPENLI_IMAP_STATE_SESSION_OVER,
    OPENLI_IMAP_STATE_SERVER_READY,
    OPENLI_IMAP_STATE_PRE_AUTH,
    OPENLI_IMAP_STATE_AUTH_STARTED,
    OPENLI_IMAP_STATE_AUTHENTICATING,
    OPENLI_IMAP_STATE_AUTH_REPLY,
    OPENLI_IMAP_STATE_AUTHENTICATED,
    OPENLI_IMAP_STATE_APPENDING,
    OPENLI_IMAP_STATE_IDLING,
    OPENLI_IMAP_STATE_LOGOUT,
    OPENLI_IMAP_STATE_IGNORING,
} openli_imap_status_t;

typedef enum {
    OPENLI_EMAIL_AUTH_NONE,
    OPENLI_EMAIL_AUTH_PLAIN,
    OPENLI_EMAIL_AUTH_LOGIN,
    OPENLI_EMAIL_AUTH_GSSAPI,
    OPENLI_EMAIL_AUTH_OTHER,
} openli_email_auth_type_t;

typedef enum {
    OPENLI_SMTP_STATE_INIT = 0,
    OPENLI_SMTP_STATE_EHLO,
    OPENLI_SMTP_STATE_EHLO_RESPONSE,
    OPENLI_SMTP_STATE_EHLO_OVER,
    OPENLI_SMTP_STATE_MAIL_FROM,
    OPENLI_SMTP_STATE_MAIL_FROM_REPLY,
    OPENLI_SMTP_STATE_MAIL_FROM_OVER,
    OPENLI_SMTP_STATE_RCPT_TO,
    OPENLI_SMTP_STATE_RCPT_TO_REPLY,
    OPENLI_SMTP_STATE_RCPT_TO_OVER,
    OPENLI_SMTP_STATE_DATA_INIT_REPLY,
    OPENLI_SMTP_STATE_DATA_CONTENT,
    OPENLI_SMTP_STATE_DATA_FINAL_REPLY,
    OPENLI_SMTP_STATE_DATA_OVER,
    OPENLI_SMTP_STATE_RESET,
    OPENLI_SMTP_STATE_QUIT,
    OPENLI_SMTP_STATE_QUIT_REPLY,
    OPENLI_SMTP_STATE_AUTH,
    OPENLI_SMTP_STATE_AUTH_REPLY,
    OPENLI_SMTP_STATE_AUTH_CREDS,
    OPENLI_SMTP_STATE_OTHER_COMMAND,
    OPENLI_SMTP_STATE_OTHER_COMMAND_REPLY,
    OPENLI_SMTP_STATE_STARTTLS,
} openli_smtp_status_t;

typedef struct openli_email_timeouts {
    uint16_t smtp;
    uint16_t imap;
    uint16_t pop3;
} openli_email_timeouts_t;

typedef struct openli_email_captured {

    openli_email_type_t type;
    char *session_id;
    char *target_id;
    char *remote_ip;
    char *remote_port;
    char *host_ip;
    char *host_port;
    char *datasource;
    uint8_t direction;

    uint64_t timestamp;
    uint32_t mail_id;
    uint32_t part_id;
    uint32_t msg_length;
    char *content;
    uint8_t own_content;
    uint8_t pkt_sender;

} openli_email_captured_t;

typedef struct openli_email_worker {

    void *zmq_ctxt;
    zmq_pollitem_t *topoll;
    int topoll_size;
    ipfrag_reassembler_t *fragreass;
    pthread_t threadid;
    int emailid;
    int tracker_threads;
    int fwd_threads;
    uint8_t default_compress_delivery;

    void *zmq_ii_sock;          /* ZMQ for receiving instructions from sync thread */
    void **zmq_pubsocks;        /* ZMQs for publishing to seqtracker threads */
    void **zmq_fwdsocks;        /* ZMQs for publishing to forwarding threads */
    void *zmq_ingest_recvsock;      /* ZMQ for receiving from the ingestor */
    void *zmq_colthread_recvsock;   /* ZMQ for receiving from collector threads */

    sync_epoll_t *timeouts;

    emailintercept_t *allintercepts;
    email_user_intercept_list_t alltargets;

    emailsession_t *activesessions;

    pthread_mutex_t *stats_mutex;
    collector_stats_t *stats;

    openli_email_timeouts_t *timeout_thresholds;
    uint8_t *mask_imap_creds;
    uint8_t *mask_pop3_creds;
    uint8_t *email_ingest_use_targetid;

    /* The default domain to apply to authenticated usernames that do not
     * include a domain.
     */
    char **defaultdomain;
    string_set_t **email_forwarding_headers;
    pthread_rwlock_t *glob_config_mutex;

} openli_email_worker_t;

void *start_email_worker_thread(void *arg);
void free_captured_email(openli_email_captured_t *cap);

void free_smtp_session_state(emailsession_t *sess, void *smtpstate);
int update_smtp_session_by_ingestion(openli_email_worker_t *state,
        emailsession_t *sess, openli_email_captured_t *cap);
void free_imap_session_state(emailsession_t *sess, void *imapstate);
int update_imap_session_by_ingestion(openli_email_worker_t *state,
        emailsession_t *sess, openli_email_captured_t *cap);
void free_pop3_session_state(emailsession_t *sess, void *pop3state);
int update_pop3_session_by_ingestion(openli_email_worker_t *state,
        emailsession_t *sess, openli_email_captured_t *cap);

void add_email_participant(emailsession_t *sess, char *address, int issender);
void clear_email_participant_list(emailsession_t *sess);
void clear_email_sender(emailsession_t *sess);

int extract_email_sender_from_body(openli_email_worker_t *state,
        emailsession_t *sess, char *bodycontent, char **extracted);

void replace_email_session_serveraddr(emailsession_t *sess,
        char *server_ip, char *server_port);
void replace_email_session_clientaddr(emailsession_t *sess,
        char *client_ip, char *client_port);

int get_email_authentication_type(char *authmsg, const char *sesskey,
        openli_email_auth_type_t *at_code, uint8_t is_imap);
void mask_plainauth_creds(char *mailbox, char *reencoded, int buflen);

email_address_set_t *is_address_interceptable(
        openli_email_worker_t *state, const char *emailaddr);
email_target_set_t *is_targetid_interceptable(
        openli_email_worker_t *state, const char *targetid);

/* Defined in emailiri.c */
int generate_email_partial_download_success_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *mailbox);
int generate_email_partial_download_failure_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *mailbox);
int generate_email_download_success_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *mailbox);
int generate_email_download_failure_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *mailbox);
int generate_email_login_success_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *participant);
int generate_email_login_failure_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *participant);
int generate_email_upload_success_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *mailbox);
int generate_email_upload_failure_iri(openli_email_worker_t *state,
        emailsession_t *sess, const char *mailbox);
int generate_email_send_iri(openli_email_worker_t *state,
        emailsession_t *sess);
int generate_email_receive_iri(openli_email_worker_t *state,
        emailsession_t *sess);
int generate_email_logoff_iri(openli_email_worker_t *state,
        emailsession_t *sess);
int generate_email_logoff_iri_for_user(openli_email_worker_t *state,
        emailsession_t *sess, const char *address);

/* Defined in emailcc.c */
int generate_email_cc_from_smtp_payload(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t *content, int content_len,
        uint64_t timestamp, const char *participant, uint8_t dir,
        int command_index);
int generate_email_cc_from_imap_payload(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t *content, int content_len,
        uint64_t timestamp, uint8_t dir, uint8_t deflated);
int generate_email_cc_from_pop3_payload(openli_email_worker_t *state,
        emailsession_t *sess, uint8_t *content, int content_len,
        uint64_t timestamp, uint8_t dir);
#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
