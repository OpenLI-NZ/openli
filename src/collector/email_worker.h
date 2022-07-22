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

typedef enum {
    OPENLI_EMAIL_TYPE_SMTP,
    OPENLI_EMAIL_TYPE_POP3,
    OPENLI_EMAIL_TYPE_IMAP,
} openli_email_type_t;

enum {
    OPENLI_EMAIL_DIRECTION_FROM_TARGET,
    OPENLI_EMAIL_DIRECTION_TO_TARGET
};

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
    uint32_t msg_length;
    char *content;

} openli_email_captured_t;

typedef struct email_session {

    /* TODO probably need a few more fields in here */
    char *session_id;

    uint32_t next_seqno;
    intercept_common_t common;
    UT_hash_handle hh;

} email_session_t;

typedef struct email_target {
    char *address;
    email_session_t *sessions;

    UT_hash_handle hh;
} email_target_t;

typedef struct openli_email_worker {

    void *zmq_ctxt;
    pthread_t threadid;
    int emailid;
    int tracker_threads;

    void *zmq_ii_sock;          /* ZMQ for receiving instructions from sync thread */
    void **zmq_pubsocks;        /* ZMQs for publishing to seqtracker threads */
    void *zmq_ingest_recvsock;      /* ZMQ for receiving from the ingestor */
    void *zmq_colthread_recvsock;   /* ZMQ for receiving from collector threads */

    email_target_t *activeintercepts;

} openli_email_worker_t;

void *start_email_worker_thread(void *arg);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
