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
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#ifndef OPENLI_COLLECTOR_H_
#define OPENLI_COLLECTOR_H_

#include <pthread.h>
#include <inttypes.h>
#include <libtrace.h>
#include <libtrace/message_queue.h>
#include <libtrace/linked_list.h>
#include <libwandder.h>

#include "intercept.h"

enum {
    OPENLI_PUSH_IPINTERCEPT = 1,
    OPENLI_PUSH_HALT_IPINTERCEPT = 2
};

typedef struct export_buffer {
    uint8_t *bufhead;
    uint8_t *buftail;
    uint64_t alloced;

    uint32_t partialfront;
} export_buffer_t;

enum {
    OPENLI_UPDATE_HELLO = 0,
    OPENLI_UPDATE_RADIUS = 1,
    OPENLI_UPDATE_DHCP = 2,
    OPENLI_UPDATE_SIP = 3
};

typedef struct openli_state_msg {

    uint8_t type;
    union {
        libtrace_message_queue_t *replyq;
    } data;

} openli_state_update_t;

typedef struct openli_ii_msg {

    uint8_t type;
    union {
        ipintercept_t *ipint;
        uint64_t interceptid;
    } data;

} openli_pushed_t;

typedef struct colinput_config {
    char *uri;
    int threadcount;

} colinput_config_t;

typedef struct colinput {
    colinput_config_t config;
    libtrace_t *trace;

    libtrace_callback_set_t *pktcbs;

} colinput_t;

typedef struct colthread_local {

    /* Message queue for pushing updates to sync thread */
    libtrace_message_queue_t tosyncq;

    /* Message queue for receiving intercept instructions from sync thread */
    libtrace_message_queue_t fromsyncq;


    /* Current intercepts */
    /* XXX For now, we can probably get away with a simple unordered list but
     * eventually we might want a radix tree for faster lookups */
    libtrace_list_t *activeipintercepts;

    /* Message queue for exporting LI records */
    libtrace_message_queue_t exportq;

    wandder_encoder_t *encoder;

    char *inputidentifier;

} colthread_local_t;

typedef struct collector_global {

    int inputcount;
    int inputalloced;
    colinput_t *inputs;

    int totalthreads;
    int queuealloced;
    int registered_syncqs;

    pthread_mutex_t syncq_mutex;

    libtrace_message_queue_t **syncsendqs;
    void **syncepollevs;

    pthread_t syncthreadid;
    pthread_t exportthreadid;

    int sync_epollfd;
    int export_epollfd;

    char *configfile;
    char *operatorid;
    char *networkelemid;
    char *intpointid;
    char *provisionerip;
    char *provisionerport;

    int operatorid_len;
    int networkelemid_len;
    int intpointid_len;

    libtrace_list_t *export_epoll_evs;

} collector_global_t;

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
