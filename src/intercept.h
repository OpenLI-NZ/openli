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

#ifndef OPENLI_INTERCEPT_H_
#define OPENLI_INTERCEPT_H_

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libtrace/linked_list.h>
#include <uthash.h>

typedef struct ipintercept {
    char *liid;
    char *authcc;
    char *delivcc;
    char *username;

    int liid_len;
    int authcc_len;
    int delivcc_len;
    int username_len;

    uint32_t destid;
    char *targetagency;
    uint8_t awaitingconfirm;
    UT_hash_handle hh_liid;
} ipintercept_t;

typedef struct sdpidentifier {
    uint32_t sessionid;
    uint32_t version;
} sip_sdp_identifier_t;

typedef struct voipintshared {
    uint32_t cin;
    uint32_t iriseqno;
    int refs;
} voipintshared_t;

/* Two types of VOIP intercept structure -- one for the target which stores
 * all CINs for that target, and another for each target/CIN combination
 * which is used by the collector threads to maintain per-CIN state.
 */
typedef struct voipcinmap {

    char *callid;
    voipintshared_t *shared;
    UT_hash_handle hh_callid;

} voipcinmap_t;

typedef struct voipsdpmap {
    sip_sdp_identifier_t sdpkey;
    voipintshared_t *shared;
    UT_hash_handle hh_sdp;
} voipsdpmap_t;


typedef struct rtpstreaminf rtpstreaminf_t;

#define voip_intercept_equal(a,b) \
    ((strcmp(a->authcc, b->authcc) == 0) && \
     (strcmp(a->delivcc, b->delivcc) == 0) && \
     (strcmp(a->sipuri, b->sipuri) == 0) && \
     (strcmp(a->targetagency, b->targetagency) == 0))

typedef struct voipintercept {

    uint64_t internalid;
    char *liid;
    char *authcc;
    char *delivcc;
    char *sipuri;

    int liid_len;
    int authcc_len;
    int delivcc_len;
    int sipuri_len;

    uint32_t destid;
    char *targetagency;
    uint8_t awaitingconfirm;
    uint8_t active;

    voipcinmap_t *cin_callid_map;
    voipsdpmap_t *cin_sdp_map;
    rtpstreaminf_t *active_cins;

    UT_hash_handle hh_liid;
} voipintercept_t;

struct rtpstreaminf {
    char *streamkey;
    uint32_t cin;

    int ai_family;
    struct sockaddr_storage *targetaddr;
    struct sockaddr_storage *otheraddr;
    uint16_t targetport;
    uint16_t otherport;
    uint32_t seqno;
    uint8_t active;
    uint8_t byematched;
    char *invitecseq;
    char *byecseq;

    void *timeout_ev;
    voipintercept_t *parent;
    UT_hash_handle hh;
};

void free_all_ipintercepts(ipintercept_t *interceptlist);
void free_all_voipintercepts(voipintercept_t *vintercepts);
void free_all_rtpstreams(rtpstreaminf_t *streams);
void free_single_voip_cin(rtpstreaminf_t *rtp);
void free_single_ipintercept(ipintercept_t *cept);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
