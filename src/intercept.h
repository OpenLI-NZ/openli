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

#define OPENLI_ALUSHIM_NONE (0xffffffff)

typedef enum {
    INTERNET_ACCESS_TYPE_UNDEFINED = 0,
    INTERNET_ACCESS_TYPE_DIALUP = 1,
    INTERNET_ACCESS_TYPE_XDSL = 2,
    INTERNET_ACCESS_TYPE_CABLEMODEM = 3,
    INTERNET_ACCESS_TYPE_LAN = 4,
    INTERNET_ACCESS_TYPE_WIRELESS_LAN = 5,
    INTERNET_ACCESS_TYPE_FIBER = 6,
    INTERNET_ACCESS_TYPE_WIMAX = 7,
    INTERNET_ACCESS_TYPE_SATELLITE= 8,
    INTERNET_ACCESS_TYPE_WIRELESS_OTHER = 9,
} internet_access_method_t;

typedef struct static_ipranges {
    char *rangestr;
    char *liid;
    uint32_t cin;
    uint8_t awaitingconfirm;
    UT_hash_handle hh;
} static_ipranges_t;

typedef struct intercept_common {
    char *liid;
    char *authcc;
    char *delivcc;
    int liid_len;
    int authcc_len;
    int delivcc_len;
    uint32_t destid;
    char *targetagency;
} intercept_common_t;

typedef struct ipintercept {
    intercept_common_t common;

    char *username;
    int username_len;

    internet_access_method_t accesstype;


    /* Special case for converting ALU intercepts into ETSI ones */
    uint32_t alushimid;

    static_ipranges_t *statics;

    uint8_t awaitingconfirm;
    UT_hash_handle hh_liid;
    UT_hash_handle hh_user;
} ipintercept_t;

typedef struct userinterceptlist {
    char *username;
    ipintercept_t *intlist;
    UT_hash_handle hh;
} user_intercept_list_t;

typedef struct sip_identity {
    char *username;
    int username_len;
    char *realm;        // or hostname, I guess
    int realm_len;
    int awaitingconfirm;
    int active;
} openli_sip_identity_t;


typedef struct sdpidentifier {
    uint32_t sessionid;
    uint32_t version;
    char username[32];
    char address[32];
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
typedef struct ipsession ipsession_t;
typedef struct aluintercept aluintercept_t;

#define voip_intercept_equal(a,b) \
    ((strcmp(a->common.authcc, b->common.authcc) == 0) && \
     (strcmp(a->common.delivcc, b->common.delivcc) == 0) && \
     (strcmp(a->common.targetagency, b->common.targetagency) == 0))

typedef struct voipintercept {

    uint64_t internalid;
    intercept_common_t common;
    libtrace_list_t *targets;

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

    intercept_common_t common;
    voipintercept_t *parent;

    void *timeout_ev;
    UT_hash_handle hh;
};

struct ipsession {
    char *streamkey;
    uint32_t cin;
    int ai_family;
    struct sockaddr_storage *targetip;
    uint32_t nextseqno;
    internet_access_method_t accesstype;

    intercept_common_t common;
    UT_hash_handle hh;
};

struct aluintercept {
    uint32_t cin;       // how do we set this properly?
    uint32_t aluinterceptid;
    uint32_t nextseqno;

    intercept_common_t common;
    UT_hash_handle hh;
};

void free_all_ipintercepts(ipintercept_t *interceptlist);
void free_all_voipintercepts(voipintercept_t *vintercepts);
void free_all_rtpstreams(rtpstreaminf_t *streams);
void free_all_ipsessions(ipsession_t *sessions);
void free_all_aluintercepts(aluintercept_t *aluintercepts);
void free_voip_cinmap(voipcinmap_t *cins);
void free_single_voip_cin(rtpstreaminf_t *rtp);
void free_single_ipintercept(ipintercept_t *cept);
void free_single_voipintercept(voipintercept_t *v);
void free_single_ipsession(ipsession_t *sess);
void free_single_aluintercept(aluintercept_t *alu);

rtpstreaminf_t *create_rtpstream(voipintercept_t *vint, uint32_t cin);
rtpstreaminf_t *deep_copy_rtpstream(rtpstreaminf_t *rtp);

ipsession_t *create_ipsession(ipintercept_t *ipint, uint32_t cin,
        int ipfamily, struct sockaddr *assignedip);

aluintercept_t *create_aluintercept(ipintercept_t *ipint);

int are_sip_identities_same(openli_sip_identity_t *a,
        openli_sip_identity_t *b);

void clear_user_intercept_list(user_intercept_list_t *ulist);
int remove_intercept_from_user_intercept_list(user_intercept_list_t **ulist,
        ipintercept_t *ipint);
int add_intercept_to_user_intercept_list(user_intercept_list_t **ulist,
        ipintercept_t *ipint);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
