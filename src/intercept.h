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

#define OPENLI_VENDOR_MIRROR_NONE (0xffffffff)

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
    INTERNET_ACCESS_TYPE_MOBILE = 32,       /* Not a "real" value */
} internet_access_method_t;

typedef enum {
    OPENLI_VOIPINT_OPTION_IGNORE_COMFORT = 0,
} voipintercept_options_t;

typedef enum {
    OPENLI_IPINT_OPTION_RADIUS_IDENT_CSID = 0,
    OPENLI_IPINT_OPTION_RADIUS_IDENT_USER = 1,
} ipintercept_options_t;

typedef enum {
    HI1_LI_ACTIVATED = 1,
    HI1_LI_DEACTIVATED = 2,
    HI1_LI_MODIFIED = 3,
    HI1_ALARM = 4
} hi1_notify_t;

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
    int seqtrackerid;
    uint32_t hi1_seqno;
    uint64_t tostart_time;
    uint64_t toend_time;
} intercept_common_t;

typedef struct hi1_notify_data {
    hi1_notify_t notify_type;
    char *liid;
    char *authcc;
    char *delivcc;
    char *agencyid;
    uint32_t seqno;
    uint64_t ts_sec;
    uint32_t ts_usec;
} hi1_notify_data_t;

typedef struct ipintercept {
    intercept_common_t common;

    char *username;
    int username_len;

    internet_access_method_t accesstype;

    /* Used in cases where we are converting vendor-mirrored packets into
     * ETSI records */
    uint32_t vendmirrorid;

    static_ipranges_t *statics;

    uint8_t awaitingconfirm;
    uint32_t options;
    UT_hash_handle hh_liid;
    UT_hash_handle hh_user;
} ipintercept_t;

typedef struct email_target {
    char *address;
    uint8_t awaitingconfirm;
    UT_hash_handle hh;
} email_target_t;

typedef struct userinterceptlist {
    char *username;
    ipintercept_t *intlist;
    UT_hash_handle hh;
} user_intercept_list_t;

typedef struct emailintercept {
    intercept_common_t common;
    email_target_t *targets;

    uint8_t awaitingconfirm;
    UT_hash_handle hh_liid;

} emailintercept_t;

typedef struct emailinterceptlist {
    char *emailaddr;
    emailintercept_t *intlist;
    UT_hash_handle hh;
} email_user_intercept_list_t;


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
    int refs;
} voipintshared_t;

/* Two types of VOIP intercept structure -- one for the target which stores
 * all CINs for that target, and another for each target/CIN combination
 * which is used by the collector threads to maintain per-CIN state.
 */
typedef struct voipcinmap {

    char *callid;
    char *username;
    char *realm;
    voipintshared_t *shared;
    UT_hash_handle hh_callid;

} voipcinmap_t;

typedef struct voipsdpmap {
    sip_sdp_identifier_t sdpkey;
    char *username;
    char *realm;
    voipintshared_t *shared;
    UT_hash_handle hh_sdp;
} voipsdpmap_t;


typedef struct rtpstreaminf rtpstreaminf_t;
typedef struct ipsession ipsession_t;
typedef struct emailsession emailsession_t;
typedef struct vendmirror_intercept vendmirror_intercept_t;
typedef struct staticipsession staticipsession_t;
typedef struct sipregister sipregister_t;

#define voip_intercept_equal(a,b) \
    ((strcmp(a->common.authcc, b->common.authcc) == 0) && \
     (strcmp(a->common.delivcc, b->common.delivcc) == 0) && \
     (strcmp(a->common.targetagency, b->common.targetagency) == 0) && \
     (a->common.tostart_time == b->common.tostart_time) && \
     (a->common.toend_time == b->common.toend_time) && \
     (a->options == b->options))

#define email_intercept_equal(a,b) \
    ((strcmp(a->common.authcc, b->common.authcc) == 0) && \
     (strcmp(a->common.delivcc, b->common.delivcc) == 0) && \
     (strcmp(a->common.targetagency, b->common.targetagency) == 0) && \
     (a->common.tostart_time == b->common.tostart_time) && \
     (a->common.toend_time == b->common.toend_time))


typedef struct voipintercept {

    uint64_t internalid;
    intercept_common_t common;
    libtrace_list_t *targets;

    uint32_t options;
    uint8_t awaitingconfirm;
    uint8_t active;
    voipcinmap_t *cin_callid_map;
    voipsdpmap_t *cin_sdp_map;
    rtpstreaminf_t *active_cins;
    sipregister_t *active_registrations;

    UT_hash_handle hh_liid;
} voipintercept_t;

struct sipregister {
    char *callid;
    uint32_t cin;

    intercept_common_t common;
    voipintercept_t *parent;

    UT_hash_handle hh;
};

#define RTP_STREAM_ALLOC 8

struct sipmediastream {
    uint16_t targetport;
    uint16_t otherport;
    char *mediatype;
};

typedef struct email_participant {
    char *emailaddr;
    uint8_t is_sender;
    UT_hash_handle hh;
} email_participant_t;

struct emailsession {
    char *key;
    uint32_t cin;

    char *session_id;
    int ai_family;
    struct sockaddr_storage *serveraddr;
    struct sockaddr_storage *clientaddr;

    email_participant_t *participants;

    uint32_t seqno;
    uint8_t active;
    uint8_t protocol;
    uint8_t currstate;
    void *timeout_ev;

    intercept_common_t common;
    UT_hash_handle hh;
};

struct rtpstreaminf {
    char *streamkey;
    uint32_t cin;

    int ai_family;
    struct sockaddr_storage *targetaddr;
    struct sockaddr_storage *otheraddr;

    int streamcount;
    struct sipmediastream *mediastreams;

    uint32_t seqno;
    uint8_t active;
    uint8_t changed;
    uint8_t byematched;
    char *invitecseq;
    char *byecseq;

    uint8_t skip_comfort;
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
    uint8_t prefixlen;
    uint32_t nextseqno;
    internet_access_method_t accesstype;

    intercept_common_t common;
    UT_hash_handle hh;
};

struct vendmirror_intercept {
    uint32_t sessionid;
    intercept_common_t common;
    UT_hash_handle hh;
};

typedef struct vendmirror_intercept_list {
    uint32_t sessionid;
    vendmirror_intercept_t *intercepts;
    UT_hash_handle hh;
} vendmirror_intercept_list_t;

struct staticipsession {
    char *key;
    char *rangestr;
    intercept_common_t common;
    uint32_t cin;
    uint32_t nextseqno;
    uint32_t references;
    UT_hash_handle hh;
};

/* A default username that may appear in RADIUS packets that should not
 * be treated as an actual user. Some ISPs will use CSID as user identity
 * instead and configure their CPEs to send a "default" username in RADIUS
 * when joining the network -- if the ISP can provide the defaults, we
 * can tell the collectors to not bother trying to track the sessions for
 * those "users".
 */
typedef struct default_radius_user {
    char *name;     /**< The default username */
    int namelen;    /**< The length of the username, in bytes */

    uint8_t awaitingconfirm;
    UT_hash_handle hh;
} default_radius_user_t;

void free_all_ipintercepts(ipintercept_t **interceptlist);
void free_all_voipintercepts(voipintercept_t **vintercepts);
void free_all_emailintercepts(emailintercept_t **mailintercepts);
void free_all_rtpstreams(rtpstreaminf_t **streams);
void free_all_ipsessions(ipsession_t **sessions);
void free_all_emailsessions(emailsession_t **sessions);
void free_all_vendmirror_intercepts(vendmirror_intercept_list_t **mirror_intercepts);
void free_all_staticipsessions(staticipsession_t **statintercepts);

void free_voip_cinmap(voipcinmap_t *cins);
void free_single_ipintercept(ipintercept_t *cept);
void free_single_voipintercept(voipintercept_t *v);
void free_single_emailintercept(emailintercept_t *m);
void free_single_ipsession(ipsession_t *sess);
void free_single_emailsession(emailsession_t *sess);
void free_single_rtpstream(rtpstreaminf_t *rtp);
void free_single_vendmirror_intercept(vendmirror_intercept_t *mirror);
void free_single_staticipsession(staticipsession_t *statint);
void free_single_staticiprange(static_ipranges_t *ipr);

sipregister_t *create_sipregister(voipintercept_t *vint, char *callid,
        uint32_t cin);

emailsession_t *create_emailsession(emailintercept_t *mailint, char *sessionid,
        uint32_t cin);

rtpstreaminf_t *create_rtpstream(voipintercept_t *vint, uint32_t cin);
rtpstreaminf_t *deep_copy_rtpstream(rtpstreaminf_t *rtp);

ipsession_t *create_ipsession(ipintercept_t *ipint, uint32_t cin,
        int ipfamily, struct sockaddr *assignedip, uint8_t prefixlen);

vendmirror_intercept_t *create_vendmirror_intercept(ipintercept_t *ipint);

staticipsession_t *create_staticipsession(ipintercept_t *ipint, char *rangestr,
        uint32_t cin);

int are_sip_identities_same(openli_sip_identity_t *a,
        openli_sip_identity_t *b);

void clear_user_intercept_list(user_intercept_list_t *ulist);
int remove_intercept_from_user_intercept_list(user_intercept_list_t **ulist,
        ipintercept_t *ipint);
int add_intercept_to_user_intercept_list(user_intercept_list_t **ulist,
        ipintercept_t *ipint);

const char *get_access_type_string(internet_access_method_t method);
const char *get_radius_ident_string(uint32_t radoptions);
internet_access_method_t map_access_type_string(char *confstr);
uint32_t map_radius_ident_string(char *confstr);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
