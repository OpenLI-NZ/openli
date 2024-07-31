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
#include <Judy.h>

#define OPENLI_VENDOR_MIRROR_NONE (0xffffffff)

#define INTERCEPT_IS_ACTIVE(cept, now) \
    (cept->common.tostart_time <= now.tv_sec && ( \
        cept->common.toend_time == 0 || cept->common.toend_time > now.tv_sec))

typedef enum {
    OPENLI_INTERCEPT_TYPE_UNKNOWN = 0,
    OPENLI_INTERCEPT_TYPE_IP = 1,
    OPENLI_INTERCEPT_TYPE_VOIP = 2,
    OPENLI_INTERCEPT_TYPE_EMAIL = 3,
    OPENLI_INTERCEPT_TYPE_EOL,
} openli_intercept_types_t;

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
    OPENLI_MOBILE_IDENTIFIER_NOT_SPECIFIED = 0,
    OPENLI_MOBILE_IDENTIFIER_MSISDN = 1,
    OPENLI_MOBILE_IDENTIFIER_IMSI = 2,
    OPENLI_MOBILE_IDENTIFIER_IMEI = 3,
} openli_mobile_identifier_t;

typedef enum {
    OPENLI_PAYLOAD_ENCRYPTION_NOT_SPECIFIED = 0,
    OPENLI_PAYLOAD_ENCRYPTION_NONE = 1,
    OPENLI_PAYLOAD_ENCRYPTION_NATIONAL = 2,
    OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC = 3,
    OPENLI_PAYLOAD_ENCRYPTION_AES_256_CBC = 4,
    OPENLI_PAYLOAD_ENCRYPTION_BLOWFISH_192_CBC = 5,
    OPENLI_PAYLOAD_ENCRYPTION_BLOWFISH_256_CBC = 6,
    OPENLI_PAYLOAD_ENCRYPTION_THREEDES_CBC = 7,
} payload_encryption_method_t;

typedef enum {
    OPENLI_VOIPINT_OPTION_IGNORE_COMFORT = 0,
} voipintercept_options_t;

typedef enum {
    OPENLI_IPINT_OPTION_RADIUS_IDENT_CSID = 0,
    OPENLI_IPINT_OPTION_RADIUS_IDENT_USER = 1,
} ipintercept_options_t;

typedef enum {
    OPENLI_INTERCEPT_OUTPUTS_ALL = 0,
    OPENLI_INTERCEPT_OUTPUTS_IRIONLY = 1,
    OPENLI_INTERCEPT_OUTPUTS_CCONLY = 2,
} intercept_outputs_t;

enum {
    OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS = 0,
    OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED = 1,
    OPENLI_EMAILINT_DELIVER_COMPRESSED_NOT_SET = 254,
    OPENLI_EMAILINT_DELIVER_COMPRESSED_DEFAULT = 255,
};

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
    time_t tostart_time;
    time_t toend_time;
    intercept_outputs_t tomediate;
    payload_encryption_method_t encrypt;
    char *encryptkey;

    /** A pointer to use for storing "local" data against an instance of
     *  an intercept, i.e. the provisioner might want to associate
     *  certain data against each intercept that is not required by the
     *  collector or mediator.
     */
    void *local;
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
    char *target_info;
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

    openli_mobile_identifier_t mobileident;
    uint8_t awaitingconfirm;
    uint32_t options;
    UT_hash_handle hh_liid;
    UT_hash_handle hh_user;
} ipintercept_t;

typedef struct email_target {
    char *address;
    char *sha512;
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
    uint8_t delivercompressed;
    UT_hash_handle hh_liid;

} emailintercept_t;

typedef struct email_intercept_ref {
    emailintercept_t *em;
    UT_hash_handle hh;
} email_intercept_ref_t;

typedef struct email_address_set {
    char *emailaddr;
    email_intercept_ref_t *intlist;
    UT_hash_handle hh_addr;
} email_address_set_t;

typedef struct email_target_set {
    char *sha512;
    char *origaddress;
    email_intercept_ref_t *intlist;
    UT_hash_handle hh_sha;
    UT_hash_handle hh_plain;
} email_target_set_t;

typedef struct emailinterceptlist {
    email_address_set_t *addresses;
    email_target_set_t *targets;
    email_target_set_t *targets_plain;
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
    uint32_t server_octets;
    uint32_t client_octets;
    uint64_t login_time;
    uint8_t login_sent;
    time_t event_time;

    char *ingest_target_id;
    uint8_t ingest_direction;
    email_participant_t sender;
    email_participant_t *participants;

    uint8_t protocol;
    uint8_t currstate;
    uint8_t mask_credentials;
    uint8_t compressed;
    void *timeout_ev;
    uint8_t handle_compress;

    void *proto_state;
    void **held_captured;
    uint32_t held_captured_size;
    uint32_t next_expected_captured;
    uint8_t sender_validated_etsivalue;

    Pvoid_t ccs_sent;
    Pvoid_t iris_sent;
    int iricount;
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

    uint8_t inviter[16];

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
void free_all_vendmirror_intercepts(vendmirror_intercept_list_t **mirror_intercepts);
void free_all_staticipsessions(staticipsession_t **statintercepts);
void free_all_staticipranges(static_ipranges_t **ipranges);

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
void free_single_email_target(email_target_t *tgt);

int update_modified_intercept_common(intercept_common_t *current,
        intercept_common_t *update, openli_intercept_types_t cepttype,
        int *changed);

/* Create a comma-separated string containing all of the SIP target IDs
 * for a VoIP intercept.
 */
char *list_sip_targets(voipintercept_t *v, int maxchars);

/* Add a provided SIP identity to the targets list for a VoIP intercept.
 */
void add_new_sip_target_to_list(voipintercept_t *vint,
        openli_sip_identity_t *sipid);

/* Disables the provided SIP identity for a VoIP intercept. */
void disable_sip_target_from_list(voipintercept_t *vint,
        openli_sip_identity_t *sipid);

/* Disables any VoIP intercepts that were not confirmed by the provisioner
 * since we last had a reliable connection back to it.
 *
 * Takes two function callbacks as arguments: one function to be called
 * for each unconfirmed intercept (percept), and one to be called for each
 * unconfirmed target (whose intercept was confirmed) (pertgt).
 *
 * The percept_arg and pertgt_arg parameters allow the user to pass
 * their own context data into the callback functions, if required.
 */
void disable_unconfirmed_voip_intercepts(voipintercept_t **voipintercepts,
        void (*percept)(voipintercept_t *, void *),
        void *percept_arg,
        void (*pertgt)(openli_sip_identity_t *, voipintercept_t *vint, void *),
        void *pertgt_arg);

/* Mark all VoIP intercepts (and their targets) as unconfirmed, pending
 * a re-announcement from the provisioner. You should call this on a
 * set of known VoIP intercepts whenever the connection to the provisioner
 * is lost.
 */
void flag_voip_intercepts_as_unconfirmed(voipintercept_t **voipintercepts);

/* Create a comma-separated string containing all of the target addresses
 * for an email intercept.
 */
char *list_email_targets(emailintercept_t *m, int maxchars);

sipregister_t *create_sipregister(voipintercept_t *vint, char *callid,
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

void clear_email_user_intercept_list(email_user_intercept_list_t *ulist);
int remove_intercept_from_email_user_intercept_list(
        email_user_intercept_list_t *ulist, emailintercept_t *em,
        email_target_t *tgt);
int add_intercept_to_email_user_intercept_list(
        email_user_intercept_list_t *ulist, emailintercept_t *em,
        email_target_t *tgt);

int generate_ipint_userkey(ipintercept_t *ipint, char *space,
        size_t spacelen);

const char *get_mobile_identifier_string(openli_mobile_identifier_t idtype);
const char *get_access_type_string(internet_access_method_t method);
const char *get_radius_ident_string(uint32_t radoptions);
internet_access_method_t map_access_type_string(char *confstr);
uint32_t map_radius_ident_string(char *confstr);
payload_encryption_method_t map_encrypt_method_string(char *encstr);
uint8_t map_email_decompress_option_string(char *decstr);
openli_mobile_identifier_t map_mobile_ident_string(char *idstr);

void intercept_mediation_mode_as_string(intercept_outputs_t mode,
        char *space, int spacelen);
void intercept_encryption_mode_as_string(payload_encryption_method_t method,
        char *space, int spacelen);
void email_decompress_option_as_string(uint8_t opt, char *space, int spacelen);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
