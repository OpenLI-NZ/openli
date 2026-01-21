/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
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

#ifndef OPENLI_PROVISIONER_H_
#define OPENLI_PROVISIONER_H_

#include "config.h"

#include <libtrace/linked_list.h>
#include <uthash.h>
#include <microhttpd.h>

#ifdef HAVE_SQLCIPHER
#include <sqlcipher/sqlite3.h>
#endif

#include "netcomms.h"
#include "util.h"
#include "openli_tls.h"

#define DEFAULT_DIGEST_HASH_KEY_LOCATION "/etc/openli/digesthash/private.pem"

#define DEFAULT_INTERCEPT_CONFIG_FILE "/etc/openli/running-intercept-config.yaml"

#define DEFAULT_ENCPASSFILE_LOCATION "/etc/openli/.intercept-encrypt"

#ifndef MHD_SOCKET_DEFINED
typedef int MHD_socket;
#define MHD_SOCKET_DEFINED
#endif

typedef struct prov_client prov_client_t;
typedef struct prov_intercept_data prov_intercept_data_t;

/** Describes an OpenLI client component that has connected to this provisioner
 *  at least once before.
 */
typedef struct known_client {
    /** If the client is a mediator, this field contains their mediator ID */
    uint32_t medid;

    const char *colname;

    /** Set to TARGET_COLLECTOR if this client was a collector,
     *  TARGET_MEDIATOR if it was a mediator.
     */
    uint8_t type;

    /** The IP address that the client used to connect to the provisioner */
    const char *ipaddress;

    /** The timestamp of when this client was first seen by the provisioner */
    time_t firstseen;

    /** The timestamp of when this client was most recently seen by the
     *  provisioner (approximately)
     */
    time_t lastseen;

    /** The configuration for the client component in JSON format */
    const char *jsonconfig;
} known_client_t;

/** Describes a single X2/X3 listening socket that is available on a collector
 */
typedef struct x2x3_listener {
    char *ipaddr;
    char *port;
    time_t lastseen;
} x2x3_listener_t;

/** Describes a single UDP sink that is available on a collector
 */
typedef struct col_udp_sink {
    char *ipaddr;
    char *port;
    char *identifier;
    time_t lastseen;
} collector_udp_sink_t;

/** Represents an event that has been added to the epoll event set */
typedef struct prov_epoll_ev {
    /** The event type -- one of the PROV_EPOLL_* values listed below */
    int fdtype;

    /** The file descriptor that is being polled by epoll */
    int fd;

    /** A reference to the client that the fd belongs to (only appropriate
     *  for some event types).
     */
    prov_client_t *client;

    /** A reference to the intercept that this fd belongs to (only used for
     *  some event types)
     */
    prov_intercept_data_t *cept;
} prov_epoll_ev_t;


/** Types of sockets that may trigger an epoll event */
enum {
    /** An incoming connection from a collector */
    PROV_EPOLL_COLL_CONN,
    /** An incoming connection from a mediator */
    PROV_EPOLL_MEDIATE_CONN,
    /** An incoming connection from an updater */
    PROV_EPOLL_UPDATE_CONN,

    /** Communication either to or from an updater */
    PROV_EPOLL_UPDATE,
    /** Communication either to or from a mediator */
    PROV_EPOLL_MEDIATOR,
    /** Communication either to or from a collector */
    PROV_EPOLL_COLLECTOR,

    /** Internal tick timer, used to trigger checks for halting or config
     *  reloads. */
    PROV_EPOLL_MAIN_TIMER,

    /** Authentication timeout for a client has expired */
    PROV_EPOLL_FD_TIMER,

    /** A signal has been received */
    PROV_EPOLL_SIGNAL,

    /** A pending SSL handshake from a mediator has progressed */
    PROV_EPOLL_MEDIATOR_HANDSHAKE,
    /** A pending SSL handshake from a collector has progressed */
    PROV_EPOLL_COLLECTOR_HANDSHAKE,

    /** Idle timeout for a client has expired */
    PROV_EPOLL_FD_IDLETIMER,

    /** Timer to fire when a delayed intercept begins */
    PROV_EPOLL_INTERCEPT_START,

    /** Timer to fire when an intercept is scheduled to cease */
    PROV_EPOLL_INTERCEPT_HALT,

    /** Timer to periodically update the last_seen field in the client
     *  database for all connected clients */
    PROV_EPOLL_CLIENTDB_TIMER,
};

/** A LIID->agency mapping, used to ensure mediators route the intercept
 *  traffic to the correct LEA.
 */
typedef struct liid_hash {
    /** The identifier for the agency */
    char *agency;
    /** The LIID for the intercept */
    char *liid;

    /** Whether the LIID is ascii-text or binary octets */
    openli_liid_format_t liid_format;

    /** The encryption method to use if/when encrypting intercept payload */
    payload_encryption_method_t encryptmethod;

    /** The encryption key to use if/when encrypting intercept payload */
    uint8_t encryptkey[OPENLI_MAX_ENCRYPTKEY_LEN];

    size_t encryptkey_len;

    /** Flag to indicate if any of the configuration in this mapping has
     *  changed and therefore needs to be announced to the mediators
     */
    uint8_t need_announce;

    UT_hash_handle hh;
} liid_hash_t;

/** An LEA that this provisioner knows about */
typedef struct prov_agency {
    /** The agency details */
    liagency_t *ag;

    /** A flag indicating whether the agency needs to be re-announced to
     *  all mediators (i.e. after a config change) */
    uint8_t announcereq;

    UT_hash_handle hh;
} prov_agency_t;

typedef struct prov_sock_state prov_sock_state_t;

/** State for a client (either collector or mediator) that has connected
 *  to the provisioner.
 */
struct prov_client {

    char *identifier;

    char *ipaddress;

    int clientrole;

    /** Epoll event for the main communication socket */
    prov_epoll_ev_t *commev;

    /** Epoll event for the authentication timer */
    prov_epoll_ev_t *authev;

    /** Epoll event for the idle timer */
    prov_epoll_ev_t *idletimer;

    /** Socket state for the main communication socket */
    prov_sock_state_t *state;

    /** SSL handle for the communication socket, if using TLS */
    SSL *ssl;

    /** Flag to indicate whether our last SSL handshake failed */
    uint8_t lastsslerror;

    /** Flag to indicate whether our last connection failed for a non-SSL
     *  reason */
    uint8_t lastothererror;

    UT_hash_handle hh;
};

/* Describes a collector that is being served by the provisioner */
typedef struct prov_collector {
    /** Unique identifier for the collector */
    char *identifier;

    /** The most recent known configuration for the collector, in JSON
     *  format.
     */
    char *jsonconfig;

    /** Common "client" state */
    prov_client_t *client;

    UT_hash_handle hh;
} prov_collector_t;

/* Describes a mediator that is being served by the provisioner */
typedef struct prov_mediator {

    /** Unique identifier for the mediator */
    uint32_t mediatorid;
    /** Common "client" state */
    prov_client_t *client;

    /** The IP address and port that the mediator is listening on for
     *  connections from collectors */
    openli_mediator_t *details;

    UT_hash_handle hh;
} prov_mediator_t;

typedef struct udp_sink_intercept_mapping {
    char *udpsink;
    char *liid;

    UT_hash_handle hh;
} udp_sink_intercept_mapping_t;

typedef struct prov_intercept_conf {
    /** The set of known RADIUS servers that will be provided to collectors */
    coreserver_t *radiusservers;
    /** The set of known GTP servers that will be provided to collectors */
    coreserver_t *gtpservers;
    /** The set of known SIP servers that will be provided to collectors */
    coreserver_t *sipservers;
    /** The set of known SMTP servers that will be provided to collectors */
    coreserver_t *smtpservers;
    /** The set of known IMAP servers that will be provided to collectors */
    coreserver_t *imapservers;
    /** The set of known POP3 servers that will be provided to collectors */
    coreserver_t *pop3servers;
    /** The set of VOIP intercepts that we are currently running */
    voipintercept_t *voipintercepts;
    /** The set of IP intercepts that we are currently running */
    ipintercept_t *ipintercepts;
    /** The set of IP intercepts that we are currently running */
    emailintercept_t *emailintercepts;
    /** The set of LEAs that are potential intercept recipients */
    prov_agency_t *leas;
    /** A map of LIIDs to their destination LEAs */
    liid_hash_t *liid_map;
    /** A set of default RADIUS user names */
    default_radius_user_t *defradusers;

    /** A map that ensures each UDP sink only is responsible for a single
     *  intercept.
     */
    udp_sink_intercept_mapping_t *udp_sink_intercept_mappings;

    /** The default approach for delivering compressed email CCs to the
     *  agencies (i.e. in their original compressed form, or decompressed).
     */
    uint8_t default_email_deliver_compress;

    int destroy_pending;

    uint8_t was_encrypted;
    /** A mutex to protect the intercept config from race conditions */
    pthread_mutex_t safelock;
} prov_intercept_conf_t;

typedef struct mediator_address {
    char *ipportstr;
    uint32_t medid;

    UT_hash_handle hh;
} mediator_address_t;

struct prov_intercept_data {
    prov_epoll_ev_t *start_timer;
    prov_epoll_ev_t *end_timer;

    openli_intercept_types_t intercept_type;
    void *intercept_ref;

    uint8_t start_hi1_sent;
    uint8_t end_hi1_sent;
};

/** Global state for the provisioner instance */
typedef struct prov_state {

    /** Path to the configuration file */
    char *conffile;

    /** Path to the file containing the passphrase for any encrypted intercept
     *  configuration */
    const char *encpassfile;

    uint8_t encrypt_intercept_config;

    /** The IP address to listen on for incoming collector connections */
    char *listenaddr;
    /** The port to listen on for incoming collector connections */
    char *listenport;
    /** The IP address to listen on for incoming mediator connections */
    char *mediateaddr;
    /** The port to listen on for incoming mediator connections */
    char *mediateport;
    /** The IP address to listen on for incoming updater connections */
    char *pushaddr;
    /** The port to listen on for incoming updater connections */
    char *pushport;
    char *interceptconffile;

    /** The file descriptor that is used for polling using epoll */
    int epoll_fd;

    prov_client_t *pendingclients;

    mediator_address_t *knownmeds;

    /** The set of mediators that we are managing, keyed by mediator ID */
    prov_mediator_t *mediators;

    /** The set of collectors that we are managing */
    prov_collector_t *collectors;

    /** Epoll event for the collector connection socket */
    prov_epoll_ev_t *clientfd;
    /** Epoll event for the updater connection socket */
    prov_epoll_ev_t *updatefd;
    /** Epoll event for the mediator connection socket */
    prov_epoll_ev_t *mediatorfd;
    /** Epoll event for the "check if halted" timer */
    prov_epoll_ev_t *timerfd;
    /** Epoll event for the incoming signal socket */
    prov_epoll_ev_t *signalfd;

    prov_intercept_conf_t interceptconf;

    char *key_pem;
    char *cert_pem;
    struct MHD_Daemon *updatedaemon;
    MHD_socket updatesockfd;

    uint8_t restauthenabled;
    char *restauthdbfile;
    char *restauthkey;
    void *authdb;

    uint8_t clientdbenabled;
    char *clientdbfile;
    char *clientdbkey;
    void *clientdb;

    /** The location of the private key to use when signing digest hash
     *  integrity checks */
    char *integrity_sign_private_key_location;
    /** The private key to use when signing digest hash integrity checks */
    EVP_PKEY *integrity_sign_private_key;

    /** context for signing digests, used if the mediator requires
     *  us to sign integrity checks */
    EVP_PKEY_CTX *sign_ctx;

    /** A flag indicating whether collectors should ignore RTP comfort noise
     *  packets when intercepting voice traffic.
     */
    int ignorertpcomfort;

    /** The SSL configuration, including the SSL context pointer */
    openli_ssl_config_t sslconf;

} provision_state_t;

/** Socket state information for a single client */
struct prov_sock_state {
    /** The IP address and port of the client, used for identification */
    char *ipaddr;

    /** A flag indicating whether we should log errors that occur when
     *  communicating with this client.
     */
    uint8_t log_allowed;

    /** Buffer for storing messages that have been received from the client */
    net_buffer_t *incoming;
    /** Buffer for storing messages that are to be sent to the client */
    net_buffer_t *outgoing;

    void *parent;

    /** Set to 1 if the client has authenticated, 0 otherwise */
    uint8_t trusted;

    /** Set to 1 if the client has been disconnected, 0 otherwise */
    uint8_t halted;

    /** The type of client, e.g. either collector or mediator */
    int clientrole;

};

/* Implemented in provisioner.c, but included here to be available
 * inside hup_reload.c
 */
int init_prov_state(provision_state_t *state, char *configfile,
        const char *encpassfile);
void clear_prov_state(provision_state_t *state);
void free_all_mediators(int epollfd, prov_mediator_t **mediators,
        mediator_address_t **knownmeds);
void stop_all_collectors(int epollfd, prov_collector_t **collectors);
int start_main_listener(provision_state_t *state);
int start_mediator_listener(provision_state_t *state);
void start_mhd_daemon(provision_state_t *state);
void clear_intercept_state(prov_intercept_conf_t *conf);
void init_intercept_config(prov_intercept_conf_t *conf);
int map_intercepts_to_leas(prov_intercept_conf_t *conf);

/* Implemented in configparser_provisioner.c */
size_t read_encryption_password_file(const char *encpassfile, uint8_t *space);

/* Implemented in configwriter.c */
int emit_intercept_config(char *configfile, const char *encpassfile,
        prov_intercept_conf_t *conf);

/* Implemented in integrity_sign.c */
int load_integrity_signing_privatekey(provision_state_t *state);
int prov_handle_ics_signing_request(provision_state_t *state,
        uint8_t *msgbody, uint16_t msglen, prov_sock_state_t *cs,
        prov_epoll_ev_t *pev );

/* Implemented in clientupdates.c */
int compare_sip_targets(provision_state_t *currstate,
        voipintercept_t *existing, voipintercept_t *reload);
int compare_email_targets(provision_state_t *currstate,
        emailintercept_t *existing, emailintercept_t *reload);
int announce_default_radius_username(provision_state_t *state,
        default_radius_user_t *raduser);
int withdraw_default_radius_username(provision_state_t *state,
        default_radius_user_t *raduser);
int announce_lea_to_mediators(provision_state_t *state,
        prov_agency_t *lea);
int withdraw_agency_from_mediators(provision_state_t *state,
        prov_agency_t *lea);
void add_new_staticip_range(provision_state_t *state,
        ipintercept_t *ipint, static_ipranges_t *ipr);
void modify_existing_staticip_range(provision_state_t *state,
        ipintercept_t *ipint, static_ipranges_t *ipr);
void remove_existing_staticip_range(provision_state_t *state,
        ipintercept_t *ipint, static_ipranges_t *ipr);
void add_new_intercept_udp_sink(provision_state_t *state,
        intercept_common_t *common, intercept_udp_sink_t *sink);
void modify_intercept_udp_sink(provision_state_t *state,
        intercept_common_t *common, intercept_udp_sink_t *sink);
void remove_intercept_udp_sink(provision_state_t *state,
        intercept_common_t *common, intercept_udp_sink_t *sink);
int halt_existing_intercept(provision_state_t *state,
        void *cept, openli_proto_msgtype_t wdtype);
int modify_existing_intercept_options(provision_state_t *state,
        void *cept, openli_proto_msgtype_t modtype);
int disconnect_mediators_from_collectors(provision_state_t *state);
int remove_liid_mapping(provision_state_t *state,
        char *liid, int liid_len, int droppedmeds);
int announce_liidmapping_to_mediators(provision_state_t *state,
        liid_hash_t *liidmap);
int announce_coreserver_change(provision_state_t *state,
        coreserver_t *cs, uint8_t isnew);
int announce_email_target_change(provision_state_t *state,
        email_target_t *tgt, emailintercept_t *mailint, uint8_t isnew);
int announce_all_email_targets(provision_state_t *state,
        emailintercept_t *mailint);
int remove_all_email_targets(provision_state_t *state,
        emailintercept_t *mailint);
int announce_sip_target_change(provision_state_t *state,
        openli_sip_identity_t *sipid, voipintercept_t *vint, uint8_t isnew);
int announce_all_sip_targets(provision_state_t *state, voipintercept_t *vint);
int remove_all_sip_targets(provision_state_t *state, voipintercept_t *vint);
int announce_single_intercept(provision_state_t *state,
        void *cept, int (*sendfunc)(net_buffer_t *, void *));
liid_hash_t *add_liid_mapping(prov_intercept_conf_t *conf,
        intercept_common_t *common);
int announce_all_updated_liidmappings_to_mediators(provision_state_t *state);
void clear_liid_announce_flags(prov_intercept_conf_t *conf);
int announce_hi1_notification_to_mediators(provision_state_t *state,
        intercept_common_t *intcomm, char *target_id, hi1_notify_t not_type);
int announce_latest_default_email_decompress(provision_state_t *state);
void apply_intercept_encryption_settings(prov_intercept_conf_t *conf,
        intercept_common_t *common);
void update_inherited_encryption_settings(provision_state_t *state,
        liagency_t *agency);
int enable_epoll_write(provision_state_t *state, prov_epoll_ev_t *pev);
void update_intercept_timeformats(provision_state_t *state,
        const char *agencyid, openli_timestamp_encoding_fmt_t newfmt);
int announce_configuration_update_to_collector(provision_state_t *state,
        prov_collector_t *col, const char *newconfig);

/* Implemented in hup_reload.c */
int reload_provisioner_config(provision_state_t *state);
int check_for_duplicate_xids(prov_intercept_conf_t *intconf,
        size_t xid_count, uuid_t *xids, char *xid_liid);
void remove_udp_sink_mapping(provision_state_t *state,
        char *liid, char *sinkid);
int add_udp_sink_mapping(provision_state_t *state, char *liid, char *sinkkey);

/* Implemented in clientdb.c */
int init_clientdb(provision_state_t *state);
void close_clientdb(provision_state_t *state);
int update_mediator_client_row(provision_state_t *state, prov_mediator_t *med);
int update_collector_client_row(provision_state_t *state,
        prov_collector_t *col);
int update_udp_sink_row(provision_state_t *state, prov_collector_t *col,
       char *listenaddr, char *listenport, char *identifier,
       uint64_t timestamp);
int update_x2x3_listener_row(provision_state_t *state, prov_collector_t *col,
       char *listenaddr, char *listenport, uint64_t timestamp);
void update_all_client_rows(provision_state_t *state);
known_client_t *fetch_all_collector_clients(provision_state_t *state,
        size_t *clientcount);
known_client_t *fetch_all_mediator_clients(provision_state_t *state,
        size_t *clientcount);
x2x3_listener_t *fetch_x2x3_listeners_for_collector(provision_state_t *state,
        size_t *listenercount, const char *collectorid);
collector_udp_sink_t *fetch_udp_sinks_for_collector(provision_state_t *state,
        size_t *sinkcount, const char *collectorid);
int remove_collector_from_clientdb(provision_state_t *state, const char *idstr);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
