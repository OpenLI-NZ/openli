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

#ifndef OPENLI_NETCOMMS_H_
#define OPENLI_NETCOMMS_H_

#include "config.h"
#include <inttypes.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>

#ifdef RMQC_HEADER_SUBDIR
#include <rabbitmq-c/amqp.h>
#include <rabbitmq-c/tcp_socket.h>
#else
#include <amqp.h>
#include <amqp_tcp_socket.h>
#endif

#define NETBUF_ALLOC_SIZE (10 * 1024 * 1024)

#define OPENLI_PROTO_MAGIC 0x5c4c6c5c
#define OPENLI_COLLECTOR_MAGIC 0x00180014202042a8
#define OPENLI_MEDIATOR_MAGIC 0x01153200d6f12905

#define NETBUF_SPACE_REM(nbuf) \
    ((nbuf->alloced >= (nbuf->appendptr - nbuf->buf)) ? \
        (unsigned int)(nbuf->alloced - (nbuf->appendptr - nbuf->buf)) : \
        (unsigned int) 0)

#define NETBUF_FRONT_FREE(nbuf) \
    ((nbuf->actptr >= nbuf->buf) ? \
        (unsigned int)(nbuf->actptr - nbuf->buf) : \
        (unsigned int) 0)

#define NETBUF_CONTENT_SIZE(nbuf) \
    ((nbuf->appendptr >= nbuf->actptr) ? \
        (unsigned int)(nbuf->appendptr - nbuf->actptr) : \
        (unsigned int) 0)

#include "intercept.h"
#include "agency.h"
#include "coreserver.h"

typedef struct ii_header {
    uint32_t magic;
    uint16_t bodylen;
    uint16_t intercepttype;
    uint64_t internalid;
} PACKED ii_header_t;

struct fwd_hello_body {
    int threadid;
    uint8_t using_rmq;
} PACKED;

typedef struct openli_forwarder_hello {
    ii_header_t ii_hdr;
    struct fwd_hello_body fwd_hello_body;
} openli_forwarder_hello_t;

typedef struct openli_mediator {
    uint32_t mediatorid;
    char *ipstr;
    char *portstr;
} openli_mediator_t;

struct ics_sign_request_message {
    char *ics_key;
    char *requestedby;
    uint32_t requestedby_fwd;
    int64_t seqno;
    unsigned char *digest;
    unsigned int digest_len;
};

struct ics_sign_response_message {
    char *ics_key;
    char *requestedby;
    uint32_t requestedby_fwd;
    int64_t seqno;
    unsigned char *signature;
    uint32_t sign_len;
};

typedef enum {
    NETBUF_RECV,
    NETBUF_SEND,
} net_buffer_type_t;

typedef enum {
    OPENLI_PROTO_SEND_ERROR = -7,
    OPENLI_PROTO_INVALID_MESSAGE = -6,
    OPENLI_PROTO_RECV_ERROR = -5,
    OPENLI_PROTO_PEER_DISCONNECTED = -4,
    OPENLI_PROTO_BUFFER_TOO_FULL = -3,
    OPENLI_PROTO_WRONG_BUFFER_TYPE = -2,
    OPENLI_PROTO_NULL_BUFFER = -1,
    OPENLI_PROTO_DISCONNECT,
    OPENLI_PROTO_NO_MESSAGE,
    OPENLI_PROTO_START_IPINTERCEPT,
    OPENLI_PROTO_HALT_IPINTERCEPT,
    OPENLI_PROTO_START_VOIPINTERCEPT,
    OPENLI_PROTO_HALT_VOIPINTERCEPT,
    OPENLI_PROTO_ANNOUNCE_MEDIATOR,
    OPENLI_PROTO_WITHDRAW_MEDIATOR,
    OPENLI_PROTO_ANNOUNCE_LEA,
    OPENLI_PROTO_WITHDRAW_LEA,
    OPENLI_PROTO_MEDIATE_INTERCEPT,
    OPENLI_PROTO_CEASE_MEDIATION,
    OPENLI_PROTO_COLLECTOR_AUTH,
    OPENLI_PROTO_MEDIATOR_AUTH,
    OPENLI_PROTO_DISCONNECT_MEDIATORS,
    OPENLI_PROTO_NOMORE_INTERCEPTS,
    OPENLI_PROTO_ETSI_CC,
    OPENLI_PROTO_ETSI_IRI,
    OPENLI_PROTO_ANNOUNCE_CORESERVER,
    OPENLI_PROTO_WITHDRAW_CORESERVER,
    OPENLI_PROTO_ANNOUNCE_SIP_TARGET,
    OPENLI_PROTO_WITHDRAW_SIP_TARGET,
    OPENLI_PROTO_ADD_STATICIPS,
    OPENLI_PROTO_REMOVE_STATICIPS,
    OPENLI_PROTO_MODIFY_VOIPINTERCEPT,
    OPENLI_PROTO_CONFIG_RELOADED,
    OPENLI_PROTO_MODIFY_IPINTERCEPT,
    OPENLI_PROTO_MODIFY_STATICIPS,
    OPENLI_PROTO_RAWIP_SYNC,
    OPENLI_PROTO_ANNOUNCE_DEFAULT_RADIUS,
    OPENLI_PROTO_WITHDRAW_DEFAULT_RADIUS,
    OPENLI_PROTO_HEARTBEAT,
    OPENLI_PROTO_SSL_REQUIRED,
    OPENLI_PROTO_HI1_NOTIFICATION,
    OPENLI_PROTO_START_EMAILINTERCEPT,
    OPENLI_PROTO_HALT_EMAILINTERCEPT,
    OPENLI_PROTO_MODIFY_EMAILINTERCEPT,
    OPENLI_PROTO_ANNOUNCE_EMAIL_TARGET,
    OPENLI_PROTO_WITHDRAW_EMAIL_TARGET,
    OPENLI_PROTO_ANNOUNCE_DEFAULT_EMAIL_COMPRESSION,
    OPENLI_PROTO_RAWIP_CC,
    OPENLI_PROTO_RAWIP_IRI,
    OPENLI_PROTO_COLLECTOR_FORWARDER_HELLO,
    OPENLI_PROTO_X2X3_LISTENER,
    OPENLI_PROTO_INTEGRITY_SIGNATURE_REQUEST,
    OPENLI_PROTO_INTEGRITY_SIGNATURE_RESPONSE,
    OPENLI_PROTO_ADD_UDPSINK,
    OPENLI_PROTO_MODIFY_UDPSINK,
    OPENLI_PROTO_REMOVE_UDPSINK,
} openli_proto_msgtype_t;

typedef struct net_buffer {
    int fd;
    char *buf;
    char *appendptr;
    char *actptr;
    int alloced;
    net_buffer_type_t buftype;
    SSL *ssl;
    int unacked;
    uint64_t last_tag;
    amqp_channel_t rmq_channel;
} net_buffer_t;

typedef enum {
    OPENLI_PROTO_FIELD_MEDIATORID,
    OPENLI_PROTO_FIELD_MEDIATORIP,
    OPENLI_PROTO_FIELD_MEDIATORPORT,
    OPENLI_PROTO_FIELD_USERNAME,
    OPENLI_PROTO_FIELD_SIPURI,
    OPENLI_PROTO_FIELD_LIID,
    OPENLI_PROTO_FIELD_AUTHCC,
    OPENLI_PROTO_FIELD_DELIVCC,
    OPENLI_PROTO_FIELD_INTERCEPTID,
    OPENLI_PROTO_FIELD_LEAID,
    OPENLI_PROTO_FIELD_HI2IP,
    OPENLI_PROTO_FIELD_HI2PORT,
    OPENLI_PROTO_FIELD_HI3IP,
    OPENLI_PROTO_FIELD_HI3PORT,
    OPENLI_PROTO_FIELD_CORESERVER_TYPE,
    OPENLI_PROTO_FIELD_CORESERVER_IP,
    OPENLI_PROTO_FIELD_CORESERVER_PORT,
    OPENLI_PROTO_FIELD_VENDMIRRORID,
    OPENLI_PROTO_FIELD_KAFREQ,
    OPENLI_PROTO_FIELD_KAWAIT,
    OPENLI_PROTO_FIELD_ACCESSTYPE,
    OPENLI_PROTO_FIELD_SIP_USER,
    OPENLI_PROTO_FIELD_SIP_REALM,
    OPENLI_PROTO_FIELD_STATICIP_RANGE,
    OPENLI_PROTO_FIELD_CIN,
    OPENLI_PROTO_FIELD_INTOPTIONS,
    OPENLI_PROTO_FIELD_HI1_NOTIFY_TYPE,
    OPENLI_PROTO_FIELD_SEQNO,
    OPENLI_PROTO_FIELD_TS_SEC,
    OPENLI_PROTO_FIELD_TS_USEC,
    OPENLI_PROTO_FIELD_INTERCEPT_START_TIME,
    OPENLI_PROTO_FIELD_INTERCEPT_END_TIME,
    OPENLI_PROTO_FIELD_EMAIL_TARGET,
    OPENLI_PROTO_FIELD_TOMEDIATE,
    OPENLI_PROTO_FIELD_PAYLOAD_ENCRYPTION,
    OPENLI_PROTO_FIELD_ENCRYPTION_KEY,
    OPENLI_PROTO_FIELD_DELIVER_COMPRESSED,
    OPENLI_PROTO_FIELD_MOBILEIDENT,
    OPENLI_PROTO_FIELD_CORESERVER_UPPER_PORT,
    OPENLI_PROTO_FIELD_CORESERVER_LOWER_PORT,
    OPENLI_PROTO_FIELD_LEACC,
    OPENLI_PROTO_FIELD_XID,
    OPENLI_PROTO_FIELD_INTEGRITY_HASH_METHOD,
    OPENLI_PROTO_FIELD_INTEGRITY_SIGNED_HASH_METHOD,
    OPENLI_PROTO_FIELD_INTEGRITY_HASH_TIMEOUT,
    OPENLI_PROTO_FIELD_INTEGRITY_HASH_PDULIMIT,
    OPENLI_PROTO_FIELD_INTEGRITY_SIGN_TIMEOUT,
    OPENLI_PROTO_FIELD_INTEGRITY_SIGN_HASHLIMIT,
    OPENLI_PROTO_FIELD_INTEGRITY_ENABLED,
    OPENLI_PROTO_FIELD_COMPONENT_NAME,
    OPENLI_PROTO_FIELD_DIGEST,
    OPENLI_PROTO_FIELD_LENGTH_BYTES,
    OPENLI_PROTO_FIELD_COLLECTORID,
    OPENLI_PROTO_FIELD_HANDOVER_RETRY,
    OPENLI_PROTO_FIELD_WINDOW_SIZE,
    OPENLI_PROTO_FIELD_TIMESTAMP_FORMAT,
    OPENLI_PROTO_FIELD_THREADID,
    OPENLI_PROTO_FIELD_LIID_FORMAT,
    OPENLI_PROTO_FIELD_UDP_SINK_IDENTIFIER,
    OPENLI_PROTO_FIELD_DIRECTION,
    OPENLI_PROTO_FIELD_UDP_ENCAPSULATION,
    OPENLI_PROTO_FIELD_ACL_IPADDR,
    OPENLI_PROTO_FIELD_ACL_PORT,
    OPENLI_PROTO_FIELD_UUID,
    OPENLI_PROTO_FIELD_JSON_CONFIGURATION,
} openli_proto_fieldtype_t;
/* XXX one day we may need to separate these field types into distinct
 * enums for each "message type" as there is only one byte available for
 * storing the field type in a field.
 *
 * But since we always know the context of the message type that we are
 * parsing, we can re-purpose each field type value to mean different fields
 * depending on whether we are parsing an LEA announcement vs an intercept vs
 * a core server etc...
 */

net_buffer_t *create_net_buffer(net_buffer_type_t buftype, int fd, SSL *ssl);
int fd_set_nonblock(int fd);
int fd_set_block(int fd);
void destroy_net_buffer(net_buffer_t *nb, amqp_connection_state_t amqp_state);

int construct_netcomm_protocol_header(ii_header_t *hdr, uint32_t contentlen,
        uint16_t msgtype, uint64_t internalid, uint32_t *hdrlen);

int push_default_email_compression_onto_net_buffer(net_buffer_t *nb,
        uint8_t defaultcompress);
int push_default_radius_onto_net_buffer(net_buffer_t *nb,
        default_radius_user_t *defuser);
int push_default_radius_withdraw_onto_net_buffer(net_buffer_t *nb,
        default_radius_user_t *defuser);
int push_mediator_onto_net_buffer(net_buffer_t *nb, openli_mediator_t *med);
int push_ics_signing_request_onto_net_buffer(net_buffer_t *nb,
        struct ics_sign_request_message *req);
int push_ics_signing_response_onto_net_buffer(net_buffer_t *nb,
        struct ics_sign_response_message *resp);
int push_mediator_withdraw_onto_net_buffer(net_buffer_t *nb,
        openli_mediator_t *med);
int push_ipintercept_onto_net_buffer(net_buffer_t *nb, void *ipint);
int push_voipintercept_onto_net_buffer(net_buffer_t *nb,
        void *vint);
int push_emailintercept_onto_net_buffer(net_buffer_t *nb,
        void *mailint);
int push_intercept_withdrawal_onto_net_buffer(net_buffer_t *nb,
        void *cept, openli_proto_msgtype_t wdtype);
int push_intercept_modify_onto_net_buffer(net_buffer_t *nb,
        void *cept, openli_proto_msgtype_t modtype);
int push_lea_onto_net_buffer(net_buffer_t *nb, liagency_t *lea);
int push_lea_withdrawal_onto_net_buffer(net_buffer_t *nb, liagency_t *lea);
int push_intercept_dest_onto_net_buffer(net_buffer_t *nb, char *liid,
        char *agencyid);
int push_auth_onto_net_buffer(net_buffer_t *nb, openli_proto_msgtype_t
        authtype, char *jsonconfig, char *uuidstr);
int push_udp_sink_onto_net_buffer(net_buffer_t *nb, char *addr,
        char *port, char *identifier, uint64_t ts);
int push_x2x3_listener_onto_net_buffer(net_buffer_t *nb, char *addr,
        char *port, uint64_t ts);
int push_liid_mapping_onto_net_buffer(net_buffer_t *nb, char *agency,
        char *liid, uint8_t *encryptkey, size_t encryptlen,
        payload_encryption_method_t method, openli_liid_format_t liidformat);
int push_cease_mediation_onto_net_buffer(net_buffer_t *nb, char *liid,
        int liid_len);
int push_disconnect_mediators_onto_net_buffer(net_buffer_t *nb);
int push_coreserver_onto_net_buffer(net_buffer_t *nb, coreserver_t *cs,
        uint8_t cstype);
int push_coreserver_withdraw_onto_net_buffer(net_buffer_t *nb, coreserver_t *cs,
        uint8_t cstype);
int push_sip_target_onto_net_buffer(net_buffer_t *nb,
        openli_sip_identity_t *sipid, voipintercept_t *vint);
int push_sip_target_withdrawal_onto_net_buffer(net_buffer_t *nb,
        openli_sip_identity_t *sipid, voipintercept_t *vint);
int push_nomore_intercepts(net_buffer_t *nb);
int push_ssl_required(net_buffer_t *nb);
int transmit_net_buffer(net_buffer_t *nb, openli_proto_msgtype_t *err);
int push_static_ipranges_removal_onto_net_buffer(net_buffer_t *nb,
        ipintercept_t *ipint, static_ipranges_t *ipr);
int push_static_ipranges_modify_onto_net_buffer(net_buffer_t *nb,
        ipintercept_t *ipint, static_ipranges_t *ipr);
int push_static_ipranges_onto_net_buffer(net_buffer_t *nb,
        ipintercept_t *ipint, static_ipranges_t *ipr);
int push_hi1_notification_onto_net_buffer(net_buffer_t *nb,
        hi1_notify_data_t *ndata);
int push_email_target_onto_net_buffer(net_buffer_t *nb,
        email_target_t *tgt, emailintercept_t *mailint);
int push_email_target_withdrawal_onto_net_buffer(net_buffer_t *nb,
        email_target_t *tgt, emailintercept_t *mailint);
int push_intercept_udp_sink_onto_net_buffer(net_buffer_t *nb,
        intercept_common_t *common, intercept_udp_sink_t *sink);
int push_modify_intercept_udp_sink_onto_net_buffer(net_buffer_t *nb,
        intercept_common_t *common, intercept_udp_sink_t *sink);
int push_remove_intercept_udp_sink_onto_net_buffer(net_buffer_t *nb,
        intercept_common_t *common, intercept_udp_sink_t *sink);

int transmit_forwarder_hello(int sockfd, SSL *ssl, int threadid,
        uint8_t using_rmq);

openli_proto_msgtype_t receive_RMQ_buffer(net_buffer_t *nb,
        amqp_connection_state_t amqp_state, uint8_t **msgbody,
        uint16_t *msglen, uint64_t *intid);
openli_proto_msgtype_t receive_net_buffer(net_buffer_t *nb, uint8_t **msgbody,
        uint16_t *msglen, uint64_t *intid);
int decode_default_email_compression_announcement(uint8_t *msgbody,
        uint16_t len, uint8_t *result);
int decode_default_radius_announcement(uint8_t *msgbody, uint16_t len,
        default_radius_user_t *defuser);
int decode_default_radius_withdraw(uint8_t *msgbody, uint16_t len,
        default_radius_user_t *defuser);
int decode_mediator_announcement(uint8_t *msgbody, uint16_t len,
        openli_mediator_t *med);
int decode_ics_signing_request(uint8_t *msgbody, uint16_t len,
        struct ics_sign_request_message *req);
int decode_ics_signing_response(uint8_t *msgbody, uint16_t len,
        struct ics_sign_response_message *resp);
int decode_mediator_withdraw(uint8_t *msgbody, uint16_t len,
        openli_mediator_t *med);
int decode_ipintercept_start(uint8_t *msgbody, uint16_t len,
        ipintercept_t *ipint);
int decode_ipintercept_halt(uint8_t *msgbody, uint16_t len,
        ipintercept_t *ipint);
int decode_ipintercept_modify(uint8_t *msgbody, uint16_t len,
        ipintercept_t *ipint);
int decode_voipintercept_start(uint8_t *msgbody, uint16_t len,
        voipintercept_t *vint);
int decode_voipintercept_halt(uint8_t *msgbody, uint16_t len,
        voipintercept_t *vint);
int decode_voipintercept_modify(uint8_t *msgbody, uint16_t len,
        voipintercept_t *vint);
int decode_emailintercept_start(uint8_t *msgbody, uint16_t len,
        emailintercept_t *mailint);
int decode_emailintercept_halt(uint8_t *msgbody, uint16_t len,
        emailintercept_t *mailint);
int decode_emailintercept_modify(uint8_t *msgbody, uint16_t len,
        emailintercept_t *mailint);
int decode_lea_announcement(uint8_t *msgbody, uint16_t len, liagency_t *lea);
int decode_lea_withdrawal(uint8_t *msgbody, uint16_t len, liagency_t *lea);
int decode_liid_mapping(uint8_t *msgbody, uint16_t len, char **agency,
        char **liid, uint8_t *encryptkey, size_t *encryptlen,
        payload_encryption_method_t *method,
        openli_liid_format_t *liidformat);
int decode_udp_sink(uint8_t *msgbody, uint16_t len, char **addr,
        char **port, char **identifier, uint64_t *ts);
int decode_x2x3_listener(uint8_t *msgbody, uint16_t len, char **addr,
        char **port, uint64_t *ts);
int decode_cease_mediation(uint8_t *msgbody, uint16_t len, char **liid);
int decode_coreserver_announcement(uint8_t *msgbody, uint16_t len,
        coreserver_t *cs);
int decode_coreserver_withdraw(uint8_t *msgbody, uint16_t len,
        coreserver_t *cs);
int decode_sip_target_announcement(uint8_t *msgbody, uint16_t len,
        openli_sip_identity_t *sipid, char *liidspace, int spacelen);
int decode_sip_target_withdraw(uint8_t *msgbody, uint16_t len,
        openli_sip_identity_t *sipid, char *liidspace, int spacelen);
int decode_email_target_announcement(uint8_t *msgbody, uint16_t len,
        email_target_t *tgt, char *liidspace, int spacelen);
int decode_email_target_withdraw(uint8_t *msgbody, uint16_t len,
        email_target_t *tgt, char *liidspace, int spacelen);
int decode_staticip_announcement(uint8_t *msgbody, uint16_t len,
        static_ipranges_t *ipr);
int decode_staticip_removal(uint8_t *msgbody, uint16_t len,
        static_ipranges_t *ipr);
int decode_staticip_modify(uint8_t *msgbody, uint16_t len,
        static_ipranges_t *ipr);
int decode_intercept_udpsink_announcement(uint8_t *msgbody, uint16_t len,
        intercept_udp_sink_t *sink);
int decode_intercept_udpsink_modify(uint8_t *msgbody, uint16_t len,
        intercept_udp_sink_t *sink);
int decode_intercept_udpsink_removal(uint8_t *msgbody, uint16_t len,
        intercept_udp_sink_t *sink);

int decode_hi1_notification(uint8_t *msgbody, uint16_t len,
        hi1_notify_data_t *ndata);
int decode_component_name(uint8_t *msgbody, uint16_t len, char **jsonconfig,
        char **uuidstr);
void nb_log_receive_error(openli_proto_msgtype_t err);
void nb_log_transmit_error(openli_proto_msgtype_t err);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
