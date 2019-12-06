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

#ifndef OPENLI_NETCOMMS_H_
#define OPENLI_NETCOMMS_H_

#include "config.h"
#include <inttypes.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>

#define NETBUF_ALLOC_SIZE (10 * 1024 * 1024)

#define OPENLI_PROTO_MAGIC 0x5c4c6c5c
#define OPENLI_COLLECTOR_MAGIC 0x00180014202042a8
#define OPENLI_MEDIATOR_MAGIC 0x01153200d6f12905

#define NETBUF_SPACE_REM(nbuf) (nbuf->alloced - (nbuf->appendptr - nbuf->buf))
#define NETBUF_FRONT_FREE(nbuf) (nbuf->actptr - nbuf->buf)
#define NETBUF_CONTENT_SIZE(nbuf) (nbuf->appendptr - nbuf->actptr)

#include "intercept.h"
#include "agency.h"
#include "coreserver.h"

typedef struct ii_header {
    uint32_t magic;
    uint16_t bodylen;
    uint16_t intercepttype;
    uint64_t internalid;
} PACKED ii_header_t;


typedef struct openli_mediator {
    uint32_t mediatorid;
    char *ipstr;
    char *portstr;
} openli_mediator_t;

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
} openli_proto_msgtype_t;

typedef struct net_buffer {
    int fd;
    char *buf;
    char *appendptr;
    char *actptr;
    int alloced;
    net_buffer_type_t buftype;
    SSL *ssl;
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
} openli_proto_fieldtype_t;

net_buffer_t *create_net_buffer(net_buffer_type_t buftype, int fd, SSL *ssl);
int fd_set_nonblock(int fd);
int fd_set_block(int fd);
void destroy_net_buffer(net_buffer_t *nb);

int construct_netcomm_protocol_header(ii_header_t *hdr, uint32_t contentlen,
        uint16_t msgtype, uint64_t internalid, uint32_t *hdrlen);

int push_default_radius_onto_net_buffer(net_buffer_t *nb,
        default_radius_user_t *defuser);
int push_default_radius_withdraw_onto_net_buffer(net_buffer_t *nb,
        default_radius_user_t *defuser);
int push_mediator_onto_net_buffer(net_buffer_t *nb, openli_mediator_t *med);
int push_mediator_withdraw_onto_net_buffer(net_buffer_t *nb,
        openli_mediator_t *med);
int push_ipintercept_onto_net_buffer(net_buffer_t *nb, void *ipint);
int push_voipintercept_onto_net_buffer(net_buffer_t *nb,
        void *vint);
int push_intercept_withdrawal_onto_net_buffer(net_buffer_t *nb,
        void *cept, openli_proto_msgtype_t wdtype);
int push_intercept_modify_onto_net_buffer(net_buffer_t *nb,
        void *cept, openli_proto_msgtype_t modtype);
int push_lea_onto_net_buffer(net_buffer_t *nb, liagency_t *lea);
int push_lea_withdrawal_onto_net_buffer(net_buffer_t *nb, liagency_t *lea);
int push_intercept_dest_onto_net_buffer(net_buffer_t *nb, char *liid,
        char *agencyid);
int push_auth_onto_net_buffer(net_buffer_t *nb, openli_proto_msgtype_t
        authtype);
int push_liid_mapping_onto_net_buffer(net_buffer_t *nb, char *agency,
        char *liid);
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
int transmit_net_buffer(net_buffer_t *nb, openli_proto_msgtype_t *err);
int push_static_ipranges_removal_onto_net_buffer(net_buffer_t *nb,
        ipintercept_t *ipint, static_ipranges_t *ipr);
int push_static_ipranges_modify_onto_net_buffer(net_buffer_t *nb,
        ipintercept_t *ipint, static_ipranges_t *ipr);
int push_static_ipranges_onto_net_buffer(net_buffer_t *nb,
        ipintercept_t *ipint, static_ipranges_t *ipr);

openli_proto_msgtype_t receive_net_buffer(net_buffer_t *nb, uint8_t **msgbody,
        uint16_t *msglen, uint64_t *intid);
int decode_default_radius_announcement(uint8_t *msgbody, uint16_t len,
        default_radius_user_t *defuser);
int decode_default_radius_withdraw(uint8_t *msgbody, uint16_t len,
        default_radius_user_t *defuser);
int decode_mediator_announcement(uint8_t *msgbody, uint16_t len,
        openli_mediator_t *med);
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
int decode_lea_announcement(uint8_t *msgbody, uint16_t len, liagency_t *lea);
int decode_lea_withdrawal(uint8_t *msgbody, uint16_t len, liagency_t *lea);
int decode_liid_mapping(uint8_t *msgbody, uint16_t len, char **agency,
        char **liid);
int decode_cease_mediation(uint8_t *msgbody, uint16_t len, char **liid);
int decode_coreserver_announcement(uint8_t *msgbody, uint16_t len,
        coreserver_t *cs);
int decode_coreserver_withdraw(uint8_t *msgbody, uint16_t len,
        coreserver_t *cs);
int decode_sip_target_announcement(uint8_t *msgbody, uint16_t len,
        openli_sip_identity_t *sipid, char *liidspace, int spacelen);
int decode_sip_target_withdraw(uint8_t *msgbody, uint16_t len,
        openli_sip_identity_t *sipid, char *liidspace, int spacelen);
int decode_staticip_announcement(uint8_t *msgbody, uint16_t len,
        static_ipranges_t *ipr);
int decode_staticip_removal(uint8_t *msgbody, uint16_t len,
        static_ipranges_t *ipr);
int decode_staticip_modify(uint8_t *msgbody, uint16_t len,
        static_ipranges_t *ipr);
void nb_log_receive_error(openli_proto_msgtype_t err);
void nb_log_transmit_error(openli_proto_msgtype_t err);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
