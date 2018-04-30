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

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "netcomms.h"
#include "logger.h"
#include "byteswap.h"


static inline void dump_buffer_contents(uint8_t *buf, uint16_t len) {

    uint16_t i = 0;

    for (i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if (i % 16 == 15) {
            printf("\n");
        }
    }


}

net_buffer_t *create_net_buffer(net_buffer_type_t buftype, int fd) {

    net_buffer_t *nb = (net_buffer_t *)malloc(sizeof(net_buffer_t));
    nb->buf = (char *)malloc(NETBUF_ALLOC_SIZE);
    nb->appendptr = nb->buf;
    nb->actptr = nb->buf;
    nb->alloced = NETBUF_ALLOC_SIZE;
    nb->fd = fd;
    nb->buftype = buftype;
    return nb;
}

void destroy_net_buffer(net_buffer_t *nb) {
    if (nb == NULL) {
        return;
    }
    free(nb->buf);
    free(nb);
}

static inline int extend_net_buffer(net_buffer_t *nb) {

    int bufused = nb->alloced - NETBUF_SPACE_REM(nb);
    int frontfree = NETBUF_FRONT_FREE(nb);
    int contsize = NETBUF_CONTENT_SIZE(nb);

    nb->buf = (char *)realloc(nb->buf, nb->alloced + NETBUF_ALLOC_SIZE);
    if (nb->buf == NULL) {
        /* OOM */
        logger(LOG_DAEMON, "OpenLI: unable to allocate larger net buffer.");
        return -1;
    }

    nb->actptr = nb->buf + frontfree;
    nb->appendptr = nb->actptr + contsize;
    nb->alloced += NETBUF_ALLOC_SIZE;
    return 0;

}

static int push_generic_onto_net_buffer(net_buffer_t *nb,
        uint8_t *data, uint16_t len) {

    if (len == 0) {
        return len;
    }

    while (NETBUF_SPACE_REM(nb) < len) {
        if (extend_net_buffer(nb) == -1) {
            return -1;
        }
    }

    memcpy(nb->appendptr, data, len);
    nb->appendptr += len;
    return len;
}

static inline void populate_header(ii_header_t *hdr,
        openli_proto_msgtype_t msgtype, uint16_t len, uint64_t intid) {

    hdr->magic = htonl(OPENLI_PROTO_MAGIC);
    hdr->bodylen = htons(len);
    hdr->intercepttype = htons((uint16_t)msgtype);
    hdr->internalid = bswap_host_to_be64(intid);
}

/* Quick and dirty method for constructing a netcomm protocol header
 * that can be used to push netcomm messages via sockets that are not
 * wrapped in a net buffer structure (e.g. collector->mediator sessions
 * which use the collector export API rather than net buffer, but will
 * use net buffer on the mediator side for receiving and decoding).
 */
uint8_t *construct_netcomm_protocol_header(uint32_t contentlen,
        uint16_t msgtype, uint64_t internalid, uint32_t *hdrlen) {

    ii_header_t *newhdr = (ii_header_t *)malloc(sizeof(ii_header_t));

    if (newhdr == NULL) {
        logger(LOG_DAEMON,
                "OOM while trying to create a netcomm protocol header.");
        return NULL;
    }

    if (contentlen > 65535) {
        logger(LOG_DAEMON,
                "Content of size %u cannot fit in a single netcomm PDU.",
                contentlen);
        free(newhdr);
        return NULL;
    }

    populate_header(newhdr, (openli_proto_msgtype_t)msgtype,
            (uint16_t)contentlen, internalid);
    *hdrlen = sizeof(ii_header_t);

    /* NOTE: the caller must free the header when they are finished with it!
     */
    return (uint8_t *)newhdr;

}

static inline int push_tlv(net_buffer_t *nb, openli_proto_fieldtype_t type,
        uint8_t *value, uint16_t vallen) {

    char tmp[NETBUF_ALLOC_SIZE];
    char *ptr = tmp;
    uint16_t shorttype, swaplen;

    if (vallen > NETBUF_ALLOC_SIZE - 4) {
        logger(LOG_DAEMON,
                "OpenLI: internal protocol does not support value fields larger than %u bytes.",
                NETBUF_ALLOC_SIZE - 4);
        logger(LOG_DAEMON, "Supplied field was %u bytes.", vallen);
        return -1;
    }

    shorttype = htons((uint16_t)type);
    swaplen = htons(vallen);

    memcpy(ptr, &shorttype, sizeof(uint16_t));
    ptr += 2;
    memcpy(ptr, &swaplen, sizeof(uint16_t));
    ptr += 2;
    memcpy(ptr, value, vallen);

    return push_generic_onto_net_buffer(nb, tmp, vallen + 4);
}

int push_auth_onto_net_buffer(net_buffer_t *nb, openli_proto_msgtype_t msgtype)
{

    ii_header_t hdr;

    if (msgtype == OPENLI_PROTO_COLLECTOR_AUTH) {
        populate_header(&hdr, msgtype, 0, OPENLI_COLLECTOR_MAGIC);
    } else if (msgtype == OPENLI_PROTO_MEDIATOR_AUTH) {
        populate_header(&hdr, msgtype, 0, OPENLI_MEDIATOR_MAGIC);
    } else {
        logger(LOG_DAEMON, "OpenLI: invalid auth message type: %d.", msgtype);
        return -1;
    }

    return push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t));
}

int push_disconnect_mediators_onto_net_buffer(net_buffer_t *nb) {
    ii_header_t hdr;

    /* TODO maybe add some extra security to this? */
    populate_header(&hdr, OPENLI_PROTO_DISCONNECT_MEDIATORS, 0, 0);
    return push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t));
}


#define LIIDMAP_BODY_LEN(agency, liid) \
    (strlen(agency) + strlen(liid) + (2 * 4))

int push_liid_mapping_onto_net_buffer(net_buffer_t *nb, char *agency,
        char *liid) {

    ii_header_t hdr;
    uint16_t totallen;

    totallen = LIIDMAP_BODY_LEN(agency, liid);
    populate_header(&hdr, OPENLI_PROTO_MEDIATE_INTERCEPT, totallen, 0);

    if (push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_LEAID, (uint8_t *)(agency),
                strlen(agency)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_LIID, (uint8_t *)(liid),
                strlen(liid)) == -1) {
        return -1;
    }
    return (int)totallen;
}

int push_cease_mediation_onto_net_buffer(net_buffer_t *nb, char *liid,
        int liid_len) {
    ii_header_t hdr;
    uint16_t totallen;

    totallen = liid_len + 4;
    populate_header(&hdr, OPENLI_PROTO_CEASE_MEDIATION, totallen, 0);

    if (push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_LIID, (uint8_t *)(liid),
                liid_len) == -1) {
        return -1;
    }
    return (int)totallen;
}

#define LEA_BODY_LEN(lea) \
    (strlen(lea->agencyid) + strlen(lea->hi2_ipstr) + \
    strlen(lea->hi2_portstr) + strlen(lea->hi3_ipstr) + \
    strlen(lea->hi3_portstr) + (5 * 4))

#define LEA_WITHDRAW_BODY_LEN(lea) \
    (strlen(lea->agencyid) + (1 * 4))

int push_lea_onto_net_buffer(net_buffer_t *nb, liagency_t *lea) {
    ii_header_t hdr;
    uint16_t totallen;

    totallen = LEA_BODY_LEN(lea);
    populate_header(&hdr, OPENLI_PROTO_ANNOUNCE_LEA, totallen, 0);
    if (push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_LEAID, (uint8_t *)(lea->agencyid),
                strlen(lea->agencyid)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_HI2IP, (uint8_t *)(lea->hi2_ipstr),
                strlen(lea->hi2_ipstr)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_HI2PORT, (uint8_t *)(lea->hi2_portstr),
                strlen(lea->hi2_portstr)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_HI3IP, (uint8_t *)(lea->hi3_ipstr),
                strlen(lea->hi3_ipstr)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_HI3PORT, (uint8_t *)(lea->hi3_portstr),
                strlen(lea->hi3_portstr)) == -1) {
        return -1;
    }
    return (int)totallen;

}

int push_lea_withdrawal_onto_net_buffer(net_buffer_t *nb, liagency_t *lea) {
    ii_header_t hdr;
    uint16_t totallen;

    totallen = LEA_WITHDRAW_BODY_LEN(lea);
    populate_header(&hdr, OPENLI_PROTO_WITHDRAW_LEA, totallen, 0);
    if (push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t)) == -1) {
        return -1;
    }

    if (push_tlv(nb, OPENLI_PROTO_FIELD_LEAID, (uint8_t *)(lea->agencyid),
                strlen(lea->agencyid)) == -1) {
        return -1;
    }
    return (int)totallen;
}



#define VOIPINTERCEPT_BODY_LEN(vint) \
        (vint->liid_len + vint->authcc_len + vint->delivcc_len + \
         vint->sipuri_len + sizeof(vint->destid) + \
         + (5 * 4))

#define VOIPINTERCEPT_WITHDRAW_BODY_LEN(vint) \
        (vint->liid_len + vint->authcc_len) + (2 * 4)

int push_voipintercept_withdrawal_onto_net_buffer(net_buffer_t *nb,
        voipintercept_t *vint) {

    ii_header_t hdr;
    uint16_t totallen;
    int ret;

    /* Pre-compute our body length so we can write it in the header */
    if (VOIPINTERCEPT_WITHDRAW_BODY_LEN(vint) > 65535) {
        logger(LOG_DAEMON,
                "OpenLI: VOIP intercept withdrawal is too long to fit in a single message (%d).",
                VOIPINTERCEPT_WITHDRAW_BODY_LEN(vint));
        return -1;
    }

    totallen = VOIPINTERCEPT_WITHDRAW_BODY_LEN(vint);

    /* Push on header */
    populate_header(&hdr, OPENLI_PROTO_HALT_VOIPINTERCEPT, totallen, 0);
    if ((ret = push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t))) == -1) {
        return -1;
    }

    /* Push on each intercept field */

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_LIID, vint->liid,
            vint->liid_len)) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_AUTHCC, vint->authcc,
            vint->authcc_len)) == -1) {
        return -1;
    }

    return (int)totallen;
}

int push_voipintercept_onto_net_buffer(net_buffer_t *nb,
        voipintercept_t *vint) {

    ii_header_t hdr;
    uint16_t totallen;
    int ret;

    /* Pre-compute our body length so we can write it in the header */
    if (VOIPINTERCEPT_BODY_LEN(vint) > 65535) {
        logger(LOG_DAEMON,
                "OpenLI: VOIP intercept announcement is too long to fit in a single message (%d).",
                VOIPINTERCEPT_BODY_LEN(vint));
        return -1;
    }

    totallen = VOIPINTERCEPT_BODY_LEN(vint);

    /* Push on header */
    populate_header(&hdr, OPENLI_PROTO_START_VOIPINTERCEPT, totallen, 0);
    if ((ret = push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t))) == -1) {
        return -1;
    }

    /* Push on each intercept field */
    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_LIID, vint->liid,
            vint->liid_len)) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_AUTHCC, vint->authcc,
            vint->authcc_len)) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_DELIVCC, vint->delivcc,
            vint->delivcc_len)) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_SIPURI, vint->sipuri,
            vint->sipuri_len)) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_MEDIATORID,
            (uint8_t *)&(vint->destid), sizeof(vint->destid))) == -1) {
        return -1;
    }

    return (int)totallen;

}

#define IPINTERCEPT_BODY_LEN(ipint) \
        (ipint->liid_len + ipint->authcc_len + ipint->delivcc_len + \
         ipint->username_len + sizeof(ipint->destid) + \
         + (5 * 4))

int push_ipintercept_onto_net_buffer(net_buffer_t *nb, ipintercept_t *ipint) {

    ii_header_t hdr;
    uint16_t totallen;
    int ret;

    /* Pre-compute our body length so we can write it in the header */
    if (IPINTERCEPT_BODY_LEN(ipint) > 65535) {
        logger(LOG_DAEMON,
                "OpenLI: intercept announcement is too long to fit in a single message (%d).",
                IPINTERCEPT_BODY_LEN(ipint));
        return -1;
    }

    totallen = IPINTERCEPT_BODY_LEN(ipint);

    /* Push on header */
    populate_header(&hdr, OPENLI_PROTO_START_IPINTERCEPT, totallen, 0);
    if ((ret = push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t))) == -1) {
        return -1;
    }

    /* Push on each intercept field */
    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_LIID, ipint->liid,
            ipint->liid_len)) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_AUTHCC, ipint->authcc,
            ipint->authcc_len)) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_DELIVCC, ipint->delivcc,
            ipint->delivcc_len)) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_USERNAME, ipint->username,
            ipint->username_len)) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_MEDIATORID,
            (uint8_t *)&(ipint->destid), sizeof(ipint->destid))) == -1) {
        return -1;
    }

    return (int)totallen;

}

#define MEDIATOR_BODY_LEN(med) \
    (sizeof(med->mediatorid) + strlen(med->ipstr) + strlen(med->portstr) \
     + (3 * 4))

static inline int push_mediator_msg_onto_net_buffer(net_buffer_t *nb,
        openli_mediator_t *med, openli_proto_msgtype_t type) {

    ii_header_t hdr;
    uint16_t totallen;
    int ret;

    /* Pre-compute our body length so we can write it in the header */
    if (MEDIATOR_BODY_LEN(med) > 65535) {
        logger(LOG_DAEMON,
                "OpenLI: mediator announcement is too long to fit in a single message (%d).",
                MEDIATOR_BODY_LEN(med));
        return -1;
    }

    totallen = MEDIATOR_BODY_LEN(med);

    /* Push on header */
    populate_header(&hdr, type, totallen, 0);
    if ((ret = push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t))) == -1) {
        return -1;
    }

    /* Push on each mediator field */
    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_MEDIATORID,
            (uint8_t *)&(med->mediatorid), sizeof(med->mediatorid))) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_MEDIATORIP, med->ipstr,
            strlen(med->ipstr))) == -1) {
        return -1;
    }

    if ((ret = push_tlv(nb, OPENLI_PROTO_FIELD_MEDIATORPORT, med->portstr,
            strlen(med->portstr))) == -1) {
        return -1;
    }

    return (int)totallen;
}

int push_mediator_onto_net_buffer(net_buffer_t *nb, openli_mediator_t *med) {

    return push_mediator_msg_onto_net_buffer(nb, med,
            OPENLI_PROTO_ANNOUNCE_MEDIATOR);
}

int push_mediator_withdraw_onto_net_buffer(net_buffer_t *nb,
        openli_mediator_t *med) {

    return push_mediator_msg_onto_net_buffer(nb, med,
            OPENLI_PROTO_WITHDRAW_MEDIATOR);
}


int push_nomore_intercepts(net_buffer_t *nb) {
    ii_header_t hdr;
    populate_header(&hdr, OPENLI_PROTO_NOMORE_INTERCEPTS, 0, 0);

    return push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t));
}

int push_nomore_mediators(net_buffer_t *nb) {
    ii_header_t hdr;
    populate_header(&hdr, OPENLI_PROTO_NOMORE_MEDIATORS, 0, 0);

    return push_generic_onto_net_buffer(nb, (uint8_t *)(&hdr),
            sizeof(ii_header_t));
}

int transmit_net_buffer(net_buffer_t *nb) {
    int ret;

    if (nb == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: attempted to transmit using a NULL buffer.");
        return -1;
    }

    if (nb->buftype != NETBUF_SEND) {
        logger(LOG_DAEMON,
                "OpenLI: attempted to transmit using a receive buffer.");
        return -1;
    }

    if (NETBUF_CONTENT_SIZE(nb) == 0) {
        return 0;
    }

    //dump_buffer_contents(nb->actptr, NETBUF_CONTENT_SIZE(nb));
    ret = send(nb->fd, nb->actptr, NETBUF_CONTENT_SIZE(nb), MSG_DONTWAIT);

    if (ret == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Socket not available right now... */
            return 1;
        }
        logger(LOG_DAEMON,
                "OpenLI: error while sending net buffer contents: %s.",
                strerror(errno));
        return -1;
    }


    nb->actptr += ret;

    /* If we've got a lot of unused space at the front of the buffer,
     * reclaim it by moving our content back to the front.
     */
    if (NETBUF_FRONT_FREE(nb) > NETBUF_ALLOC_SIZE) {
        int consize = NETBUF_CONTENT_SIZE(nb);

        if (consize > 0) {
            memmove(nb->buf, nb->actptr, consize);
        }
        nb->actptr = nb->buf;
        nb->appendptr = nb->actptr + consize;

        /* TODO consider shrinking the buffer if alloced > 10 allocations
         * and consize < 0.3 * alloced.
         */
    }

    return NETBUF_CONTENT_SIZE(nb);
}

static openli_proto_msgtype_t parse_received_message(net_buffer_t *nb,
        uint8_t **msgbody, uint16_t *msglen, uint64_t *intid) {

    ii_header_t *hdr;
    openli_proto_msgtype_t rettype;

    if (NETBUF_CONTENT_SIZE(nb) < sizeof(ii_header_t)) {
        return OPENLI_PROTO_NO_MESSAGE;
    }

    hdr = (ii_header_t *)(nb->actptr);

    if (ntohl(hdr->magic) != OPENLI_PROTO_MAGIC) {
        logger(LOG_DAEMON, "OpenLI: bogus message received via net buffer.");
        dump_buffer_contents(nb->actptr, NETBUF_CONTENT_SIZE(nb));
        assert(0);
        return OPENLI_PROTO_DISCONNECT;
    }

    if (NETBUF_CONTENT_SIZE(nb) < sizeof(ii_header_t) + ntohs(hdr->bodylen)) {
        return OPENLI_PROTO_NO_MESSAGE;
    }

    /* Got a complete message */
    *msgbody = ((uint8_t *)(nb->actptr)) + sizeof(ii_header_t);
    *msglen = ntohs(hdr->bodylen);
    *intid = bswap_be_to_host64(hdr->internalid);
    rettype = ntohs(hdr->intercepttype);

    nb->actptr += ((*msglen) + sizeof(ii_header_t));

    return rettype;
}

static int decode_tlv(uint8_t *start, uint8_t *end,
        openli_proto_fieldtype_t *t, uint16_t *l, uint8_t **v) {

    uint16_t t16 = ntohs(*(uint16_t *)start);
    *t = t16;

    start += 2;
    if (start >= end) {
        logger(LOG_DAEMON, "OpenLI: truncated TLV.");
        return -1;
    }

    *l = ntohs(*((uint16_t *)start));
    start += 2;
    if (start >= end) {
        logger(LOG_DAEMON, "OpenLI: truncated TLV.");
        return -1;
    }

    if (start + *l > end) {
        logger(LOG_DAEMON, "OpenLI: truncated TLV -- value is %u bytes, length field says %u\n",
                end - start, *l);
        return -1;
    }

    *v = start;
    return 0;
}

#define DECODE_STRING_FIELD(target, valptr, vallen) \
    target = (char *)malloc(vallen + 1); \
    memcpy(target, valptr, vallen); \
    (target)[vallen] = '\0';

int decode_voipintercept_start(uint8_t *msgbody, uint16_t len,
        voipintercept_t *vint) {

    uint8_t *msgend = msgbody + len;

    vint->internalid = 0;
    vint->liid = NULL;
    vint->authcc = NULL;
    vint->delivcc = NULL;
    vint->active_cins = NULL;  /* Placeholder -- sync thread should populate */
    vint->cin_callid_map = NULL;
    vint->cin_sdp_map = NULL;
    vint->sipuri = NULL;
    vint->destid = 0;
    vint->targetagency = NULL;
    vint->active = 1;
    vint->awaitingconfirm = 0;

    vint->liid_len = 0;
    vint->authcc_len = 0;
    vint->delivcc_len = 0;
    vint->sipuri_len = 0;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_MEDIATORID) {
            vint->destid = *((uint32_t *)valptr);
        } else if (f == OPENLI_PROTO_FIELD_LIID) {
            DECODE_STRING_FIELD(vint->liid, valptr, vallen);
            vint->liid_len = vallen;
        } else if (f == OPENLI_PROTO_FIELD_AUTHCC) {
            DECODE_STRING_FIELD(vint->authcc, valptr, vallen);
            vint->authcc_len = vallen;
        } else if (f == OPENLI_PROTO_FIELD_DELIVCC) {
            DECODE_STRING_FIELD(vint->delivcc, valptr, vallen);
            vint->delivcc_len = vallen;
        } else if (f == OPENLI_PROTO_FIELD_SIPURI) {
            DECODE_STRING_FIELD(vint->sipuri, valptr, vallen);
            vint->sipuri_len = vallen;
        } else if (f == OPENLI_PROTO_FIELD_INTERCEPTID) {
            vint->internalid = *((uint64_t *)valptr);
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_DAEMON,
                "OpenLI: invalid field in received VOIP intercept: %d.", f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    return 0;
}

int decode_voipintercept_halt(uint8_t *msgbody, uint16_t len,
        voipintercept_t *vint) {
    return decode_voipintercept_start(msgbody, len, vint);
}

int decode_ipintercept_start(uint8_t *msgbody, uint16_t len,
        ipintercept_t *ipint) {

    uint8_t *msgend = msgbody + len;

    ipint->liid = NULL;
    ipint->authcc = NULL;
    ipint->delivcc = NULL;
    ipint->username = NULL;
    ipint->destid = 0;
    ipint->targetagency = NULL;
    ipint->awaitingconfirm = 0;

    ipint->liid_len = 0;
    ipint->authcc_len = 0;
    ipint->delivcc_len = 0;
    ipint->username_len = 0;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_MEDIATORID) {
            ipint->destid = *((uint32_t *)valptr);
        } else if (f == OPENLI_PROTO_FIELD_LIID) {
            DECODE_STRING_FIELD(ipint->liid, valptr, vallen);
            ipint->liid_len = vallen;
        } else if (f == OPENLI_PROTO_FIELD_AUTHCC) {
            DECODE_STRING_FIELD(ipint->authcc, valptr, vallen);
            ipint->authcc_len = vallen;
        } else if (f == OPENLI_PROTO_FIELD_DELIVCC) {
            DECODE_STRING_FIELD(ipint->delivcc, valptr, vallen);
            ipint->delivcc_len = vallen;
        } else if (f == OPENLI_PROTO_FIELD_USERNAME) {
            DECODE_STRING_FIELD(ipint->username, valptr, vallen);
            ipint->username_len = vallen;
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_DAEMON,
                "OpenLI: invalid field in received IP intercept: %d.", f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    return 0;

}

int decode_mediator_announcement(uint8_t *msgbody, uint16_t len,
        openli_mediator_t *med) {

    uint8_t *msgend = msgbody + len;

    med->ipstr = NULL;
    med->portstr = NULL;
    med->mediatorid = 0;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_MEDIATORID) {
            med->mediatorid = *((uint32_t *)valptr);
        } else if (f == OPENLI_PROTO_FIELD_MEDIATORIP) {
            DECODE_STRING_FIELD(med->ipstr, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_MEDIATORPORT) {
            DECODE_STRING_FIELD(med->portstr, valptr, vallen);
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_DAEMON,
                "OpenLI: invalid field in received mediator announcement: %d.",
                f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    return 0;
}

int decode_mediator_withdraw(uint8_t *msgbody, uint16_t len,
        openli_mediator_t *med) {

    return decode_mediator_announcement(msgbody, len, med);
}

int decode_lea_announcement(uint8_t *msgbody, uint16_t len, liagency_t *lea) {

    uint8_t *msgend = msgbody + len;

    lea->hi2_ipstr = NULL;
    lea->hi2_portstr = NULL;
    lea->hi3_ipstr = NULL;
    lea->hi3_portstr = NULL;
    lea->agencyid = NULL;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_LEAID) {
            DECODE_STRING_FIELD(lea->agencyid, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_HI2IP) {
            DECODE_STRING_FIELD(lea->hi2_ipstr, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_HI2PORT) {
            DECODE_STRING_FIELD(lea->hi2_portstr, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_HI3IP) {
            DECODE_STRING_FIELD(lea->hi3_ipstr, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_HI3PORT) {
            DECODE_STRING_FIELD(lea->hi3_portstr, valptr, vallen);
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_DAEMON,
                "OpenLI: invalid field in received LEA announcement: %d.",
                f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    return 0;
}

int decode_lea_withdrawal(uint8_t *msgbody, uint16_t len, liagency_t *lea) {
    return decode_lea_announcement(msgbody, len, lea);
}

int decode_liid_mapping(uint8_t *msgbody, uint16_t len, char **agency,
        char **liid) {

    uint8_t *msgend = msgbody + len;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_LIID) {
            DECODE_STRING_FIELD(*liid, valptr, vallen);
        } else if (f == OPENLI_PROTO_FIELD_LEAID) {
            DECODE_STRING_FIELD(*agency, valptr, vallen);
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_DAEMON,
                    "OpenLI: invalid field in received LIID mapping: %d.",
                    f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    return 0;
}

int decode_cease_mediation(uint8_t *msgbody, uint16_t len, char **liid) {
    uint8_t *msgend = msgbody + len;

    while (msgbody < msgend) {
        openli_proto_fieldtype_t f;
        uint8_t *valptr;
        uint16_t vallen;

        if (decode_tlv(msgbody, msgend, &f, &vallen, &valptr) == -1) {
            return -1;
        }

        if (f == OPENLI_PROTO_FIELD_LIID) {
            DECODE_STRING_FIELD(*liid, valptr, vallen);
        } else {
            dump_buffer_contents(msgbody, len);
            logger(LOG_DAEMON,
                    "OpenLI: invalid field in received cease mediation: %d.",
                    f);
            return -1;
        }
        msgbody += (vallen + 4);
    }

    return 0;
}


openli_proto_msgtype_t receive_net_buffer(net_buffer_t *nb, uint8_t **msgbody,
        uint16_t *msglen, uint64_t *intid) {

    ii_header_t *hdr;
    openli_proto_msgtype_t rettype;
    int ret;

    if (nb == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: attempted to receive using a NULL buffer.");
        return OPENLI_PROTO_DISCONNECT;
    }

    if (nb->buftype != NETBUF_RECV) {
        logger(LOG_DAEMON,
                "OpenLI: attempted to receive using a transmit buffer.");
        return OPENLI_PROTO_DISCONNECT;
    }

    rettype = parse_received_message(nb, msgbody, msglen, intid);
    if (rettype != OPENLI_PROTO_NO_MESSAGE) {
        return rettype;
    }

    /* Not enough data in the buffer for a complete message, read some more. */
    if (NETBUF_SPACE_REM(nb) < NETBUF_ALLOC_SIZE) {
        if (extend_net_buffer(nb) == -1) {
            return OPENLI_PROTO_DISCONNECT;
        }
    }

    ret = recv(nb->fd, nb->appendptr, NETBUF_SPACE_REM(nb), MSG_DONTWAIT);
    if (ret <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return OPENLI_PROTO_NO_MESSAGE;
        }
        if (ret == 0) {
            /* Other end disconnected */
            return OPENLI_PROTO_DISCONNECT;
        }
        logger(LOG_DAEMON,
                "OpenLI: error while receiving data into net buffer: %s,",
                strerror(errno));
        return OPENLI_PROTO_DISCONNECT;
    }

    nb->appendptr += ret;

    rettype = parse_received_message(nb, msgbody, msglen, intid);
    return rettype;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
