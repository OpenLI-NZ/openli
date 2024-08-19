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

#ifndef OPENLI_COLLECTOR_PUBLISH_H_
#define OPENLI_COLLECTOR_PUBLISH_H_

#include <libtrace.h>
#include <zmq.h>

#include "netcomms.h"
#include "etsili_core.h"
#include "intercept.h"
#include "internetaccess.h"
#include "location.h"

enum {
    OPENLI_EXPORT_HALT_WORKER = 1,
    OPENLI_EXPORT_PACKET_FIN = 2,
    OPENLI_EXPORT_MEDIATOR = 3,
    OPENLI_EXPORT_FLAG_MEDIATORS = 4,
    OPENLI_EXPORT_RECONNECT_ALL_MEDIATORS = 5,
    OPENLI_EXPORT_DROP_ALL_MEDIATORS = 6,
    OPENLI_EXPORT_DROP_SINGLE_MEDIATOR = 7,
    OPENLI_EXPORT_IPCC = 8,
    OPENLI_EXPORT_IPMMCC = 9,
    OPENLI_EXPORT_IPIRI = 10,
    OPENLI_EXPORT_IPMMIRI = 11,
    OPENLI_EXPORT_INTERCEPT_DETAILS = 12,
    OPENLI_EXPORT_INTERCEPT_OVER = 13,
    OPENLI_EXPORT_HALT = 14,
    OPENLI_EXPORT_RECONFIGURE_INTERCEPTS = 15,
    OPENLI_EXPORT_UMTSCC = 16,
    OPENLI_EXPORT_UMTSIRI = 17,
    OPENLI_EXPORT_RAW_SYNC = 18,
    OPENLI_EXPORT_INTERCEPT_CHANGED = 19,
    OPENLI_EXPORT_PROVISIONER_MESSAGE = 20,
    OPENLI_EXPORT_EMAILCC = 21,
    OPENLI_EXPORT_EMAILIRI = 22,
    OPENLI_EXPORT_RAW_CC = 23,
    OPENLI_EXPORT_RAW_IRI = 24,
    OPENLI_EXPORT_EPSCC = 25,
    OPENLI_EXPORT_EPSIRI = 26,
};

/* This structure is also used for IPMMCCs since they require the same
 * raw information.
 */
typedef struct openli_ipcc_job {
    char *liid;
    uint8_t *ipcontent;
    uint32_t ipclen;
    uint32_t ipcalloc;
    uint16_t liidalloc;
    uint32_t cin;
    uint8_t dir;
} PACKED openli_ipcc_job_t;

typedef struct openli_mobcc_job {
    char *liid;
    uint32_t cin;
    uint8_t dir;
    uint8_t *ipcontent;
    uint32_t ipclen;
    uint8_t icetype;
    uint16_t gtpseqno;
} PACKED openli_mobcc_job_t;

typedef struct openli_emailiri_job {
    char *liid;
    uint32_t cin;
    etsili_iri_type_t iritype;
    etsili_email_iri_content_t content;
    etsili_generic_t *customparams;
} openli_emailiri_job_t;

typedef struct openli_emailcc_job {
    char *liid;
    uint32_t cin;
    uint8_t format;
    uint8_t dir;
    uint8_t *cc_content;
    int cc_content_len;
} openli_emailcc_job_t;

typedef struct openli_ipmmiri_job {
    char *liid;
    uint32_t cin;
    etsili_iri_type_t iritype;
    uint8_t ipmmiri_style;
    uint8_t *content;
    uint16_t contentlen;
    uint8_t ipsrc[16];
    uint8_t ipdest[16];
    int ipfamily;

    openli_location_t *locations;
    uint8_t location_cnt;
    uint32_t location_types;
    uint8_t location_encoding;
}  openli_ipmmiri_job_t;

typedef struct openli_mobiri_job {
    char *liid;
    uint32_t cin;
    etsili_iri_type_t iritype;
    etsili_generic_t *customparams;
}  openli_mobiri_job_t;


typedef struct openli_ipiri_job {
    char *liid;
    uint32_t cin;
    char *username;

    internetaccess_ip_t *assignedips;
    uint8_t ipcount;
    uint8_t ipversioning;

    struct timeval sessionstartts;
    internet_access_method_t access_tech;
    uint8_t special;
    uint8_t ipassignmentmethod;
    etsili_iri_type_t iritype;
    etsili_generic_t *customparams;

}  openli_ipiri_job_t;

typedef struct openli_rawip_job {
    char *liid;
    uint8_t *ipcontent;
    uint32_t ipclen;
    uint32_t seqno;
    uint32_t cin;
}  openli_rawip_job_t;

enum {
    OPENLI_IPIRI_STANDARD,
    OPENLI_IPIRI_ENDWHILEACTIVE,
    OPENLI_IPIRI_STARTWHILEACTIVE,
    OPENLI_IPIRI_SILENTLOGOFF,
};

enum {
    OPENLI_IPIRI_IPMETHOD_STATIC,
    OPENLI_IPIRI_IPMETHOD_DYNAMIC,
    OPENLI_IPIRI_IPMETHOD_UNKNOWN,
};

typedef struct published_intercept_msg {
    char *liid;
    char *authcc;
    char *delivcc;
    int seqtrackerid;
    payload_encryption_method_t encryptmethod;
    char *encryptkey;
} published_intercept_msg_t;

typedef struct provisioner_msg {
    uint8_t msgtype;
    uint8_t *msgbody;
    uint16_t msglen;
} provisioner_msg_t;

typedef struct openli_export_recv openli_export_recv_t;

struct openli_export_recv {
    uint8_t type;
    uint32_t destid;
    struct timeval ts;
    union {
        openli_mediator_t med;
        libtrace_packet_t *packet;
        published_intercept_msg_t cept;
        provisioner_msg_t provmsg;
        openli_ipcc_job_t ipcc;
        openli_ipmmiri_job_t ipmmiri;
        openli_ipiri_job_t ipiri;
        openli_mobiri_job_t mobiri;
        openli_mobcc_job_t mobcc;
        openli_rawip_job_t rawip;
        openli_emailiri_job_t emailiri;
        openli_emailcc_job_t emailcc;
    } data;
};

int publish_openli_msg(void *pubsock, openli_export_recv_t *msg);
void free_published_message(openli_export_recv_t *msg);

openli_export_recv_t *create_intercept_details_msg(intercept_common_t *common);

openli_export_recv_t *create_ipcc_job(
        uint32_t cin, char *liid, uint32_t destid, libtrace_packet_t *pkt,
        uint8_t dir);

/** Creates a raw IP packet encoding job from a pointer to an IP header.
 *  Supports creating messages using both the OPENLI_EXPORT_RAW_CC type and
 *  the OPENLI_EXPORT_RAW_IRI type.
 *
 *  Used to export IP packets that are being intercepted by pcapdisk
 *  IP data intercepts.
 *
 *  @param liid     The LIID that this packet has been intercepted for
 *  @param destid   The mediator that should receive the raw IP packet
 *  @param l3       Pointer to the start of the IP header from the packet
 *                  that is being intercepted
 *  @param l3_len   The number of bytes in the intercepted packet, starting
 *                  from the pointer given as `l3`
 *  @param tv       The timestamp for the intercepted packet
 *  @param msgtype  The type of job to encode (either OPENLI_EXPORT_RAW_CC
 *                  or OPENLI_EXPORT_RAW_IRI)
 *
 *  @return an encoding job that is ready to be published using
 *          publish_openli_msg()
 */
openli_export_recv_t *create_rawip_job_from_ip(char *liid,
        uint32_t destid, void *l3, uint32_t l3_len, struct timeval tv,
        uint8_t msgtype);

/** Creates a raw IP packet encoding job using the OPENLI_EXPORT_RAW_CC type.
 *
 *  Used to export IP packets that are being intercepted by pcapdisk
 *  IP data intercepts.
 *
 *  @param liid     The LIID that this packet has been intercepted for
 *  @param destid   The mediator that should receive the raw IP packet
 *  @param pkt      The packet that was intercepted
 *
 *  @return an encoding job that is ready to be published using
 *          publish_openli_msg()
 */
openli_export_recv_t *create_rawip_cc_job(char *liid, uint32_t destid,
        libtrace_packet_t *pkt);

/** Creates a raw IP packet encoding job using the OPENLI_EXPORT_RAW_IRI type.
 *
 *  Used to export SIP packets that are being intercepted by pcapdisk
 *  VOIP intercepts.
 *
 *  @param liid     The LIID that this packet has been intercepted for
 *  @param destid   The mediator that should receive the raw IP packet
 *  @param pkt      The packet that was intercepted
 *
 *  @return an encoding job that is ready to be published using
 *          publish_openli_msg()
 */
openli_export_recv_t *create_rawip_iri_job(char *liid, uint32_t destid,
        libtrace_packet_t *pkt);

int push_vendor_mirrored_ipcc_job(void *pubqueue,
        intercept_common_t *common, struct timeval tv,
        uint32_t cin, uint8_t dir, void *l3, uint32_t rem);

void copy_location_into_ipmmiri_job(openli_export_recv_t *dest,
        openli_location_t *loc, int loc_count);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
