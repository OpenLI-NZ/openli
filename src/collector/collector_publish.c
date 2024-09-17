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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <pthread.h>
#include <zmq.h>

#include "logger.h"
#include "util.h"
#include "collector_publish.h"
#include "emailiri.h"
#include "export_buffer.h"

int publish_openli_msg(void *pubsock, openli_export_recv_t *msg) {

    if (msg == NULL) {
        return 0;
    }

    while (1) {
        if (zmq_send(pubsock, &msg, sizeof(openli_export_recv_t *), 0) < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger(LOG_INFO, "Error while publishing OpenLI export message: %s",
                    strerror(errno));
            return -1;
        }
        break;
    }

    return 0;
}

openli_export_recv_t *create_intercept_details_msg(intercept_common_t *common) {

    openli_export_recv_t *expmsg;
    expmsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    expmsg->type = OPENLI_EXPORT_INTERCEPT_DETAILS;
    expmsg->data.cept.liid = strdup(common->liid);
    expmsg->data.cept.authcc = strdup(common->authcc);
    expmsg->data.cept.delivcc = strdup(common->delivcc);
    expmsg->data.cept.encryptmethod = common->encrypt;
    if (common->encryptkey) {
        expmsg->data.cept.encryptkey = strdup(common->encryptkey);
    } else {
        expmsg->data.cept.encryptkey = NULL;
    }
    expmsg->data.cept.seqtrackerid = common->seqtrackerid;

    return expmsg;
}


void free_published_message(openli_export_recv_t *msg) {

    if (msg->type == OPENLI_EXPORT_IPCC || msg->type == OPENLI_EXPORT_IPMMCC
            || msg->type == OPENLI_EXPORT_UMTSCC) {
        if (msg->data.ipcc.liid) {
            free(msg->data.ipcc.liid);
        }
        if (msg->data.ipcc.ipcontent) {
            free(msg->data.ipcc.ipcontent);
        }
    } else if (msg->type == OPENLI_EXPORT_EPSCC) {
        if (msg->data.mobcc.liid) {
            free(msg->data.mobcc.liid);
        }
        if (msg->data.mobcc.ipcontent) {
            free(msg->data.mobcc.ipcontent);
        }
    }else if (msg->type == OPENLI_EXPORT_EMAILCC) {
        if (msg->data.emailcc.liid) {
            free(msg->data.emailcc.liid);
        }
        if (msg->data.emailcc.cc_content) {
            free(msg->data.emailcc.cc_content);
        }
    } else if (msg->type == OPENLI_EXPORT_EMAILIRI) {
        if (msg->data.emailiri.liid) {
            free(msg->data.emailiri.liid);
        }
        free_email_iri_content(&(msg->data.emailiri.content));

    } else if (msg->type == OPENLI_EXPORT_IPMMIRI) {
        if (msg->data.ipmmiri.liid) {
            free(msg->data.ipmmiri.liid);
        }
        if (msg->data.ipmmiri.content) {
            free(msg->data.ipmmiri.content);
        }
        if (msg->data.ipmmiri.locations) {
            free(msg->data.ipmmiri.locations);
        }
    } else if (msg->type == OPENLI_EXPORT_IPIRI) {
        if (msg->data.ipiri.liid) {
            free(msg->data.ipiri.liid);
        }
        if (msg->data.ipiri.username) {
            free(msg->data.ipiri.username);
        }
        if (msg->data.ipiri.assignedips) {
            free(msg->data.ipiri.assignedips);
        }
    } else if (msg->type == OPENLI_EXPORT_UMTSIRI) {
        if (msg->data.mobiri.liid) {
            free(msg->data.mobiri.liid);
        }
    } else if (msg->type == OPENLI_EXPORT_RAW_SYNC ||
            msg->type == OPENLI_EXPORT_RAW_CC ||
            msg->type == OPENLI_EXPORT_RAW_IRI) {
        if (msg->data.rawip.liid) {
            free(msg->data.rawip.liid);
        }
        if (msg->data.rawip.ipcontent) {
            free(msg->data.rawip.ipcontent);
        }
    }

    free(msg);
}

openli_export_recv_t *create_rawip_job_from_ip(char *liid,
        uint32_t destid, void *l3, uint32_t l3_len, struct timeval tv,
        uint8_t msgtype) {

    openli_export_recv_t *msg = NULL;
    openli_pcap_header_t *pcap;

    msg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    if (msg == NULL) {
        return msg;
    }

    msg->type = msgtype;
    msg->destid = destid;
    msg->ts = tv;

    msg->data.rawip.liid = strdup(liid);
    msg->data.rawip.ipcontent = malloc(l3_len + sizeof(openli_pcap_header_t));

    pcap = (openli_pcap_header_t *)msg->data.rawip.ipcontent;
    pcap->ts_sec = tv.tv_sec;
    pcap->ts_usec = tv.tv_usec;
    pcap->caplen = l3_len;
    pcap->wirelen = l3_len;

    memcpy(msg->data.rawip.ipcontent + sizeof(openli_pcap_header_t), l3,
            l3_len);
    msg->data.rawip.ipclen = l3_len + sizeof(openli_pcap_header_t);
    msg->data.rawip.seqno = 0;
    msg->data.rawip.cin = 0;

    return msg;
}

openli_export_recv_t *create_rawip_cc_job(char *liid, uint32_t destid,
        libtrace_packet_t *pkt) {

    void *l3;
    uint32_t rem;
    uint16_t ethertype;
    struct timeval tv;

    l3 = trace_get_layer3(pkt, &ethertype, &rem);

    if (l3 == NULL || rem == 0 || (ethertype != TRACE_ETHERTYPE_IP &&
            ethertype != TRACE_ETHERTYPE_IPV6)) {
        return NULL;
    }

    tv = trace_get_timeval(pkt);
    return create_rawip_job_from_ip(liid, destid, l3, rem, tv,
            OPENLI_EXPORT_RAW_CC);

}

openli_export_recv_t *create_rawip_iri_job(char *liid, uint32_t destid,
        libtrace_packet_t *pkt) {

    void *l3;
    uint32_t rem;
    uint16_t ethertype;
    struct timeval tv;

    l3 = trace_get_layer3(pkt, &ethertype, &rem);

    if (l3 == NULL || rem == 0 || (ethertype != TRACE_ETHERTYPE_IP &&
            ethertype != TRACE_ETHERTYPE_IPV6)) {
        return NULL;
    }

    tv = trace_get_timeval(pkt);
    return create_rawip_job_from_ip(liid, destid, l3, rem, tv,
            OPENLI_EXPORT_RAW_IRI);

}

int push_vendor_mirrored_ipcc_job(void *pubqueue,
        intercept_common_t *common, struct timeval tv,
        uint32_t cin, uint8_t dir, void *l3, uint32_t rem) {

    openli_export_recv_t *msg;

    if (common->targetagency == NULL || strcmp(common->targetagency,
            "pcapdisk") == 0) {
        msg = create_rawip_job_from_ip(common->liid,
                common->destid, l3, rem, tv, OPENLI_EXPORT_RAW_CC);
    } else {
        msg = calloc(1, sizeof(openli_export_recv_t));

        msg->type = OPENLI_EXPORT_IPCC;
        msg->ts = tv;
        msg->destid = common->destid;
        msg->data.ipcc.liid = strdup(common->liid);
        msg->data.ipcc.cin = cin;
        msg->data.ipcc.dir = dir;
        msg->data.ipcc.ipcontent = (uint8_t *)calloc(1, rem);
        msg->data.ipcc.ipclen = rem;

        memcpy(msg->data.ipcc.ipcontent, l3, rem);
    }

    if (msg) {
        publish_openli_msg(pubqueue, msg);  //FIXME
        return 1;
    }
    return 0;
}

openli_export_recv_t *create_epscc_job_from_ip(uint32_t cin, char *liid,
        uint32_t destid, libtrace_packet_t *pkt, uint8_t dir) {

    void *l3;
    uint32_t rem;
    uint16_t ethertype;
    openli_export_recv_t *msg = NULL;

    msg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    if (msg == NULL) {
        return msg;
    }

    l3 = trace_get_layer3(pkt, &ethertype, &rem);

    if (l3 == NULL || rem == 0) {
        free(msg);
        return NULL;
    }

    msg->type = OPENLI_EXPORT_EPSCC;
    msg->destid = destid;
    msg->ts = trace_get_timeval(pkt);
    msg->data.mobcc.liid = strdup(liid);
    msg->data.mobcc.ipcontent = calloc(rem, sizeof(uint8_t));
    memcpy(msg->data.mobcc.ipcontent, l3, rem);
    msg->data.mobcc.ipclen = rem;
    msg->data.mobcc.cin = cin;
    msg->data.mobcc.dir = dir;

    msg->data.mobcc.icetype = 0;
    msg->data.mobcc.gtpseqno = 0;

    return msg;
}

openli_export_recv_t *create_ipcc_job(uint32_t cin, char *liid,
        uint32_t destid, libtrace_packet_t *pkt, uint8_t dir) {

    void *l3;
    uint32_t rem;
    uint16_t ethertype;
    openli_export_recv_t *msg = NULL;
    uint32_t x;
    size_t liidlen = strlen(liid);

    msg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    if (msg == NULL) {
        return msg;
    }

    l3 = trace_get_layer3(pkt, &ethertype, &rem);

    msg->type = OPENLI_EXPORT_IPCC;
    msg->destid = destid;
    msg->ts = trace_get_timeval(pkt);

    if (liidlen + 1 > msg->data.ipcc.liidalloc) {
        if (liidlen + 1 < 32) {
            x = 32;
        } else {
            x = liidlen + 1;
        }
        msg->data.ipcc.liid = realloc(msg->data.ipcc.liid, x);
        msg->data.ipcc.liidalloc = x;
    }
    if (msg->data.ipcc.liid == NULL) {
        msg->data.ipcc.liidalloc = 0;
        free(msg);
        return NULL;
    }

    memcpy(msg->data.ipcc.liid, liid, liidlen);
    msg->data.ipcc.liid[liidlen] = '\0';

    if (rem > msg->data.ipcc.ipcalloc) {
        if (rem < 512) {
            x = 512;
        } else {
            x = rem;
        }
        msg->data.ipcc.ipcontent = realloc(msg->data.ipcc.ipcontent, x);
        msg->data.ipcc.ipcalloc = x;
    }

    if (msg->data.ipcc.ipcontent == NULL) {
        msg->data.ipcc.ipcalloc = 0;
        free(msg);
        return NULL;
    }
    memcpy(msg->data.ipcc.ipcontent, l3, rem);
    msg->data.ipcc.ipclen = rem;
    msg->data.ipcc.cin = cin;
    msg->data.ipcc.dir = dir;

    return msg;
}

void copy_location_into_ipmmiri_job(openli_export_recv_t *dest,
        openli_location_t *loc, int loc_count) {
    int i;

    if (loc) {
        dest->data.ipmmiri.location_types = 0;
        dest->data.ipmmiri.locations = calloc(loc_count,
                sizeof(openli_location_t));

        for (i = 0; i < loc_count; i++) {
            memcpy(dest->data.ipmmiri.locations[i].encoded, loc[i].encoded, 8);
            dest->data.ipmmiri.locations[i].loc_type = loc[i].loc_type;
            dest->data.ipmmiri.locations[i].enc_len = loc[i].enc_len;
            dest->data.ipmmiri.location_types |= loc[i].loc_type;
        }
        dest->data.ipmmiri.location_cnt = loc_count;

        /* TODO support other encoding methods as required */
        dest->data.ipmmiri.location_encoding = OPENLI_LOC_ENCODING_EPS;
    } else {
        dest->data.ipmmiri.location_cnt = 0;
        dest->data.ipmmiri.location_types = 0;
        dest->data.ipmmiri.locations = NULL;
    }
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
