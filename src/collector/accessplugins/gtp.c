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

#include <assert.h>
#include <libtrace_parallel.h>
#include <pthread.h>
#include <Judy.h>

#include "umtsiri.h"
#include "logger.h"
#include "internetaccess.h"
#include "util.h"

#define GTP_FLUSH_OLD_PKT_FREQ 180

enum {
    GTPV1_IE_CAUSE = 1,
    GTPV1_IE_IMSI = 2,
    GTPV1_IE_TEID_CTRL = 17,
    GTPV1_IE_END_USER_ADDRESS = 128,
    GTPV1_IE_APNAME = 131,
    GTPV1_IE_MSISDN = 134,
    GTPV1_IE_ULI = 152,
    GTPV1_IE_MEI = 154,
};

enum {
    GTPV2_IE_IMSI = 1,
    GTPV2_IE_CAUSE = 2,
    GTPV2_IE_APNAME = 71,
    GTPV2_IE_MEI = 75,
    GTPV2_IE_MSISDN = 76,
    GTPV2_IE_PDN_ALLOC = 79,
    GTPV2_IE_ULI = 86,
    GTPV2_IE_FTEID = 87,
};

/* TODO add more cause values here */
enum {
    GTPV2_CAUSE_REQUEST_ACCEPTED = 16,
};

enum {
    GTPV1_CAUSE_REQUEST_ACCEPTED = 128,
};

enum {
    SM_CAUSE_REGULAR_DEACTIVATION = 36,
};

/* XXX do we need to support other message types here, e.g. for IRI-Report? */
enum {
    GTPV1_CREATE_PDP_CONTEXT_REQUEST = 16,
    GTPV1_CREATE_PDP_CONTEXT_RESPONSE = 17,
    GTPV1_UPDATE_PDP_CONTEXT_REQUEST = 18,
    GTPV1_UPDATE_PDP_CONTEXT_RESPONSE = 19,
    GTPV1_DELETE_PDP_CONTEXT_REQUEST = 20,
    GTPV1_DELETE_PDP_CONTEXT_RESPONSE = 21,

    GTPV2_CREATE_SESSION_REQUEST = 32,
    GTPV2_CREATE_SESSION_RESPONSE = 33,
    GTPV2_DELETE_SESSION_REQUEST = 36,
    GTPV2_DELETE_SESSION_RESPONSE = 37,
};

typedef struct gtpv1_header {
    uint8_t octet1;
    uint8_t msgtype;
    uint16_t msglen;
    uint32_t teid;
    uint16_t seqno;
    uint8_t npdu;
    uint8_t next_ext;
} PACKED gtpv1_header_t;

typedef struct gtpv2_header_teid {
    uint8_t octet1;
    uint8_t msgtype;
    uint16_t msglen;
    uint32_t teid;
    uint32_t seqno;
} PACKED gtpv2_header_teid_t;

typedef struct gtp_infelem gtp_infoelem_t;

struct gtp_infelem {
    uint8_t ietype;
    uint16_t ielength;
    uint8_t ieflags;
    void *iecontent;
    gtp_infoelem_t *next;
};

/* Stored copies of the IEs that we need to include in IRI messages, in their
 * original binary format (for easier encoding).
 */
typedef struct gtp_sess_saved {
    uint8_t *imsi;
    uint16_t imsi_len;
    uint8_t *msisdn;
    uint16_t msisdn_len;
    uint8_t *apname;
    uint16_t apname_len;
    uint8_t *imei;
    uint16_t imei_len;
    uint8_t *location;
    uint16_t location_len;
    uint8_t loc_version;
} PACKED gtp_sess_saved_t;

typedef struct gtp_saved_packet gtp_saved_pkt_t;

typedef struct gtp_session {

    char *sessid;
    gtp_sess_saved_t saved;

    char idstr_msisdn[64];
    int idstr_msisdn_len;
    char idstr_imsi[64];
    int idstr_imsi_len;
    char idstr_imei[64];
    int idstr_imei_len;
    uint32_t teid;

    internetaccess_ip_t *pdpaddrs;
    uint8_t pdpaddrcount;
    uint16_t pdptype;
    int64_t cin;

    uint8_t serverid[16];
    uint8_t serveripfamily;

    session_state_t current;


    uint64_t last_reqid;
    uint8_t last_reqtype;
    session_state_t savedoldstate;
    session_state_t savednewstate;
    gtp_saved_pkt_t *lastsavedpkt;

} gtp_session_t;

struct gtp_saved_packet {
    uint64_t reqid;
    uint8_t version;
    uint8_t type;
    uint8_t applied;
    double tvsec;
    uint8_t response_cause;

    uint8_t *ipcontent;
    uint16_t iplen;
    gtp_infoelem_t *ies;
    gtp_session_t *matched_session;
};

typedef struct gtp_parsed {

    uint8_t attached;
    libtrace_packet_t *origpkt;

    uint8_t version;
    uint8_t msgtype;
    double tvsec;
    uint32_t teid;
    uint32_t teid_ctl;
    uint32_t seqno;
    uint8_t response_cause;

    uint8_t serveripfamily;
    uint8_t serverid[16];

    char imsi[16];
    char msisdn[16];
    char imei[16];

    gtp_saved_pkt_t *request;
    gtp_saved_pkt_t *response;

    gtp_infoelem_t *ies;
    gtp_session_t *matched_session;

    access_action_t action;

} gtp_parsed_t;

typedef struct gtp_global {
    gtp_parsed_t *parsedpkt;

    Pvoid_t saved_packets;
    Pvoid_t session_map;
    Pvoid_t alt_session_map;

    double lastrefresh;
} gtp_global_t;


static void reset_parsed_pkt(gtp_parsed_t *parsed) {
    parsed->attached = 1;
    parsed->origpkt = NULL;
    parsed->version = 0;
    parsed->msgtype = 0;
    parsed->tvsec = 0;
    parsed->teid = 0;
    parsed->teid_ctl = 0;
    parsed->seqno = 0;
    parsed->response_cause = 0;

    parsed->serveripfamily = 0;
    memset(parsed->serverid, 0, 16);
    memset(parsed->imsi, 0, 16);
    memset(parsed->imei, 0, 16);
    memset(parsed->msisdn, 0, 16);

    parsed->ies = NULL;
    parsed->matched_session = NULL;
    parsed->action = ACCESS_ACTION_NONE;
    parsed->request = NULL;
    parsed->response = NULL;
}

static void gtp_init_plugin_data(access_plugin_t *p) {

    gtp_global_t *glob;

    glob = (gtp_global_t *)calloc(1, sizeof(gtp_global_t));
    glob->parsedpkt = (gtp_parsed_t *)malloc(sizeof(gtp_parsed_t));
    reset_parsed_pkt(glob->parsedpkt);

    p->plugindata = (void *)glob;
}

static inline void destroy_gtp_session(gtp_session_t *sess) {
    if (!sess) {
        return;
    }

    if (sess->sessid) {
        free(sess->sessid);
    }

    if (sess->saved.imei) {
        free(sess->saved.imei);
    }

    if (sess->saved.apname) {
        free(sess->saved.apname);
    }

    if (sess->saved.location) {
        free(sess->saved.location);
    }

    if (sess->saved.imsi) {
        free(sess->saved.imsi);
    }

    if (sess->saved.msisdn) {
        free(sess->saved.msisdn);
    }

    free(sess);
}

static inline void gtp_free_ie_list(gtp_infoelem_t *ies) {

    gtp_infoelem_t *ie, *tmp;

    ie = ies;

    while (ie) {
        tmp = ie;
        ie = ie->next;
        if (tmp->iecontent) {
            free(tmp->iecontent);
        }
        free(tmp);
    }
}

static void gtp_destroy_plugin_data(access_plugin_t *p) {
    gtp_global_t *glob;
    unsigned char index[64];
    PWord_t pval;
    Word_t res, indexnum;

    glob = (gtp_global_t *)(p->plugindata);
    if (!glob) {
        return;
    }

    index[0] = '\0';
    JSLF(pval, glob->session_map, index);
    while (pval) {
        gtp_session_t *sess = (gtp_session_t *)(*pval);
        destroy_gtp_session(sess);
        JSLN(pval, glob->session_map, index);
    }
    JSLFA(res, glob->session_map);
    JSLFA(res, glob->alt_session_map);

    indexnum = 0;
    JLF(pval, glob->saved_packets, indexnum);
    while (pval) {
        gtp_saved_pkt_t *pkt = (gtp_saved_pkt_t *)(*pval);

        if (pkt->ipcontent) {
            free(pkt->ipcontent);
        }
        gtp_free_ie_list(pkt->ies);
        free(pkt);
        JLN(pval, glob->saved_packets, indexnum);
    }
    JLFA(res, glob->saved_packets);

    if (glob->parsedpkt) {
        free(glob->parsedpkt);
    }
    free(glob);
}

static void gtp_uncouple_parsed_data(access_plugin_t *p) {

}

static void gtp_destroy_parsed_data(access_plugin_t *p, void *parsed) {

    gtp_parsed_t *gparsed = (gtp_parsed_t *)parsed;

    if (!gparsed) {
        return;
    }

    gtp_free_ie_list(gparsed->ies);

    if (gparsed->request) {
        if (gparsed->request->ipcontent) {
            free(gparsed->request->ipcontent);
        }
        gtp_free_ie_list(gparsed->request->ies);
        free(gparsed->request);
    }

    if (gparsed->response) {
        if (gparsed->response->ipcontent) {
            free(gparsed->response->ipcontent);
        }
        gtp_free_ie_list(gparsed->response->ies);
        free(gparsed->response);
    }

    if (gparsed->attached) {
        reset_parsed_pkt(gparsed);
    } else {
        free(gparsed);
    }
}

static inline bool interesting_info_element(uint8_t gtpv, uint8_t ietype) {

    if (gtpv == 2) {
        switch(ietype) {
            case GTPV2_IE_IMSI:
            case GTPV2_IE_FTEID:
            case GTPV2_IE_MSISDN:
            case GTPV2_IE_PDN_ALLOC:
            case GTPV2_IE_CAUSE:
            case GTPV2_IE_MEI:
            case GTPV2_IE_APNAME:
            case GTPV2_IE_ULI:
                return true;
        }
    } else if (gtpv == 1) {
        switch (ietype) {
            case GTPV1_IE_CAUSE:
            case GTPV1_IE_IMSI:
            case GTPV1_IE_TEID_CTRL:
            case GTPV1_IE_END_USER_ADDRESS:
            case GTPV1_IE_APNAME:
            case GTPV1_IE_MSISDN:
            case GTPV1_IE_ULI:
            case GTPV1_IE_MEI:
                return true;
        }
    }

    return false;
}

static inline gtp_infoelem_t *create_new_gtpv2_infoel(uint8_t ietype,
        uint16_t ielen, uint8_t *ieptr) {

    gtp_infoelem_t *el;

    el = (gtp_infoelem_t *)calloc(1, sizeof(gtp_infoelem_t));

    el->ietype = ietype;
    el->ielength = ielen;
    el->ieflags = *(ieptr + 3);
    el->iecontent = malloc(ielen);
    el->next = NULL;

    memcpy(el->iecontent, ieptr + 4, ielen);
    return el;
}

static inline gtp_infoelem_t *create_new_gtpv1_infoel(uint8_t ietype,
        uint16_t ielen, uint8_t *ieptr) {

    gtp_infoelem_t *el;

    el = (gtp_infoelem_t *)calloc(1, sizeof(gtp_infoelem_t));

    el->ietype = ietype;
    el->ielength = ielen;
    el->ieflags = 0;
    el->iecontent = malloc(ielen);
    el->next = NULL;

    if (ietype & 0x80) {
        memcpy(el->iecontent, ieptr + 3, ielen);
    } else {
        memcpy(el->iecontent, ieptr + 1, ielen);
    }
    return el;
}

static inline uint32_t get_teid_from_teidctl(gtp_infoelem_t *gtpel) {

    /* No flags byte in GTPv1 TEID */
    uint32_t *ptr = (uint32_t *)(gtpel->iecontent);
    return ntohl(*ptr);
}

static inline uint32_t get_teid_from_fteid(gtp_infoelem_t *gtpel) {

    /* Skip over first byte, which contains flags */
    uint32_t *ptr = (uint32_t *)(gtpel->iecontent + 1);

    /* Bytes 2-5 contain the TEID/GRE key */
    return ntohl(*ptr);
}

static inline uint8_t get_cause_from_ie(gtp_infoelem_t *gtpel) {

    return *((uint8_t *)(gtpel->iecontent));
}

static inline void get_gtpnum_from_ie(gtp_infoelem_t *gtpel, char *field,
        int skipfront) {

    /* IMSI is encoded in a weird way :( */
    uint8_t *ptr = (gtpel->iecontent + skipfront);
    int i, j;

    j = 0;
    for (i = 0; i < gtpel->ielength - skipfront; i++) {
        uint8_t num = *(ptr + i);
        field[j] = (char)('0' + (num & 0x0f));

        j++;

        /* bits 8-5 are 1111, which is a filler when there is an odd number
         * of digits.
         */
        if ((num & 0xf0) == 0xf0) {
            break;
        }

        field[j] = (char)('0' + ((num & 0xf0) >> 4));
        j++;
    }

    field[j] = '\0';
}

static inline uint16_t gtpv1_lookup_ielen(uint8_t ietype) {

    /* The fact that this function has to exist annoys me so much! */

    /* Ref: 3GPP TS 29.060 -- Information Elements table */
    switch (ietype) {
        case 1: return 1;
        case 2: return 8;
        case 3: return 6;
        case 4: return 4;
        case 5: return 4;
        case 8: return 1;
        case 9: return 28;
        case 11: return 1;
        case 12: return 3;
        case 13: return 1;
        case 14: return 1;
        case 15: return 1;
        case 16: return 4;
        case 17: return 4;
        case 18: return 5;
        case 19: return 1;
        case 20: return 1;
        case 21: return 1;
        case 22: return 9;
        case 23: return 1;
        case 24: return 1;
        case 25: return 2;
        case 26: return 2;
        case 27: return 2;
        case 28: return 2;
        case 29: return 1;
        case 127: return 4;
    }

    return 0;
}

static int walk_gtpv1_ies(gtp_parsed_t *parsedpkt, uint8_t *ptr, uint32_t rem,
        uint16_t gtplen) {

    uint16_t used = 0;

    while (rem > 2 && used < gtplen) {
        uint8_t ietype;
        uint16_t ielen;
        gtp_infoelem_t *gtpel = NULL;

        ietype = *ptr;

        if (ietype & 0x80) {
            /* IE is a TLV IE */
            ielen = ntohs(*((uint16_t *)(ptr + 1)));
        } else {
            /* IE is a TV IE */
            ielen = gtpv1_lookup_ielen(ietype);
        }

        if (ielen == 0) {
            logger(LOG_INFO,
                    "OpenLI: unable to determine IE length for GTPv1 IE %u.",
                    ietype);
            logger(LOG_INFO,
                    "OpenLI: aborting parsing of GTPv1 packet.",
                    ietype);
            return -1;
        }

        if (interesting_info_element(parsedpkt->version, ietype)) {
            gtpel = create_new_gtpv1_infoel(ietype, ielen, ptr);
            gtpel->next = parsedpkt->ies;
            parsedpkt->ies = gtpel;
        }

        if (gtpel) {
            if (parsedpkt->msgtype == GTPV1_CREATE_PDP_CONTEXT_REQUEST) {
                if (ietype == GTPV1_IE_TEID_CTRL) {
                    parsedpkt->teid = get_teid_from_teidctl(gtpel);
                }
                if (ietype == GTPV1_IE_IMSI) {
                    get_gtpnum_from_ie(gtpel, parsedpkt->imsi, 0);
                }
                if (ietype == GTPV1_IE_MSISDN) {
                    get_gtpnum_from_ie(gtpel, parsedpkt->msisdn, 1);
                }
            }

            if (ietype == GTPV1_IE_TEID_CTRL) {
                parsedpkt->teid_ctl = get_teid_from_teidctl(gtpel);
            }

            if (ietype == GTPV1_IE_CAUSE) {
                parsedpkt->response_cause = get_cause_from_ie(gtpel);
            }
        }

        if (ietype & 0x80) {
            ptr += (ielen + 3);
            used += (ielen + 3);
            rem -= (ielen + 3);
        } else {
            ptr += (ielen + 1);
            used += (ielen + 1);
            rem -= (ielen + 1);
        }
    }
    return 0;
}

static void walk_gtpv2_ies(gtp_parsed_t *parsedpkt, uint8_t *ptr, uint32_t rem,
        uint16_t gtplen) {

    uint16_t used = 0;

    while (rem > 4 && used < gtplen) {
        uint8_t ietype;
        uint16_t ielen;
        gtp_infoelem_t *gtpel;

        ietype = *ptr;
        ielen = ntohs(*((uint16_t *)(ptr + 1)));

        if (interesting_info_element(parsedpkt->version, ietype)) {
            gtpel = create_new_gtpv2_infoel(ietype, ielen, ptr);
            gtpel->next = parsedpkt->ies;
            parsedpkt->ies = gtpel;

            if (parsedpkt->msgtype == GTPV2_CREATE_SESSION_REQUEST) {
                if (ietype == GTPV2_IE_FTEID) {
                    parsedpkt->teid = get_teid_from_fteid(gtpel);
                }
                if (ietype == GTPV2_IE_IMSI) {
                    get_gtpnum_from_ie(gtpel, parsedpkt->imsi, 0);
                }
                if (ietype == GTPV2_IE_MEI) {
                    get_gtpnum_from_ie(gtpel, parsedpkt->imei, 0);
                }
                if (ietype == GTPV2_IE_MSISDN) {
                    get_gtpnum_from_ie(gtpel, parsedpkt->msisdn, 0);
                }
            } else if (parsedpkt->msgtype == GTPV2_DELETE_SESSION_REQUEST) {
                if (ietype == GTPV2_IE_FTEID) {
                    parsedpkt->teid = get_teid_from_fteid(gtpel);
                }
            }

            if (ietype == GTPV2_IE_CAUSE) {
                parsedpkt->response_cause = get_cause_from_ie(gtpel);
            }

        }

        ptr += (ielen + 4);
        used += (ielen + 4);
        rem -= (ielen + 4);
    }
}

static void flush_old_gtp_packets(gtp_global_t *glob, double ts) {

    Word_t index, rc;
    PWord_t pval;
    int purged = 0;

    index = 0;
    JLF(pval, glob->saved_packets, index);

    while (pval) {
        gtp_saved_pkt_t *pkt = (gtp_saved_pkt_t *)(*pval);

        if (ts > pkt->tvsec + GTP_FLUSH_OLD_PKT_FREQ) {
            gtp_free_ie_list(pkt->ies);
            if (pkt->ipcontent) {
                free(pkt->ipcontent);
            }
            JLD(rc, glob->saved_packets, pkt->reqid);
            free(pkt);
            purged ++;
        }
        JLN(pval, glob->saved_packets, index);
    }
}

static int gtp_parse_v2_teid(gtp_global_t *glob, libtrace_packet_t *pkt,
        uint8_t *gtpstart, uint32_t rem) {

    uint8_t *ptr;
    uint16_t len;

    gtpv2_header_teid_t *header = (gtpv2_header_teid_t *)gtpstart;

    if (rem < sizeof(gtpv2_header_teid_t)) {
        logger(LOG_INFO,
                "OpenLI: GTPv2 packet did not have a complete header");
        return -1;
    }

    len = ntohs(header->msglen);

    if (len + 4 > rem) {
        logger(LOG_INFO,
                "OpenLI: GTPv2 packet was truncated, some IEs may be missed.");
        logger(LOG_INFO,
                "OpenLI: GTPv2 length was %u, but we only had %u bytes of payload.",
                len, rem - 4);
    }

    glob->parsedpkt->origpkt = pkt;
    glob->parsedpkt->version = 2;
    glob->parsedpkt->msgtype = header->msgtype;
    glob->parsedpkt->teid = ntohl(header->teid);
    glob->parsedpkt->seqno = ntohl(header->seqno);  /* could >> 8 if need be */

    ptr = gtpstart + sizeof(gtpv2_header_teid_t);
    rem -= sizeof(gtpv2_header_teid_t);
    len -= (sizeof(gtpv2_header_teid_t) - 4);

    walk_gtpv2_ies(glob->parsedpkt, ptr, rem, len);

    return 0;
}

static int gtp_parse_v1_teid(gtp_global_t *glob, libtrace_packet_t *pkt,
        uint8_t *gtpstart, uint32_t rem) {

    uint8_t *ptr;
    uint16_t len;

    gtpv1_header_t *header = (gtpv1_header_t *)gtpstart;

    if (rem < sizeof(gtpv1_header_t)) {
        logger(LOG_INFO,
                "OpenLI: GTPv1 packet did not have a complete header");
        return -1;
    }

    len = ntohs(header->msglen);

    if (len + 8 > rem) {
        logger(LOG_INFO,
                "OpenLI: GTPv1 packet was truncated, some IEs may be missed.");
        logger(LOG_INFO,
                "OpenLI: GTPv1 length was %u, but we only had %u bytes of payload.",
                len, rem - 8);
    }

    glob->parsedpkt->origpkt = pkt;
    glob->parsedpkt->version = 1;
    glob->parsedpkt->msgtype = header->msgtype;
    glob->parsedpkt->teid = ntohl(header->teid);
    glob->parsedpkt->seqno = ntohs(header->seqno);

    ptr = gtpstart + sizeof(gtpv1_header_t);
    rem -= sizeof(gtpv1_header_t);
    len -= (sizeof(gtpv1_header_t) - 8);

    if (walk_gtpv1_ies(glob->parsedpkt, ptr, rem, len) < 0) {
        return -1;
    }

    return 0;
}

static void *gtp_parse_packet(access_plugin_t *p, libtrace_packet_t *pkt) {

    uint8_t *gtpstart;
    uint32_t rem;
    gtp_global_t *glob;
    void *l3 = NULL;
    uint16_t ethertype;

    glob = (gtp_global_t *)(p->plugindata);
    if (!glob) {
        return NULL;
    }

    if (glob->parsedpkt && glob->parsedpkt->msgtype != 0) {
        gtp_destroy_parsed_data(p, (void *)glob->parsedpkt);
    }

    l3 = trace_get_layer3(pkt, &ethertype, &rem);
    if (l3 == NULL) {
        return NULL;
    }

    gtpstart = (uint8_t *)get_udp_payload(pkt, &rem, NULL, NULL);
    if (gtpstart == NULL) {
        return NULL;
    }

    /* Check GTP version */
    if (((*gtpstart) & 0xe8) == 0x48) {
        /* GTPv2 with TEID */
        if (gtp_parse_v2_teid(glob, pkt, gtpstart, rem) < 0) {
            return NULL;
        }

    } else if (((*gtpstart) & 0xe0) == 0x20) {
        /* GTPv1 */
        if (gtp_parse_v1_teid(glob, pkt, gtpstart, rem) < 0) {
            return NULL;
        }
    } else {
        /* TODO GTPv2 without TEID */
        //return NULL;
    }

    if (ethertype == TRACE_ETHERTYPE_IP) {
        libtrace_ip_t *ip = (libtrace_ip_t *)l3;

        glob->parsedpkt->serveripfamily = 4;

        switch(glob->parsedpkt->msgtype) {
            case GTPV2_CREATE_SESSION_REQUEST:
            case GTPV2_DELETE_SESSION_REQUEST:
            case GTPV1_CREATE_PDP_CONTEXT_REQUEST:
            case GTPV1_UPDATE_PDP_CONTEXT_REQUEST:
            case GTPV1_DELETE_PDP_CONTEXT_REQUEST:
                memcpy(glob->parsedpkt->serverid, &(ip->ip_dst.s_addr), 4);
                break;
            case GTPV2_CREATE_SESSION_RESPONSE:
            case GTPV2_DELETE_SESSION_RESPONSE:
            case GTPV1_CREATE_PDP_CONTEXT_RESPONSE:
            case GTPV1_UPDATE_PDP_CONTEXT_RESPONSE:
            case GTPV1_DELETE_PDP_CONTEXT_RESPONSE:
                memcpy(glob->parsedpkt->serverid, &(ip->ip_src.s_addr), 4);
                break;
            default:
                glob->parsedpkt->serveripfamily = 0;
                break;
        }
    } else if (ethertype == TRACE_ETHERTYPE_IPV6) {
        libtrace_ip6_t *ip6 = (libtrace_ip6_t *)l3;

        glob->parsedpkt->serveripfamily = 6;

        switch(glob->parsedpkt->msgtype) {
            case GTPV2_CREATE_SESSION_REQUEST:
            case GTPV2_DELETE_SESSION_REQUEST:
            case GTPV1_CREATE_PDP_CONTEXT_REQUEST:
            case GTPV1_UPDATE_PDP_CONTEXT_REQUEST:
            case GTPV1_DELETE_PDP_CONTEXT_REQUEST:
                memcpy(glob->parsedpkt->serverid, &(ip6->ip_dst.s6_addr),
                        16);
                break;
            case GTPV2_CREATE_SESSION_RESPONSE:
            case GTPV2_DELETE_SESSION_RESPONSE:
            case GTPV1_CREATE_PDP_CONTEXT_RESPONSE:
            case GTPV1_UPDATE_PDP_CONTEXT_RESPONSE:
            case GTPV1_DELETE_PDP_CONTEXT_RESPONSE:
                memcpy(glob->parsedpkt->serverid, &(ip6->ip_src.s6_addr),
                        16);
                break;
            default:
                glob->parsedpkt->serveripfamily = 0;
                break;
        }
    }

    glob->parsedpkt->tvsec = trace_get_seconds(pkt);

    if (glob->lastrefresh == 0) {
        glob->lastrefresh = (uint32_t)glob->parsedpkt->tvsec;
    }

    if (glob->parsedpkt->tvsec - glob->lastrefresh > GTP_FLUSH_OLD_PKT_FREQ) {
        flush_old_gtp_packets(glob, glob->parsedpkt->tvsec);
        glob->lastrefresh = (uint32_t)glob->parsedpkt->tvsec;
    }

    if (glob->parsedpkt->serveripfamily == 0) {
        return glob->parsedpkt;
    }

    return glob->parsedpkt;
}

static inline user_identity_t *copy_identifiers(gtp_parsed_t *gparsed,
        int *numberids) {

    int x = 0;
    user_identity_t *uids;

    uids = calloc(3, sizeof(user_identity_t));

    if (gparsed->matched_session->idstr_msisdn[0] != '\0') {
        uids[x].method = USER_IDENT_GTP_MSISDN;
        uids[x].idstr = strdup(gparsed->matched_session->idstr_msisdn);
        uids[x].idlength = gparsed->matched_session->idstr_msisdn_len;
        *numberids += 1;
        x ++;
    }
    if (gparsed->matched_session->idstr_imsi[0] != '\0') {
        uids[x].method = USER_IDENT_GTP_IMSI;
        uids[x].idstr = strdup(gparsed->matched_session->idstr_imsi);
        uids[x].idlength = gparsed->matched_session->idstr_imsi_len;
        *numberids += 1;
        x ++;
    }
    if (gparsed->matched_session->idstr_imei[0] != '\0') {
        uids[x].method = USER_IDENT_GTP_IMEI;
        uids[x].idstr = strdup(gparsed->matched_session->idstr_imei);
        uids[x].idlength = gparsed->matched_session->idstr_imei_len;
        *numberids += 1;
        x ++;
    }
    return uids;
}

static void save_identifier_strings(gtp_parsed_t *gparsed, gtp_session_t *sess)
{
    if (gparsed->msisdn[0] != '\0') {
        snprintf(sess->idstr_msisdn, 64, "%s", gparsed->msisdn);
        sess->idstr_msisdn_len = strlen(sess->idstr_msisdn);
    } else {
        sess->idstr_msisdn_len = 0;
    }
    if (gparsed->imsi[0] != '\0') {
        snprintf(sess->idstr_imsi, 64, "%s", gparsed->imsi);
        sess->idstr_imsi_len = strlen(sess->idstr_imsi);
    } else {
        sess->idstr_imsi_len = 0;
    }
    if (gparsed->imei[0] != '\0') {
        snprintf(sess->idstr_imei, 64, "%s", gparsed->imei);
        sess->idstr_imei_len = strlen(sess->idstr_imei);
    } else {
        sess->idstr_imei_len = 0;
    }
}

#define GEN_SESSID(sessid, gparsed, teid) \
    if (gparsed->serveripfamily == 4) { \
        snprintf(sessid, 64, "%u-%u", *(uint32_t *)gparsed->serverid, teid); \
    } else if (gparsed->serveripfamily == 6) { \
        snprintf(sessid, 64, "%lu-%lu-%u", *(uint64_t *)gparsed->serverid, \
                *(uint64_t *)(gparsed->serverid + 8), teid); \
    }

static user_identity_t *gtp_get_userid(access_plugin_t *p, void *parsed,
        int *numberids) {

    gtp_global_t *glob = (gtp_global_t *)(p->plugindata);
    gtp_parsed_t *gparsed = (gtp_parsed_t *)parsed;
    unsigned char sessid[64];
    unsigned char alt_sessid[64];
    gtp_session_t *sess;
    PWord_t pval;
    user_identity_t *uids;
    Pvoid_t search;

    if (glob == NULL || gparsed == NULL) {
        return NULL;
    }

    if (gparsed->serveripfamily != 4 && gparsed->serveripfamily != 6) {
        return NULL;
    }

    if (gparsed->matched_session) {
        uids = copy_identifiers(gparsed, numberids);
        return uids;
    }

    /* Need to look up the session */
    GEN_SESSID((char *)sessid, gparsed, gparsed->teid);

    if (gparsed->msgtype == GTPV1_DELETE_PDP_CONTEXT_REQUEST) {
        search = glob->alt_session_map;
    } else {
        search = glob->session_map;
    }

    JSLG(pval, search, sessid);

    if (pval) {
        gparsed->matched_session = (gtp_session_t *)(*pval);

        if (gparsed->matched_session->idstr_msisdn_len == 0 &&
                gparsed->msisdn[0] != '\0') {
            save_identifier_strings(gparsed, gparsed->matched_session);
        }

        if (search == glob->alt_session_map) {
            gparsed->teid = gparsed->matched_session->teid;
        }

        /* v1 delete requests use the teid_cp from the create response
         * as their TEID, so we need to have a reference to this session
         * for that TEID as well. Otherwise we'll miss the delete requests.
         */
        if (gparsed->msgtype == GTPV1_CREATE_PDP_CONTEXT_RESPONSE) {
            GEN_SESSID((char *)alt_sessid, gparsed, gparsed->teid_ctl);
            JSLG(pval, glob->alt_session_map, alt_sessid);

            if (!pval) {
                JSLI(pval, glob->alt_session_map, alt_sessid);
                *pval = (Word_t)gparsed->matched_session;
            }

        }

        uids = copy_identifiers(gparsed, numberids);
        return uids;
    }

    if (gparsed->msgtype != GTPV2_CREATE_SESSION_REQUEST &&
            gparsed->msgtype != GTPV1_CREATE_PDP_CONTEXT_REQUEST) {
        gtp_saved_pkt_t *saved;

        saved = calloc(1, sizeof(gtp_saved_pkt_t));

        saved->type = gparsed->msgtype;
        saved->reqid = (((uint64_t)gparsed->teid) << 32) |
            ((uint64_t)gparsed->seqno);
        saved->ies = gparsed->ies;
        saved->version = gparsed->version;
        saved->matched_session = NULL;
        saved->applied = 0;
        saved->tvsec = gparsed->tvsec;
        saved->ipcontent = NULL;
        saved->iplen = 0;
        saved->response_cause = gparsed->response_cause;
        gparsed->ies = NULL;

        openli_copy_ipcontent(gparsed->origpkt, &(saved->ipcontent),
                &(saved->iplen));

        JLG(pval, glob->saved_packets, saved->reqid);
        if (pval == NULL) {
            JLI(pval, glob->saved_packets, saved->reqid);
            *pval = (Word_t)saved;
        } else {
            gparsed->ies = saved->ies;
            if (saved->ipcontent) {
                free(saved->ipcontent);
            }
            free(saved);
        }
        return NULL;
    }

    sess = calloc(1, sizeof(gtp_session_t));
    sess->sessid = strdup((char *)sessid);
    sess->current = SESSION_STATE_NEW;
    sess->teid = gparsed->teid;
    sess->pdpaddrs = NULL;
    sess->pdpaddrcount = 0;

    memcpy(sess->serverid, gparsed->serverid, 16);
    sess->serveripfamily = gparsed->serveripfamily;

    JSLI(pval, glob->session_map, (unsigned char *)sess->sessid);
    *pval = (Word_t)sess;

    gparsed->matched_session = sess;
    save_identifier_strings(gparsed, sess);

    uids = copy_identifiers(gparsed, numberids);
    return uids;
}

static void extract_gtp_assigned_ip_address(gtp_saved_pkt_t *gpkt,
        access_session_t *sess, gtp_session_t *gsess) {

    gtp_infoelem_t *ie;

    if (!gsess) {
        return;
    }

    ie = gpkt->ies;
    while (ie) {
        if (gpkt->version == 2 && ie->ietype == GTPV2_IE_PDN_ALLOC) {
            if (*((uint8_t *)(ie->iecontent)) == 0x01) {
                /* IPv4 */
                add_new_session_ip(sess, ie->iecontent + 1, AF_INET, 32,
                        ie->ielength - 1);

                /* These weird numbers are derived from bytes 3 and 4 of
                 * the Packet Data Protocol Address IE defined in
                 * 3GPP TS 24.008
                 *
                 * 0x01 = IETF assigned address
                 * 0x21 = IPv4 address
                 * 0x57 = IPv6 address
                 * 0x8d = IPv4v6 address
                 */
                gsess->pdptype = htons(0x0121);

            } else if (*((uint8_t *)(ie->iecontent)) == 0x02) {
                /* IPv6 */
                add_new_session_ip(sess, ie->iecontent + 1, AF_INET6, 128,
                        ie->ielength - 1);
                gsess->pdptype = htons(0x0157);
            } else if (*((uint8_t *)(ie->iecontent)) == 0x03) {
                /* IPv4 AND IPv6 */

                /* TODO support multiple sessionips per session */
                add_new_session_ip(sess, ie->iecontent + 1, AF_INET6, 128,
                        ie->ielength - 1);

                gsess->pdptype = htons(0x018d);
            } else {
                break;
            }

            gsess->pdpaddrs = sess->sessionips;
            gsess->pdpaddrcount = sess->sessipcount;
            break;
        }

        if (gpkt->version == 1 && ie->ietype == GTPV1_IE_END_USER_ADDRESS) {
            uint16_t pdptype = ntohs(*((uint16_t *)(ie->iecontent)));

            if ((pdptype & 0x0fff) == 0x0121 && ie->ielength >= 6) {
                /* IPv4 */
                add_new_session_ip(sess, ie->iecontent + 2, AF_INET, 32,
                        ie->ielength - 2);
                gsess->pdptype = htons(0x0121);
            } else if ((pdptype & 0x0fff) == 0x0157 && ie->ielength >= 18) {
                /* IPv6 */
                add_new_session_ip(sess, ie->iecontent + 2, AF_INET6, 128,
                        ie->ielength - 2);
                gsess->pdptype = htons(0x0157);
            }
            gsess->pdpaddrs = sess->sessionips;
            gsess->pdpaddrcount = sess->sessipcount;
            break;
        }

        ie = ie->next;
    }


}

static uint32_t assign_gtp_cin(uint32_t teid) {

    /* Hopefully this changes for different sessions for the same user */
    /* XXX maybe we need to account for the GTP server IP as well? */
    if (teid != 0) {
        return teid % (uint32_t)(pow(2, 31));
    } else {

        /* If we don't have a useful TEID for some reason, fall back to
         * using time of day */
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return (tv.tv_sec % (uint32_t)(pow(2, 31)));
    }

    return 0;
}

#define COPY_SESSION_PARAM(p, plen, attr, alen) \
    if (p) free(p); \
    p = calloc(1, alen + 1); \
    plen = alen; \
    memcpy(p, attr, alen);


static void copy_session_params_v1(gtp_parsed_t *gparsed,
        gtp_saved_pkt_t *gpkt) {

    gtp_session_t *gsess = gparsed->matched_session;
    gtp_infoelem_t *el;

    el = gpkt->ies;
    while (el) {
        uint8_t *attrptr = (uint8_t *)el->iecontent;
        uint16_t attrlen = el->ielength;

        switch(el->ietype) {
            case GTPV1_IE_IMSI:
                COPY_SESSION_PARAM(gsess->saved.imsi, gsess->saved.imsi_len,
                        attrptr, attrlen);
                break;
            case GTPV1_IE_MSISDN:
                COPY_SESSION_PARAM(gsess->saved.msisdn, gsess->saved.msisdn_len,
                        attrptr + 1, attrlen - 1);
                break;
            case GTPV1_IE_MEI:
                COPY_SESSION_PARAM(gsess->saved.imei, gsess->saved.imei_len,
                        attrptr, attrlen);
                break;
            case GTPV1_IE_APNAME:
                COPY_SESSION_PARAM(gsess->saved.apname, gsess->saved.apname_len,
                        attrptr, attrlen);
                break;
            case GTPV1_IE_ULI:
                COPY_SESSION_PARAM(gsess->saved.location,
                        gsess->saved.location_len, attrptr, attrlen);
                gsess->saved.loc_version = 1;
                break;
        }

        el = el->next;
    }
}

static void copy_session_params_v2(gtp_parsed_t *gparsed,
        gtp_saved_pkt_t *gpkt) {

    gtp_session_t *gsess = gparsed->matched_session;
    gtp_infoelem_t *el;

    el = gpkt->ies;
    while (el) {
        uint8_t *attrptr = (uint8_t *)el->iecontent;
        uint16_t attrlen = el->ielength;

        switch(el->ietype) {
            case GTPV2_IE_IMSI:
                COPY_SESSION_PARAM(gsess->saved.imsi, gsess->saved.imsi_len,
                        attrptr, attrlen);
                break;
            case GTPV2_IE_MSISDN:
                COPY_SESSION_PARAM(gsess->saved.msisdn, gsess->saved.msisdn_len,
                        attrptr, attrlen);
                break;
            case GTPV2_IE_MEI:
                COPY_SESSION_PARAM(gsess->saved.imei, gsess->saved.imei_len,
                        attrptr, attrlen);
                break;
            case GTPV2_IE_APNAME:
                COPY_SESSION_PARAM(gsess->saved.apname, gsess->saved.apname_len,
                        attrptr, attrlen);
                break;
            case GTPV2_IE_ULI:
                COPY_SESSION_PARAM(gsess->saved.location,
                        gsess->saved.location_len, attrptr, attrlen);
                gsess->saved.loc_version = 2;
                break;

        }

        el = el->next;
    }
}

static void apply_gtp_fsm_logic(gtp_parsed_t *gparsed, access_action_t *action,
        access_session_t *sess, gtp_saved_pkt_t *gpkt,
        session_state_t current) {

    if (gpkt->version == 1) {
        copy_session_params_v1(gparsed, gpkt);
    } else {
        copy_session_params_v2(gparsed, gpkt);
    }

    if (current == SESSION_STATE_NEW &&
            (gpkt->type == GTPV2_CREATE_SESSION_REQUEST ||
             gpkt->type == GTPV1_CREATE_PDP_CONTEXT_REQUEST)) {

        current = SESSION_STATE_AUTHING;
        *action = ACCESS_ACTION_NONE;

    } else if (current == SESSION_STATE_AUTHING &&
            gpkt->type == GTPV2_CREATE_SESSION_RESPONSE) {

        if (gpkt->response_cause == 0x10) {
            current = SESSION_STATE_ACTIVE;
            *action = ACCESS_ACTION_ACCEPT;

            extract_gtp_assigned_ip_address(gpkt, sess,
                    gparsed->matched_session);

        } else if (gpkt->response_cause >= 64 && gpkt->response_cause <= 239) {
            current = SESSION_STATE_OVER;
            *action = ACCESS_ACTION_REJECT;
        }
    } else if (current == SESSION_STATE_AUTHING &&
            gpkt->type == GTPV1_CREATE_PDP_CONTEXT_RESPONSE) {

        if (gpkt->response_cause == 128) {
            current = SESSION_STATE_ACTIVE;
            *action = ACCESS_ACTION_ACCEPT;

            extract_gtp_assigned_ip_address(gpkt, sess,
                    gparsed->matched_session);
        } else if (gpkt->response_cause >= 192 && gpkt->response_cause <= 255) {
            current = SESSION_STATE_OVER;
            *action = ACCESS_ACTION_REJECT;
        }

    } else if (current == SESSION_STATE_ACTIVE &&
            (gpkt->type == GTPV2_DELETE_SESSION_REQUEST ||
             gpkt->type == GTPV1_DELETE_PDP_CONTEXT_REQUEST)) {
        current = SESSION_STATE_ENDING;
        *action = ACCESS_ACTION_NONE;
    } else if (current == SESSION_STATE_ENDING &&
            (gpkt->type == GTPV2_DELETE_SESSION_RESPONSE ||
             gpkt->type == GTPV1_DELETE_PDP_CONTEXT_RESPONSE)) {
        current = SESSION_STATE_OVER;
        *action = ACCESS_ACTION_END;
    } else if (current == SESSION_STATE_ACTIVE &&
            (gpkt->type == GTPV1_UPDATE_PDP_CONTEXT_RESPONSE)) {
        *action = ACCESS_ACTION_INTERIM_UPDATE;
    }

    gparsed->matched_session->current = current;

}

static inline access_session_t *find_matched_session(access_plugin_t *p,
        access_session_t **sesslist, gtp_session_t *match, uint32_t teid) {

    access_session_t *thissess = NULL;

    if (match == NULL) {
        return NULL;
    }

    HASH_FIND(hh, *sesslist, match->sessid, strlen(match->sessid), thissess);

    if (!thissess) {
        thissess = create_access_session(p, match->sessid,
                strlen(match->sessid));
        thissess->cin = assign_gtp_cin(teid);
        match->cin = thissess->cin;

        HASH_ADD_KEYPTR(hh, *sesslist, thissess->sessionid,
                strlen(thissess->sessionid), thissess);
    }
    return thissess;
}

static access_session_t *gtp_update_session_state(access_plugin_t *p,
        void *parsed, void *plugindata, access_session_t **sesslist,
        session_state_t *oldstate, session_state_t *newstate,
        access_action_t *action) {

    gtp_global_t *glob = (gtp_global_t *)(p->plugindata);
    access_session_t *thissess = NULL;
    gtp_saved_pkt_t *saved, *check;
    gtp_parsed_t *gparsed = (gtp_parsed_t *)parsed;
    PWord_t pval;
    Word_t rcint;
    uint64_t reqid = (((uint64_t)gparsed->teid) << 32) |
            ((uint64_t)gparsed->seqno);


    if (reqid == gparsed->matched_session->last_reqid &&
            gparsed->msgtype == gparsed->matched_session->last_reqtype) {

        /* Do NOT save the packet, because we've already saved it when
         * this method was called on a previous identity found in
         * the packet.
         */
        thissess = find_matched_session(p, sesslist, gparsed->matched_session,
                gparsed->teid);
        *oldstate = gparsed->matched_session->savedoldstate;
        apply_gtp_fsm_logic(gparsed, action, thissess,
                        gparsed->matched_session->lastsavedpkt,
                        gparsed->matched_session->savedoldstate);

        *newstate = gparsed->matched_session->savednewstate;
        return thissess;
    }

    saved = calloc(1, sizeof(gtp_saved_pkt_t));

    saved->type = gparsed->msgtype;
    saved->reqid = reqid;
    saved->ies = gparsed->ies;
    saved->version = gparsed->version;
    saved->matched_session = gparsed->matched_session;
    saved->applied = 0;
    saved->tvsec = gparsed->tvsec;
    saved->ipcontent = NULL;
    saved->iplen = 0;
    saved->response_cause = gparsed->response_cause;

    gparsed->ies = NULL;
    gparsed->matched_session->last_reqid = reqid;
    gparsed->matched_session->last_reqtype = gparsed->msgtype;
    gparsed->matched_session->lastsavedpkt = saved;

    openli_copy_ipcontent(gparsed->origpkt, &(saved->ipcontent),
            &(saved->iplen));

    JLG(pval, glob->saved_packets, saved->reqid);
    if (pval == NULL) {
        JLI(pval, glob->saved_packets, saved->reqid);
        *pval = (Word_t)saved;

        if (gparsed->msgtype == GTPV2_CREATE_SESSION_REQUEST ||
                gparsed->msgtype == GTPV2_DELETE_SESSION_REQUEST ||
                gparsed->msgtype == GTPV1_CREATE_PDP_CONTEXT_REQUEST ||
                gparsed->msgtype == GTPV1_DELETE_PDP_CONTEXT_REQUEST) {

            thissess = find_matched_session(p, sesslist,
                    gparsed->matched_session, gparsed->teid);
            if (thissess) {
                *oldstate = gparsed->matched_session->current;
                gparsed->matched_session->savedoldstate = *oldstate;
                apply_gtp_fsm_logic(gparsed, &(gparsed->action), thissess,
                        saved, *oldstate);
                *newstate = gparsed->matched_session->current;
                gparsed->matched_session->savednewstate = *newstate;
                saved->applied = 1;
            }
        }

    } else {
        check = (gtp_saved_pkt_t *)*pval;

        JLD(rcint, glob->saved_packets, check->reqid);

        if (saved->type == GTPV2_CREATE_SESSION_REQUEST &&
                check->type == GTPV2_CREATE_SESSION_RESPONSE) {

            gparsed->request = saved;
            gparsed->response = check;

        } else if (check->type == GTPV2_CREATE_SESSION_REQUEST &&
                saved->type == GTPV2_CREATE_SESSION_RESPONSE) {
            gparsed->request = check;
            gparsed->response = saved;
        } else if (saved->type == GTPV2_DELETE_SESSION_REQUEST &&
                check->type == GTPV2_DELETE_SESSION_RESPONSE) {
            gparsed->request = saved;
            gparsed->response = check;
        } else if (check->type == GTPV2_DELETE_SESSION_REQUEST &&
                saved->type == GTPV2_DELETE_SESSION_RESPONSE) {
            gparsed->request = check;
            gparsed->response = saved;
        } else if (saved->type == GTPV1_CREATE_PDP_CONTEXT_REQUEST &&
                check->type == GTPV1_CREATE_PDP_CONTEXT_RESPONSE) {

            gparsed->request = saved;
            gparsed->response = check;

        } else if (check->type == GTPV1_CREATE_PDP_CONTEXT_REQUEST &&
                saved->type == GTPV1_CREATE_PDP_CONTEXT_RESPONSE) {
            gparsed->request = check;
            gparsed->response = saved;
        } else if (saved->type == GTPV1_DELETE_PDP_CONTEXT_REQUEST &&
                check->type == GTPV1_DELETE_PDP_CONTEXT_RESPONSE) {
            gparsed->request = saved;
            gparsed->response = check;
        } else if (check->type == GTPV1_DELETE_PDP_CONTEXT_REQUEST &&
                saved->type == GTPV1_DELETE_PDP_CONTEXT_RESPONSE) {
            gparsed->request = check;
            gparsed->response = saved;
        } else if (saved->type == GTPV1_UPDATE_PDP_CONTEXT_REQUEST &&
                check->type == GTPV1_UPDATE_PDP_CONTEXT_RESPONSE) {
            gparsed->request = saved;
            gparsed->response = check;
        } else if (check->type == GTPV1_UPDATE_PDP_CONTEXT_REQUEST &&
                saved->type == GTPV1_UPDATE_PDP_CONTEXT_RESPONSE) {
            gparsed->request = check;
            gparsed->response = saved;
        } else if (saved->type == check->type) {
            /* probably a re-transmit */
            JLI(pval, glob->saved_packets, saved->reqid);
            *pval = (Word_t)saved;

            if (check->ipcontent) {
                free(check->ipcontent);
            }
            gtp_free_ie_list(check->ies);
            free(check);
            return NULL;
        } else {
            logger(LOG_INFO, "OpenLI: unexpected GTP packet pair (saved=%u, check=%u) for reqid %lu", saved->type, check->type, saved->reqid);
            gparsed->request = check;
            gparsed->response = saved;
        }

        if (gparsed->request->matched_session) {
            thissess = find_matched_session(p, sesslist,
                    gparsed->request->matched_session, gparsed->teid);
            *oldstate = gparsed->request->matched_session->current;
            gparsed->matched_session = gparsed->request->matched_session;
            gparsed->matched_session->savedoldstate = *oldstate;
        } else if (gparsed->response->matched_session) {
            thissess = find_matched_session(p, sesslist,
                    gparsed->response->matched_session, gparsed->teid);
            *oldstate = gparsed->response->matched_session->current;
            gparsed->matched_session = gparsed->response->matched_session;
            gparsed->matched_session->savedoldstate = *oldstate;
        }

        if (thissess) {
            if (gparsed->request->applied == 0) {
                apply_gtp_fsm_logic(gparsed, &(gparsed->action), thissess,
                        gparsed->request, gparsed->matched_session->current);
            }
            if (gparsed->response->applied == 0) {
                apply_gtp_fsm_logic(gparsed, &(gparsed->action), thissess,
                        gparsed->response, gparsed->matched_session->current);
            }
        }
        *newstate = gparsed->matched_session->current;
        gparsed->matched_session->savednewstate = *newstate;
    }

    *action = gparsed->action;
    return thissess;
}

static void parse_uli_v1(uint8_t *locinfo,
        etsili_generic_freelist_t *freelist, etsili_generic_t **params) {

    etsili_generic_t *np;
    uint8_t uliflags;
    uint8_t *ptr;

    uliflags = *locinfo;
    ptr = locinfo + 1;

    if (uliflags == 0) {
        np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_CGI, 7,
                ptr);
        HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);
    } else if (uliflags == 1) {
        np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_SAI, 7,
                ptr);
        HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);
    }

}

static void parse_uli_v2(uint8_t *locinfo,
        etsili_generic_freelist_t *freelist, etsili_generic_t **params) {

    etsili_generic_t *np;
    uint8_t uliflags;
    uint8_t *ptr;

    uliflags = *locinfo;

    /* TODO implement CGID, SAI, RAI */
    ptr = locinfo + 1;

    if (uliflags & 0x01) {
        /* CGID */
        ptr += 7;
    }

    if (uliflags & 0x02) {
        /* SAI */
        ptr += 7;
    }

    if (uliflags & 0x04) {
        /* RAI */
        ptr += 7;
    }

    if (uliflags & 0x08) {
        /* TAI */
        uint8_t taispace[6];

        taispace[0] = 5;
        memcpy(taispace + 1, ptr, 5);
        np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_TAI,
                6, taispace);
        HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);
        ptr += 5;
    }

    if (uliflags & 0x10) {
        /* ECGI */
        uint8_t ecgispace[8];
        ecgispace[0] = 7;
        memcpy(ecgispace + 1, ptr, 7);
        np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_ECGI,
                8, ecgispace);
        HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);
        ptr += 7;
    }

}

static int gtp_create_pdp_generic_iri(gtp_parsed_t *gparsed,
        gtp_session_t *gsess,
        etsili_generic_t **params, etsili_generic_freelist_t *freelist,
        uint32_t evtype) {

    etsili_generic_t *np;
    etsili_ipaddress_t ipaddr;
    uint32_t initiator = 1;
    struct timeval tv;

    if (gsess->serveripfamily == 4) {
        etsili_create_ipaddress_v4((uint32_t *)(gsess->serverid),
                ETSILI_IPV4_SUBNET_UNKNOWN, ETSILI_IPADDRESS_ASSIGNED_UNKNOWN,
                &ipaddr);
    } else {
        etsili_create_ipaddress_v6((uint8_t *)(gsess->serverid),
                ETSILI_IPV6_SUBNET_UNKNOWN, ETSILI_IPADDRESS_ASSIGNED_UNKNOWN,
                &ipaddr);
    }

    np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_GGSN_IPADDRESS,
        sizeof(etsili_ipaddress_t), (uint8_t *)&ipaddr);
    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);

    np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_IMSI,
        gsess->saved.imsi_len, (uint8_t *)gsess->saved.imsi);
    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);

    np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_IMEI,
        gsess->saved.imei_len, (uint8_t *)gsess->saved.imei);
    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);

    np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_MSISDN,
        gsess->saved.msisdn_len, (uint8_t *)gsess->saved.msisdn);
    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);

    np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_APNAME,
        gsess->saved.apname_len, (uint8_t *)gsess->saved.apname);
    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);

    /* TODO encode all PDP addresses according to the standards */
    if (gsess->pdpaddrcount > 0) {
        if (gsess->pdpaddrs[0].ipfamily == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)
                    &(gsess->pdpaddrs[0].assignedip);

            etsili_create_ipaddress_v4((uint32_t *)&(sin->sin_addr.s_addr),
                    ETSILI_IPV4_SUBNET_UNKNOWN,
                    ETSILI_IPADDRESS_ASSIGNED_DYNAMIC,
                    &ipaddr);
        } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)
                    &(gsess->pdpaddrs[0].assignedip);

            etsili_create_ipaddress_v6((uint8_t *)(sin6->sin6_addr.s6_addr),
                    ETSILI_IPV6_SUBNET_UNKNOWN,
                    ETSILI_IPADDRESS_ASSIGNED_DYNAMIC,
                    &ipaddr);
        }
    }

    np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_PDP_ADDRESS,
            sizeof(etsili_ipaddress_t), (uint8_t *)&ipaddr);
    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum),
            np);

    np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_PDPTYPE,
            sizeof(uint16_t), (uint8_t *)&(gsess->pdptype));
    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum),
            np);

    np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_EVENT_TYPE,
            sizeof(uint32_t), (uint8_t *)&(evtype));
    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum),
            np);

    np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_INITIATOR,
            sizeof(uint32_t), (uint8_t *)&(initiator));
    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum),
            np);

    if (gparsed) {
        TIMESTAMP_TO_TV((&tv), gparsed->response->tvsec);
        np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_EVENT_TIME,
                sizeof(struct timeval), (uint8_t *)(&tv));
        HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum),
                np);

        TIMESTAMP_TO_TV((&tv), gparsed->request->tvsec);
        np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_LOCATION_TIME,
                sizeof(struct timeval), (uint8_t *)(&tv));
        HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum),
                np);
    } else {
        gettimeofday(&tv, NULL);
        np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_EVENT_TIME,
                sizeof(struct timeval), (uint8_t *)(&tv));
        HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum),
                np);

        np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_LOCATION_TIME,
                sizeof(struct timeval), (uint8_t *)(&tv));
        HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum),
                np);
    }

    if (gsess->saved.location) {
        if (gsess->saved.loc_version == 1) {
            parse_uli_v1(gsess->saved.location, freelist, params);
        } else if (gsess->saved.loc_version == 2) {
            parse_uli_v2(gsess->saved.location, freelist, params);
        }
    }

    np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_GPRS_CORRELATION,
            sizeof(int64_t), (uint8_t *)(&(gsess->cin)));
    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum),
            np);

    return 0;

}

static inline uint8_t gtpv2_cause_to_sm(uint8_t *gtpcause) {

    switch(*gtpcause) {
        case GTPV2_CAUSE_REQUEST_ACCEPTED:
            return SM_CAUSE_REGULAR_DEACTIVATION;
    }

    return 0;
}

static inline uint8_t gtpv1_cause_to_sm(uint8_t *gtpcause) {

    switch(*gtpcause) {
        case GTPV1_CAUSE_REQUEST_ACCEPTED:
            return SM_CAUSE_REGULAR_DEACTIVATION;
    }

    return 0;
}

static int gtp_create_context_deactivation_iri(gtp_parsed_t *gparsed,
        etsili_generic_t **params, etsili_generic_freelist_t *freelist) {

    uint32_t evtype = UMTSIRI_EVENT_TYPE_PDPCONTEXT_DEACTIVATION;
    gtp_infoelem_t *el;
    etsili_generic_t *np;

    gtp_create_pdp_generic_iri(gparsed, gparsed->matched_session,
            params, freelist, evtype);

    el = gparsed->response->ies;
    while (el) {
        uint8_t ieattr = 0;
        uint8_t *attrptr = (uint8_t *)el->iecontent;
        uint16_t attrlen = el->ielength;

        switch(el->ietype) {
            case GTPV2_IE_CAUSE: {
                uint8_t smcauseval = gtpv2_cause_to_sm(attrptr);
                if (smcauseval != 0) {
                    np = create_etsili_generic(freelist,
                            UMTSIRI_CONTENTS_GPRS_ERROR_CODE,
                            sizeof(uint8_t), &(smcauseval));
                    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum),
                            sizeof(np->itemnum), np);
                }
                break;
            }
            case GTPV1_IE_CAUSE: {
                uint8_t smcauseval = gtpv1_cause_to_sm(attrptr);
                if (smcauseval != 0) {
                    np = create_etsili_generic(freelist,
                            UMTSIRI_CONTENTS_GPRS_ERROR_CODE,
                            sizeof(uint8_t), &(smcauseval));
                    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum),
                            sizeof(np->itemnum), np);
                }
                break;
            }

        }

        if (ieattr != 0) {
            np = create_etsili_generic(freelist, ieattr, attrlen, attrptr);
            HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum),
                    np);
        }

        el = el->next;
    }

    return 0;
}

static int gtp_create_context_modification_iri(gtp_parsed_t *gparsed,
        etsili_generic_t **params, etsili_generic_freelist_t *freelist) {

    uint32_t evtype = UMTSIRI_EVENT_TYPE_PDPCONTEXT_MODIFICATION;

    gtp_create_pdp_generic_iri(gparsed, gparsed->matched_session,
            params, freelist, evtype);

    return 0;
}


static int gtp_create_start_with_context_active_iri(gtp_session_t *gsess,
        etsili_generic_t **params, etsili_generic_freelist_t *freelist) {

    uint32_t evtype = UMTSIRI_EVENT_TYPE_START_WITH_PDPCONTEXT_ACTIVE;

    gtp_create_pdp_generic_iri(NULL, gsess, params, freelist, evtype);

    return 0;
}

static int gtp_create_context_activation_iri(gtp_parsed_t *gparsed,
        etsili_generic_t **params, etsili_generic_freelist_t *freelist) {

    uint32_t evtype = UMTSIRI_EVENT_TYPE_PDPCONTEXT_ACTIVATION;

    gtp_create_pdp_generic_iri(gparsed, gparsed->matched_session,
            params, freelist, evtype);

    return 0;
}

static int gtp_generate_iri_data(access_plugin_t *p, void *parseddata,
        etsili_generic_t **params, etsili_iri_type_t *iritype,
        etsili_generic_freelist_t *freelist, int iteration) {

    gtp_parsed_t *gparsed = (gtp_parsed_t *)parseddata;

    if (gparsed->action == ACCESS_ACTION_ACCEPT) {
        *iritype = ETSILI_IRI_BEGIN;
        if (gtp_create_context_activation_iri(gparsed, params,
                freelist) < 0) {
            return -1;
        }
        return 0;
    }
    else if (gparsed->action == ACCESS_ACTION_REJECT) {
        printf("need to generate a PDP context activation failed IRI\n");
    }
    else if (gparsed->action == ACCESS_ACTION_INTERIM_UPDATE) {
        *iritype = ETSILI_IRI_CONTINUE;
        if (gtp_create_context_modification_iri(gparsed, params, freelist) < 0)
        {
            return -1;
        }
        return 0;
    }
    else if (gparsed->action == ACCESS_ACTION_END) {
        *iritype = ETSILI_IRI_END;
        if (gtp_create_context_deactivation_iri(gparsed, params,
                freelist) < 0) {
            return -1;
        }
        return 0;
    } else {
        return 0;
    }

    return -1;
}

static int gtp_generate_iri_from_session(access_plugin_t *p,
        access_session_t *session, etsili_generic_t **params,
        etsili_iri_type_t *iritype, etsili_generic_freelist_t *freelist,
        uint8_t trigger) {

    gtp_global_t *glob = (gtp_global_t *)(p->plugindata);
    gtp_session_t *gsess;
    PWord_t pval;

    JSLG(pval, glob->session_map, session->sessionid);

    if (pval == NULL) {
        logger(LOG_INFO, "OpenLI: cannot generate IRI of type %d for session %s, as it is not in the GTP session map?",
                iritype, (char *)session->sessionid);
        return -1;
    }

    gsess = (gtp_session_t *)(*pval);

    if (trigger == OPENLI_IPIRI_STARTWHILEACTIVE) {
        *iritype = ETSILI_IRI_BEGIN;
        if (gtp_create_start_with_context_active_iri(gsess, params, freelist)
                    < 0) {
            return -1;
        }
    }

    /* Don't return -1 if this is an unexpected trigger type -- UMTS specs
     * don't seem to include IRIs for triggers like silent log-off or
     * end intercept while context is active (as far as I can tell), so
     * we just want to ignore those trigger methods.
     */
    return 0;
}

static uint8_t *gtp_get_ip_contents(access_plugin_t *p, void *parseddata,
        uint16_t *iplen, int iteration) {

    gtp_parsed_t *gparsed = (gtp_parsed_t *)parseddata;
    uint8_t *ipc = NULL;

    if (iteration == 0) {
        if (gparsed->request && gparsed->request->ipcontent != NULL) {
            *iplen = gparsed->request->iplen;
            ipc = gparsed->request->ipcontent;
            gparsed->request->ipcontent = NULL;
            gparsed->request->iplen = 0;
            return ipc;
        }
        iteration = 1;
    }

    if (iteration == 1) {
        if (gparsed->response && gparsed->response->ipcontent != NULL) {
            *iplen = gparsed->response->iplen;
            ipc = gparsed->response->ipcontent;
            gparsed->response->ipcontent = NULL;
            gparsed->response->iplen = 0;
            return ipc;
        }
    }

    *iplen = 0;
    return NULL;

}

static void gtp_destroy_session_data(access_plugin_t *p,
        access_session_t *sess) {

    if (sess->sessionid) {
        free(sess->sessionid);
    }

}

static uint32_t gtp_get_packet_sequence(access_plugin_t *p, void *parseddata) {

    gtp_parsed_t *gparsed = (gtp_parsed_t *)parseddata;

    /* bottom 8 bits of seqno are "spare" */
    return (gparsed->seqno | gparsed->msgtype);
}

static access_plugin_t gtpplugin = {

    "GTP",
    ACCESS_GTP,
    NULL,

    gtp_init_plugin_data,
    gtp_destroy_plugin_data,
    gtp_parse_packet,
    gtp_destroy_parsed_data,
    gtp_uncouple_parsed_data,
    gtp_get_userid,
    gtp_update_session_state,
    gtp_generate_iri_data,
    gtp_generate_iri_from_session,
    gtp_destroy_session_data,
    gtp_get_packet_sequence,
    gtp_get_ip_contents,
};

access_plugin_t *get_gtp_access_plugin(void) {
    return &gtpplugin;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :


