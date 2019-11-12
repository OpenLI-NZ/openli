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
    GTP_IE_IMSI = 1,
    GTP_IE_CAUSE = 2,
    GTP_IE_APNAME = 71,
    GTP_IE_MEI = 75,
    GTP_IE_MSISDN = 76,
    GTP_IE_PDN_ALLOC = 79,
    GTP_IE_ULI = 86,
    GTP_IE_FTEID = 87,
};

/* XXX do we need to support other message types here, e.g. for IRI-Report? */
enum {
    GTPV2_CREATE_SESSION_REQUEST = 32,
    GTPV2_CREATE_SESSION_RESPONSE = 33,
    GTPV2_DELETE_SESSION_REQUEST = 36,
    GTPV2_DELETE_SESSION_RESPONSE = 37,
};

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

typedef struct gtp_userid {
    char *imsi;
    char *msisdn;

} PACKED gtp_user_identity_t;

typedef struct gtp_session {

    char *sessid;
    gtp_user_identity_t userid;

    char idstr[64];
    int idstr_len;

    internetaccess_ip_t pdpaddr;
    uint16_t pdptype;
    int64_t cin;

    uint8_t serverid[16];
    uint8_t serveripfamily;

    session_state_t current;
} gtp_session_t;

typedef struct gtp_saved_packet gtp_saved_pkt_t;

struct gtp_saved_packet {
    uint64_t reqid;
    uint8_t type;
    uint8_t applied;
    double tvsec;

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
    uint32_t seqno;
    uint8_t response_cause;

    uint8_t serveripfamily;
    uint8_t serverid[16];

    char imsi[16];
    char msisdn[16];

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

    double lastrefresh;
} gtp_global_t;


static void reset_parsed_pkt(gtp_parsed_t *parsed) {
    parsed->attached = 1;
    parsed->origpkt = NULL;
    parsed->version = 0;
    parsed->msgtype = 0;
    parsed->tvsec = 0;
    parsed->teid = 0;
    parsed->seqno = 0;
    parsed->response_cause = 0;

    parsed->serveripfamily = 0;
    memset(parsed->serverid, 0, 16);
    memset(parsed->imsi, 0, 16);
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

    if (sess->userid.imsi) {
        free(sess->userid.imsi);
    }

    if (sess->userid.msisdn) {
        free(sess->userid.msisdn);
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
    char index[64];
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

    indexnum = 0;
    JLF(pval, glob->saved_packets, indexnum);
    while (pval) {
        gtp_saved_pkt_t *pkt = (gtp_saved_pkt_t *)(*pval);

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

    gtp_global_t *glob = (gtp_global_t *)(p->plugindata);
    gtp_parsed_t *gparsed = (gtp_parsed_t *)parsed;

    if (!gparsed) {
        return;
    }

    gtp_free_ie_list(gparsed->ies);

    if (gparsed->request) {
        gtp_free_ie_list(gparsed->request->ies);
        free(gparsed->request);
    }

    if (gparsed->response) {
        gtp_free_ie_list(gparsed->response->ies);
        free(gparsed->response);
    }

    if (gparsed->attached) {
        reset_parsed_pkt(gparsed);
    } else {
        free(gparsed);
    }
}

static inline bool interesting_info_element(uint8_t ietype) {
    switch(ietype) {
        case GTP_IE_IMSI:
        case GTP_IE_FTEID:
        case GTP_IE_MSISDN:
        case GTP_IE_PDN_ALLOC:
        case GTP_IE_CAUSE:
        case GTP_IE_MEI:
        case GTP_IE_APNAME:
        case GTP_IE_ULI:
            return true;
    }

    return false;
}

static inline gtp_infoelem_t *create_new_gtp_infoel(uint8_t ietype,
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

static inline uint32_t get_teid_from_fteid(gtp_infoelem_t *gtpel) {

    /* Skip over first byte, which contains flags */
    uint32_t *ptr = (uint32_t *)(gtpel->iecontent + 1);

    /* Bytes 2-5 contain the TEID/GRE key */
    return ntohl(*ptr);
}

static inline uint8_t get_cause_from_ie(gtp_infoelem_t *gtpel) {
    
    return *((uint8_t *)(gtpel->iecontent));
}

static inline void get_gtpnum_from_ie(gtp_infoelem_t *gtpel, char *field) {

    /* IMSI is encoded in a weird way :( */
    uint8_t *ptr = gtpel->iecontent;
    int i, j;

    j = 0;
    for (i = 0; i < gtpel->ielength; i++) {
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

static void walk_gtp_ies(gtp_parsed_t *parsedpkt, uint8_t *ptr, uint32_t rem,
        uint16_t gtplen) {

    uint16_t used = 0;

    while (rem > 4 && used < gtplen) {
        uint8_t ietype;
        uint16_t ielen;
        gtp_infoelem_t *gtpel;

        ietype = *ptr;
        ielen = ntohs(*((uint16_t *)(ptr + 1)));

        if (interesting_info_element(ietype)) {
            gtpel = create_new_gtp_infoel(ietype, ielen, ptr);
            gtpel->next = parsedpkt->ies;
            parsedpkt->ies = gtpel;
        }

        if (parsedpkt->msgtype == GTPV2_CREATE_SESSION_REQUEST) {
            if (ietype == GTP_IE_FTEID) {
                parsedpkt->teid = get_teid_from_fteid(gtpel);
            }
            if (ietype == GTP_IE_IMSI) {
                get_gtpnum_from_ie(gtpel, parsedpkt->imsi);
            }
            if (ietype == GTP_IE_MSISDN) {
                get_gtpnum_from_ie(gtpel, parsedpkt->msisdn);
            }
        } else if (parsedpkt->msgtype == GTPV2_DELETE_SESSION_REQUEST) {
            if (ietype == GTP_IE_FTEID) {
                parsedpkt->teid = get_teid_from_fteid(gtpel);
            }
        }

        if (ietype == GTP_IE_CAUSE) {
            parsedpkt->response_cause = get_cause_from_ie(gtpel);
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

    walk_gtp_ies(glob->parsedpkt, ptr, rem, len);

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

        if (ethertype == TRACE_ETHERTYPE_IP) {
            libtrace_ip_t *ip = (libtrace_ip_t *)l3;

            glob->parsedpkt->serveripfamily = 4;

            switch(glob->parsedpkt->msgtype) {
                case GTPV2_CREATE_SESSION_REQUEST:
                case GTPV2_DELETE_SESSION_REQUEST:
                    memcpy(glob->parsedpkt->serverid, &(ip->ip_dst.s_addr), 4);
                    break;
                case GTPV2_CREATE_SESSION_RESPONSE:
                case GTPV2_DELETE_SESSION_RESPONSE:
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
                    memcpy(glob->parsedpkt->serverid, &(ip6->ip_dst.s6_addr),
                            16);
                    break;
                case GTPV2_CREATE_SESSION_RESPONSE:
                case GTPV2_DELETE_SESSION_RESPONSE:
                    memcpy(glob->parsedpkt->serverid, &(ip6->ip_src.s6_addr),
                            16);
                    break;
                default:
                    glob->parsedpkt->serveripfamily = 0;
                    break;
            }
        }


    } else {
        /* TODO GTPv2 without TEID and GTPv1 if required */
        //return NULL;
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

static char *gtp_get_userid(access_plugin_t *p, void *parsed,
        int *useridlen) {

    gtp_global_t *glob = (gtp_global_t *)(p->plugindata);
    gtp_parsed_t *gparsed = (gtp_parsed_t *)parsed;
    char sessid[64];
    gtp_session_t *sess;
    PWord_t pval;

    if (glob == NULL || gparsed == NULL) {
        return NULL;
    }

    if (gparsed->matched_session) {
        *useridlen = gparsed->matched_session->idstr_len;
        return gparsed->matched_session->idstr;
    }

    /* Need to look up the session */

    if (gparsed->serveripfamily == 4) {
        snprintf(sessid, 64, "%u-%u", *(uint32_t *)gparsed->serverid,
                gparsed->teid);
    } else if (gparsed->serveripfamily == 6) {
        snprintf(sessid, 64, "%lu-%lu-%u", *(uint64_t *)gparsed->serverid,
                *(uint64_t *)(gparsed->serverid + 8), gparsed->teid);
    } else {
        return NULL;
    }

    JSLG(pval, glob->session_map, sessid);

    if (pval) {
        gparsed->matched_session = (gtp_session_t *)(*pval);
        *useridlen = gparsed->matched_session->idstr_len;
        return gparsed->matched_session->idstr;
    }

    if (gparsed->msgtype != GTPV2_CREATE_SESSION_REQUEST) {
        return NULL;
    }

    sess = calloc(1, sizeof(gtp_session_t));
    sess->sessid = strdup(sessid);
    sess->current = SESSION_STATE_NEW;

    memcpy(sess->serverid, gparsed->serverid, 16);
    sess->serveripfamily = gparsed->serveripfamily;

    /* For now, I'm going to just use the MSISDN as the user identity
     * until I'm told otherwise.
     */
    if (gparsed->msisdn[0] != '\0') {
        sess->userid.msisdn = strdup(gparsed->msisdn);
    } else {
        destroy_gtp_session(sess);
        return NULL;
    }

    if (gparsed->imsi[0] != '\0') {
        sess->userid.imsi = strdup(gparsed->imsi);
    }

    snprintf(sess->idstr, 64, "%s", sess->userid.msisdn);
    sess->idstr_len = strlen(sess->idstr);

    JSLI(pval, glob->session_map, sess->sessid);
    *pval = (Word_t)sess;

    *useridlen = sess->idstr_len;
    gparsed->matched_session = sess;
    return sess->idstr;
}

static void extract_gtp_assigned_ip_address(gtp_saved_pkt_t *gpkt,
        access_session_t *sess, gtp_session_t *gsess) {

    gtp_infoelem_t *ie;

    if (!gsess) {
        return;
    }

    ie = gpkt->ies;
    while (ie) {
        if (ie->ietype == GTP_IE_PDN_ALLOC) {
            if (*((uint8_t *)(ie->iecontent)) == 0x01) {
                /* IPv4 */
                struct sockaddr_in *in;

                in = (struct sockaddr_in *)&(sess->sessionip.assignedip);
                in->sin_family = AF_INET;
                in->sin_port = 0;
                in->sin_addr.s_addr = *((uint32_t *)(ie->iecontent + 1));

                sess->sessionip.ipfamily = AF_INET;
                sess->sessionip.prefixbits = 32;

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
                struct sockaddr_in6 *in6;

                in6 = (struct sockaddr_in6 *)&(sess->sessionip.assignedip);
                in6->sin6_family = AF_INET6;
                in6->sin6_port = 0;
                memcpy(&(in6->sin6_addr.s6_addr), ie->iecontent + 1, 16);

                sess->sessionip.ipfamily = AF_INET6;
                sess->sessionip.prefixbits = 128;
                gsess->pdptype = htons(0x0157);
            } else if (*((uint8_t *)(ie->iecontent)) == 0x03) {
                /* IPv4 AND IPv6 */

                /* TODO support multiple sessionips per session */
                struct sockaddr_in6 *in6;

                in6 = (struct sockaddr_in6 *)&(sess->sessionip.assignedip);
                in6->sin6_family = AF_INET6;
                in6->sin6_port = 0;
                memcpy(&(in6->sin6_addr.s6_addr), ie->iecontent + 1, 16);

                sess->sessionip.ipfamily = AF_INET6;
                sess->sessionip.prefixbits = 128;
                gsess->pdptype = htons(0x018d);
            } else {
                break;
            }

            memcpy(&(gsess->pdpaddr), sess, sizeof(internetaccess_ip_t));
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

static void apply_gtp_fsm_logic(gtp_parsed_t *gparsed, access_action_t *action,
        access_session_t *sess, gtp_saved_pkt_t *gpkt) {

    session_state_t current = gparsed->matched_session->current;

    if (current == SESSION_STATE_NEW &&
            gpkt->type == GTPV2_CREATE_SESSION_REQUEST) {

        current = SESSION_STATE_AUTHING;
        *action = ACCESS_ACTION_NONE;

    } else if (current == SESSION_STATE_AUTHING &&
            gpkt->type == GTPV2_CREATE_SESSION_RESPONSE) {

        if (gparsed->response_cause == 0x10) {
            current = SESSION_STATE_ACTIVE;
            *action = ACCESS_ACTION_ACCEPT;

            extract_gtp_assigned_ip_address(gpkt, sess,
                    gparsed->matched_session);

        } else if (gparsed->response_cause >= 64 &&
                gparsed->response_cause <= 239) {
            current = SESSION_STATE_OVER;
            *action = ACCESS_ACTION_REJECT;
        }
    } else if (current == SESSION_STATE_ACTIVE &&
            gpkt->type == GTPV2_DELETE_SESSION_REQUEST) {
        current = SESSION_STATE_ENDING;
        *action = ACCESS_ACTION_NONE;
    } else if (current == SESSION_STATE_ENDING &&
            gpkt->type == GTPV2_DELETE_SESSION_RESPONSE) {
        current = SESSION_STATE_OVER;
        *action = ACCESS_ACTION_END;
    }

    gparsed->matched_session->current = current;

}

static inline access_session_t *find_matched_session(access_plugin_t *p,
        access_session_t **sesslist, gtp_session_t *match, uint32_t teid) {

    access_session_t *thissess = NULL;

    if (match == NULL) {
        return NULL;
    }

    thissess = *sesslist;
    while (thissess != NULL) {
        if (strcmp(thissess->sessionid, match->idstr) == 0) {
            break;
        }
        thissess = thissess->next;
    }

    if (!thissess) {
        thissess = create_access_session(p, match->idstr, match->idstr_len);
        thissess->cin = assign_gtp_cin(teid);
        match->cin = thissess->cin;

        thissess->next = *sesslist;
        *sesslist = thissess;
    }
    return thissess;
}

static access_session_t *gtp_update_session_state(access_plugin_t *p,
        void *parsed, access_session_t **sesslist,
        session_state_t *oldstate, session_state_t *newstate,
        access_action_t *action) {

    gtp_global_t *glob = (gtp_global_t *)(p->plugindata);
    access_session_t *thissess = NULL;
    gtp_saved_pkt_t *saved, *check;
    gtp_parsed_t *gparsed = (gtp_parsed_t *)parsed;
    gtp_session_t *gsession = NULL;
    PWord_t pval;
    Word_t rcint;

    saved = calloc(1, sizeof(gtp_saved_pkt_t));

    saved->type = gparsed->msgtype;
    saved->reqid = (((uint64_t)gparsed->teid) << 32) |
            ((uint64_t)gparsed->seqno);
    saved->ies = gparsed->ies;
    saved->matched_session = gparsed->matched_session;
    saved->applied = 0;
    saved->tvsec = gparsed->tvsec;
    gparsed->ies = NULL;

    JLG(pval, glob->saved_packets, saved->reqid);
    if (pval == NULL) {
        JLI(pval, glob->saved_packets, saved->reqid);
        *pval = (Word_t)saved;

        if (gparsed->msgtype == GTPV2_CREATE_SESSION_REQUEST ||
                gparsed->msgtype == GTPV2_DELETE_SESSION_REQUEST) {

            thissess = find_matched_session(p, sesslist,
                    gparsed->matched_session, gparsed->teid);
            if (thissess) {
                *oldstate = gparsed->matched_session->current;
                apply_gtp_fsm_logic(gparsed, &(gparsed->action), thissess,
                        saved);
                *newstate = gparsed->matched_session->current;
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
        } else if (saved->type == check->type) {
            /* probably a re-transmit */
            JLI(pval, glob->saved_packets, saved->reqid);
            *pval = (Word_t)saved;

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
        } else if (gparsed->response->matched_session) {
            thissess = find_matched_session(p, sesslist,
                    gparsed->response->matched_session, gparsed->teid);
            *oldstate = gparsed->response->matched_session->current;
            gparsed->matched_session = gparsed->response->matched_session;
        }

        if (thissess) {
            if (check->applied == 0) {
                apply_gtp_fsm_logic(gparsed, &(gparsed->action), thissess,
                        check);
            }
            apply_gtp_fsm_logic(gparsed, &(gparsed->action), thissess, saved);
        }
        *newstate = gparsed->matched_session->current;
    }

    return thissess;
}

static void parse_uli(gtp_infoelem_t *el, etsili_generic_freelist_t *freelist,
        etsili_generic_t **params) {

    etsili_generic_t *np;
    uint8_t uliflags;
    uint8_t *ptr;

    uliflags = *(uint8_t *)(el->iecontent);

    /* TODO implement CGID, SAI, RAI */
    ptr = ((uint8_t *)el->iecontent) + 1;

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

static int gtp_create_context_activation_iri(gtp_parsed_t *gparsed,
        etsili_generic_t **params, etsili_generic_freelist_t *freelist) {

    etsili_generic_t *np;
    etsili_ipaddress_t ipaddr;
    gtp_infoelem_t *el;
    uint32_t evtype = UMTSIRI_EVENT_TYPE_PDPCONTEXT_ACTIVATION;
    uint32_t initiator = 1;
    struct timeval tv;
    gtp_session_t *gsess = gparsed->matched_session;

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

    if (gparsed->matched_session->pdpaddr.ipfamily == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)
                &(gparsed->matched_session->pdpaddr.assignedip);

        etsili_create_ipaddress_v4((uint32_t *)&(sin->sin_addr.s_addr),
                ETSILI_IPV4_SUBNET_UNKNOWN, ETSILI_IPADDRESS_ASSIGNED_DYNAMIC,
                &ipaddr);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)
                &(gparsed->matched_session->pdpaddr.assignedip);

        etsili_create_ipaddress_v6((uint8_t *)(sin6->sin6_addr.s6_addr),
                ETSILI_IPV6_SUBNET_UNKNOWN, ETSILI_IPADDRESS_ASSIGNED_DYNAMIC,
                &ipaddr);
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

    np = create_etsili_generic(freelist, UMTSIRI_CONTENTS_GPRS_CORRELATION,
            sizeof(int64_t), (uint8_t *)(&(gparsed->matched_session->cin)));
    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum),
            np);

    el = gparsed->request->ies;
    while (el) {
        uint8_t ieattr = 0;
        uint8_t *attrptr = (uint8_t *)el->iecontent;
        uint16_t attrlen = el->ielength;

        switch(el->ietype) {
            case GTP_IE_IMSI:
                ieattr = UMTSIRI_CONTENTS_IMSI;
                break;
            case GTP_IE_MSISDN:
                ieattr = UMTSIRI_CONTENTS_MSISDN;
                break;
            case GTP_IE_MEI:
                ieattr = UMTSIRI_CONTENTS_IMEI;
                break;
            case GTP_IE_APNAME:
                ieattr = UMTSIRI_CONTENTS_APNAME;
                break;
            case GTP_IE_ULI:
                parse_uli(el, freelist, params);
                break;
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

static int gtp_generate_iri_data(access_plugin_t *p, void *parseddata,
        etsili_generic_t **params, etsili_iri_type_t *iritype,
        etsili_generic_freelist_t *freelist, int iteration) {

    gtp_global_t *glob = (gtp_global_t *)(p->plugindata);
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
    else if (gparsed->action == ACCESS_ACTION_END) {
        printf("need to generate a PDP context deactivation IRI\n");
    } else {
        return 0;
    }

    return -1;
}

static void gtp_destroy_session_data(access_plugin_t *p,
        access_session_t *sess) {

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
    gtp_destroy_session_data
};

access_plugin_t *get_gtp_access_plugin(void) {
    return &gtpplugin;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :


