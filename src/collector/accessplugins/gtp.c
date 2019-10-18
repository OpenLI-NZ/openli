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

#include "ipiri.h"
#include "logger.h"
#include "internetaccess.h"
#include "util.h"

enum {
    GTP_IE_IMSI = 1,
    GTP_IE_MSISDN = 76,
    GTP_IE_PDN_ALLOC = 79,
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

    struct sockaddr_storage assignedip;
} gtp_session_t;

typedef struct gtp_parsed {

    uint8_t attached;
    libtrace_packet_t *origpkt;

    uint8_t version;
    uint8_t msgtype;
    double tvsec;
    uint32_t teid;
    uint32_t seqno;

    uint8_t serveripfamily;
    uint8_t serverid[16];
    
    char imsi[16];
    char msisdn[16];

    gtp_infoelem_t *ies;
    gtp_session_t *matched_session;

} gtp_parsed_t;

typedef struct gtp_saved_request {

    uint64_t reqid;
    double tvsec;
    gtp_infoelem_t *ies;
    gtp_session_t *session;

} gtp_saved_request_t;

typedef struct gtp_global {
    gtp_parsed_t *parsedpkt;

    Pvoid_t session_map;
} gtp_global_t;


static void reset_parsed_pkt(gtp_parsed_t *parsed) {
    parsed->attached = 1;
    parsed->origpkt = NULL;
    parsed->version = 0;
    parsed->msgtype = 0;
    parsed->tvsec = 0;
    parsed->teid = 0;
    parsed->seqno = 0;

    parsed->serveripfamily = 0;
    memset(parsed->serverid, 0, 16);
    memset(parsed->imsi, 0, 16);
    memset(parsed->msisdn, 0, 16);

    parsed->ies = NULL;
    parsed->matched_session = NULL;
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

static void gtp_destroy_plugin_data(access_plugin_t *p) {
    gtp_global_t *glob;
    char index[64];
    PWord_t pval;
    Word_t res;

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

    gtp_infoelem_t *ie, *tmp;

    if (!gparsed) {
        return;
    }

    ie = gparsed->ies;

    while (ie) {
        tmp = ie;
        ie = ie->next;
        if (tmp->iecontent) {
            free(tmp->iecontent);
        }
        free(tmp);
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
        }

        ptr += (ielen + 4);
        used += (ielen + 4);
        rem -= (ielen + 4);
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
    glob->parsedpkt->tvsec = (uint32_t)trace_get_seconds(pkt);

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
        /* Got a session that we haven't seen before but we also
         * didn't see the create request for it -- this means we have
         * no IMSI or MSISDN, so we should probably just ignore it?
         */
        return NULL;
    }

    sess = calloc(1, sizeof(gtp_session_t));
    sess->sessid = strdup(sessid);
    memset(&(sess->assignedip), 0, sizeof(struct sockaddr_storage));

    if (gparsed->imsi[0] != '\0') {
        sess->userid.imsi = strdup(gparsed->imsi);
    } else {
        sess->userid.imsi = strdup("imsiunknown");
    }

    if (gparsed->msisdn[0] != '\0') {
        sess->userid.msisdn = strdup(gparsed->msisdn);
    } else {
        sess->userid.msisdn = strdup("msisdnunknown");
    }

    snprintf(sess->idstr, 64, "%s-%s", sess->userid.imsi, sess->userid.msisdn);
    sess->idstr_len = strlen(sess->idstr);

    JSLI(pval, glob->session_map, sess->sessid);
    *pval = (Word_t)sess;

    *useridlen = sess->idstr_len;
    gparsed->matched_session = sess;
    return sess->idstr;
}

static access_session_t *gtp_update_session_state(access_plugin_t *p,
        void *parsed, access_session_t **sesslist,
        session_state_t *oldstate, session_state_t *newstate,
        access_action_t *action) {

    gtp_global_t *glob = (gtp_global_t *)(p->plugindata);
    access_session_t *thissess;



    switch(glob->parsedpkt->msgtype) {
        case GTPV2_CREATE_SESSION_REQUEST:
            break;
        case GTPV2_CREATE_SESSION_RESPONSE:
            break;
        case GTPV2_DELETE_SESSION_REQUEST:
            break;
        case GTPV2_DELETE_SESSION_RESPONSE:
            break;
    }

    return NULL;
}

static int gtp_generate_iri_data(access_plugin_t *p, void *parseddata,
        etsili_generic_t **params, etsili_iri_type_t *iritype,
        etsili_generic_freelist_t *freelist, int iteration) {

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


