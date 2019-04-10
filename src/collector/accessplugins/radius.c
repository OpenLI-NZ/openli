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
#include <uthash.h>

#include "ipiri.h"
#include "logger.h"
#include "internetaccess.h"
#include "util.h"

#define ORPHAN_EXPIRY (1.0)

#define DERIVE_REQUEST_ID(rad, reqtype) \
    ((((uint32_t)rad->msgident) << 16) + (((uint32_t)rad->sourceport)) + \
    (((uint32_t)reqtype) << 24))

#define PREALLOC_ATTRS (50000)
#define STANDARD_ATTR_ALLOC (64)

#define TIMESTAMP_TO_TV(tv, floatts) \
        tv->tv_sec = (uint32_t)(floatts); \
        tv->tv_usec = (uint32_t)(((floatts - tv->tv_sec) * 1000000));

enum {
    RADIUS_CODE_ACCESS_REQUEST = 1,
    RADIUS_CODE_ACCESS_ACCEPT = 2,
    RADIUS_CODE_ACCESS_REJECT = 3,
    RADIUS_CODE_ACCOUNT_REQUEST = 4,
    RADIUS_CODE_ACCOUNT_RESPONSE = 5,
    RADIUS_CODE_ACCESS_CHALLENGE = 11
};

enum {
    RADIUS_ATTR_USERNAME = 1,
    RADIUS_ATTR_NASIP = 4,
    RADIUS_ATTR_NASPORT = 5,
    RADIUS_ATTR_FRAMED_IP_ADDRESS = 8,
    RADIUS_ATTR_CALLED_STATION_ID = 30,
    RADIUS_ATTR_CALLING_STATION_ID = 31,
    RADIUS_ATTR_NASIDENTIFIER = 32,
    RADIUS_ATTR_ACCT_STATUS_TYPE = 40,
    RADIUS_ATTR_ACCT_INOCTETS = 42,
    RADIUS_ATTR_ACCT_OUTOCTETS = 43,
    RADIUS_ATTR_ACCT_SESSION_ID = 44,
    RADIUS_ATTR_ACCT_TERMINATE_CAUSE = 49,
    RADIUS_ATTR_FRAMED_IPV6_PREFIX = 97,
    RADIUS_ATTR_FRAMED_IPV6_ADDRESS = 168,
};

enum {
    RADIUS_ACCT_START = 1,
    RADIUS_ACCT_STOP = 2,
    RADIUS_ACCT_INTERIM_UPDATE = 3,
};

typedef struct radius_user {

    char *userid;
    int userid_len;
    char *nasidentifier;
    int nasid_len;
    session_state_t current;
    struct sockaddr *framedip4;
    struct sockaddr *framedip6;
} radius_user_t;

typedef struct radius_v6_prefix_attr {
    uint8_t reserved;
    uint8_t preflength;
    uint8_t address[16];
} PACKED radius_v6_prefix_attr_t;

typedef struct radius_attribute radius_attribute_t;

struct radius_attribute {
    uint8_t att_type;
    uint8_t att_len;
    void *att_val;
    radius_attribute_t *next;
};

typedef struct radius_saved_request radius_saved_req_t;

struct radius_saved_request {

    uint32_t reqid;
    uint32_t statustype;
    double tvsec;
    radius_attribute_t *attrs;

    radius_user_t *targetuser;
    radius_saved_req_t *next;
    UT_hash_handle hh;
};


typedef struct radius_orphaned_resp radius_orphaned_resp_t;

struct radius_orphaned_resp {
    uint8_t resptype;
    uint32_t key;
    double tvsec;
    radius_attribute_t *savedattrs;
    radius_orphaned_resp_t *next;
};

typedef struct radius_nas_t {
    uint8_t *nasip;
    Pvoid_t user_map;
    radius_saved_req_t *request_map;

    radius_orphaned_resp_t *orphans;
    radius_orphaned_resp_t *orphans_tail;

} radius_nas_t;

typedef struct radius_server {
    uint8_t *servip;
    Pvoid_t nas_map;
} radius_server_t;

typedef struct radius_parsed {

    uint8_t attached;
    libtrace_packet_t *origpkt;
    uint8_t msgtype;
    uint8_t msgident;
    uint8_t *authptr;
    uint32_t accttype;
    uint32_t nasport;
    double tvsec;
    radius_attribute_t *attrs;

    struct sockaddr_storage nasip;
    struct sockaddr_storage radiusip;
    uint16_t sourceport;

    radius_user_t *matcheduser;
    radius_nas_t *matchednas;
    radius_server_t *matchedserv;

    radius_saved_req_t *savedreq;
    radius_orphaned_resp_t *savedresp;

    access_action_t firstaction;
    access_action_t secondaction;

    radius_attribute_t *firstattrs;
    radius_attribute_t *secondattrs;

} radius_parsed_t;

typedef struct radius_global {
    uint8_t interesting_attributes[256];
    radius_attribute_t *freeattrs;
    radius_saved_req_t *freeaccreqs;
    radius_parsed_t *parsedpkt;

    Pvoid_t server_map;
} radius_global_t;

typedef struct radius_header {
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
    uint8_t auth[16];
} PACKED radius_header_t;

static int warned = 0;

static inline void reset_parsed_packet(radius_parsed_t *parsed) {

    parsed->attached = 1;
    parsed->origpkt = NULL;
    parsed->msgtype = 0;
    parsed->accttype = 0;
    parsed->msgident = 0;
    parsed->authptr = NULL;
    parsed->attrs = NULL;
    parsed->sourceport = 0;
    parsed->tvsec = 0;
    parsed->nasport = 0;
    parsed->matcheduser = NULL;
    parsed->matchednas = NULL;
    parsed->matchedserv = NULL;
    parsed->savedreq = NULL;
    parsed->savedresp = NULL;
    memset(&(parsed->nasip), 0, sizeof(struct sockaddr_storage));
    memset(&(parsed->radiusip), 0, sizeof(struct sockaddr_storage));

    parsed->firstaction = ACCESS_ACTION_NONE;
    parsed->firstattrs = NULL;
    parsed->secondaction = ACCESS_ACTION_NONE;
    parsed->secondattrs = NULL;

}

static inline char *fast_strdup(char *orig, int origlen) {
    char *dup = malloc(origlen + 1);

    memcpy(dup, orig, origlen + 1);
    return dup;
}

static inline int interesting_attribute(uint8_t attrnum) {

    switch(attrnum) {
        case RADIUS_ATTR_USERNAME:
        case RADIUS_ATTR_ACCT_STATUS_TYPE:
        case RADIUS_ATTR_NASIDENTIFIER:
        case RADIUS_ATTR_NASPORT:
        case RADIUS_ATTR_FRAMED_IP_ADDRESS:
        case RADIUS_ATTR_FRAMED_IPV6_ADDRESS:
        case RADIUS_ATTR_FRAMED_IPV6_PREFIX:
        case RADIUS_ATTR_ACCT_INOCTETS:
        case RADIUS_ATTR_ACCT_OUTOCTETS:
        case RADIUS_ATTR_ACCT_SESSION_ID:
        case RADIUS_ATTR_NASIP:
        case RADIUS_ATTR_CALLED_STATION_ID:
        case RADIUS_ATTR_CALLING_STATION_ID:
        case RADIUS_ATTR_ACCT_TERMINATE_CAUSE:
            return 1;
    }

    return 0;

}

static inline radius_attribute_t *create_new_attribute(radius_global_t *glob,
        uint8_t type, uint8_t len, uint8_t *valptr, uint8_t forcealloc) {

    radius_attribute_t *attr;

    if (glob->freeattrs && !forcealloc) {
        attr = glob->freeattrs;
        glob->freeattrs = attr->next;
    } else {
        attr = (radius_attribute_t *)calloc(1, sizeof(radius_attribute_t));
    }

    attr->next = NULL;
    attr->att_type = type;
    attr->att_len = len - 2;

    if (attr->att_val == NULL) {
        if (attr->att_len > STANDARD_ATTR_ALLOC) {
            attr->att_val = malloc(attr->att_len);
        } else {
            attr->att_val = malloc(STANDARD_ATTR_ALLOC);
        }
    } else if (attr->att_len > STANDARD_ATTR_ALLOC) {
        attr->att_val = realloc(attr->att_val, attr->att_len);
    }

    if (valptr) {
        memcpy(attr->att_val, valptr, attr->att_len);
    }
    return attr;
}

static void radius_init_plugin_data(access_plugin_t *p) {
    radius_global_t *glob;
    int i;

    glob = (radius_global_t *)(malloc(sizeof(radius_global_t)));
    glob->freeattrs = NULL;
    glob->freeaccreqs = NULL;
    glob->server_map = (Pvoid_t)NULL;

    memset(glob->interesting_attributes, 0,
            sizeof(glob->interesting_attributes));

    for (i = 0; i < 256; i++) {
        if (interesting_attribute((uint8_t)i)) {
            glob->interesting_attributes[i] = 1;
        }
    }

    glob->parsedpkt = (radius_parsed_t *)malloc(sizeof(radius_parsed_t));
    reset_parsed_packet(glob->parsedpkt);

    for (i = 0; i < PREALLOC_ATTRS; i++) {
        radius_attribute_t *at;

        at = create_new_attribute(glob, RADIUS_ATTR_NASPORT,
                STANDARD_ATTR_ALLOC, NULL, 1);
        at->next = glob->freeattrs;
        glob->freeattrs = at;
    }

    p->plugindata = (void *)(glob);
    return;
}

static inline void free_attribute_list(radius_attribute_t *attrlist) {
    radius_attribute_t *at, *tmp;

    at = attrlist;
    while (at) {
        tmp = at;
        at = at->next;
        if (tmp->att_val) {
            free(tmp->att_val);
        }
        free(tmp);
    }
}

static void destroy_radius_nas(radius_nas_t *nas) {
    radius_orphaned_resp_t *orph, *tmporph;
    radius_saved_req_t *req, *tmpreq;
    radius_user_t *user;
    PWord_t pval;
    char index[128];
    Word_t res;

    index[0] = '\0';
    JSLF(pval, nas->user_map, index);
    while (pval) {
        user = (radius_user_t *)(*pval);
        if (user->userid) {
            free(user->userid);
        }
        if (user->nasidentifier) {
            free(user->nasidentifier);
        }
        if (user->framedip4) {
            free(user->framedip4);
        }
        if (user->framedip6) {
            free(user->framedip6);
        }
        free(user);

        JSLN(pval, nas->user_map, index);
    }
    JSLFA(res, nas->user_map);

    HASH_ITER(hh, nas->request_map, req, tmpreq) {
        HASH_DELETE(hh, nas->request_map, req);
        free_attribute_list(req->attrs);
        free(req);

    }

    orph = nas->orphans;
    while (orph) {
        tmporph = orph;
        orph = orph->next;
        free_attribute_list(tmporph->savedattrs);
        free(tmporph);
    }

    if (nas->nasip) {
        free(nas->nasip);
    }
    free(nas);
}

static void destroy_radius_server(radius_server_t *srv) {

    radius_nas_t *nas;
    PWord_t pval;
    Word_t res;
    char index[128];

    index[0] = '\0';
    JSLF(pval, srv->nas_map, index);
    while (pval) {
        nas = (radius_nas_t *)(*pval);
        destroy_radius_nas(nas);

        JSLN(pval, srv->nas_map, index);
    }

    JSLFA(res, srv->nas_map);
    if (srv->servip) {
        free(srv->servip);
    }
    free(srv);
}

static void radius_destroy_plugin_data(access_plugin_t *p) {

    radius_global_t *glob;
    radius_server_t *srv;
    radius_nas_t *nas;
    radius_saved_req_t *req, *tmpreq;
    PWord_t pval;
    char index[128];
    Word_t res;

    glob = (radius_global_t *)(p->plugindata);
    if (!glob) {
        return;
    }

    free_attribute_list(glob->freeattrs);

    req = glob->freeaccreqs;
    while (req) {
        tmpreq = req;
        req = req->next;
        free(tmpreq);
    }

    index[0] = '\0';
    JSLF(pval, glob->server_map, index);
    while (pval) {
        srv = (radius_server_t *)(*pval);
        destroy_radius_server(srv);
        JSLN(pval, glob->server_map, index);
    }
    JSLFA(res, glob->server_map);

    if (glob->parsedpkt) {
        free_attribute_list(glob->parsedpkt->attrs);
        free(glob->parsedpkt);
    }

    free(glob);
    return;
}

static inline void release_attribute(radius_attribute_t **freelist,
        radius_attribute_t *attr) {

    if (*freelist == NULL) {
        *freelist = attr;
        (*freelist)->next = NULL;
    } else {
        attr->next = *freelist;
        *freelist = attr;
    }
}

static inline void release_attribute_list(
        radius_attribute_t **freelist, radius_attribute_t *attrlist) {

    radius_attribute_t *at, *tmp;

    at = attrlist;

    while (at != NULL) {
        tmp = at;
        at = at->next;
        release_attribute(freelist, tmp);
    }

}

static inline void release_saved_request(radius_saved_req_t **freelist,
        radius_saved_req_t *req) {

    if (*freelist == NULL) {
        *freelist = req;
        req->next = NULL;
    } else {
        req->next = *freelist;
        *freelist = req;
    }
}

static void radius_destroy_parsed_data(access_plugin_t *p, void *parsed) {

    radius_global_t *glob;
    radius_parsed_t *rparsed = (radius_parsed_t *)parsed;

    glob = (radius_global_t *)(p->plugindata);

    /* Only release our attributes if we were part of a successful req/resp
     * match. Otherwise, the attributes are still somewhere in our saved
     * requests or orphans maps so don't free them just yet.
     */
    if (rparsed->msgtype == RADIUS_CODE_ACCESS_REQUEST ||
                    rparsed->msgtype == RADIUS_CODE_ACCOUNT_REQUEST) {
        if (rparsed->savedresp) {
            release_attribute_list(&(glob->freeattrs), rparsed->attrs);
        }
    }
    else if (rparsed->msgtype == RADIUS_CODE_ACCESS_ACCEPT ||
            rparsed->msgtype == RADIUS_CODE_ACCESS_REJECT ||
            rparsed->msgtype == RADIUS_CODE_ACCESS_CHALLENGE ||
            rparsed->msgtype == RADIUS_CODE_ACCOUNT_RESPONSE) {
        if (rparsed->savedreq) {
            release_attribute_list(&(glob->freeattrs), rparsed->attrs);
        }
    }
    else {
        release_attribute_list(&(glob->freeattrs), rparsed->attrs);
    }


    if (rparsed->savedreq) {
        release_attribute_list(&(glob->freeattrs), rparsed->savedreq->attrs);
        release_saved_request(&(glob->freeaccreqs), rparsed->savedreq);
        rparsed->savedreq = NULL;
    }

    if (rparsed->savedresp) {
        release_attribute_list(&(glob->freeattrs),
                rparsed->savedresp->savedattrs);
        free(rparsed->savedresp);
    }

    if (rparsed->attached) {
        reset_parsed_packet(rparsed);
    } else {
        free(rparsed);
    }

}

static void radius_uncouple_parsed_data(access_plugin_t *p) {

    radius_global_t *glob;
    glob = (radius_global_t *)(p->plugindata);
    glob->parsedpkt->attached = 0;

    glob->parsedpkt = (radius_parsed_t *)malloc(sizeof(radius_parsed_t));
    reset_parsed_packet(glob->parsedpkt);

}

static void create_orphan(radius_global_t *glob, radius_orphaned_resp_t **head,
        radius_orphaned_resp_t **tail, libtrace_packet_t *pkt,
        radius_parsed_t *raddata, uint32_t reqid) {

    /* Hopefully this is rare enough that we don't need a freelist of
     * orphaned responses */

    radius_orphaned_resp_t *resp, *iter;
    radius_attribute_t *attr, *attrcopy;

    resp = (radius_orphaned_resp_t *)malloc(sizeof(radius_orphaned_resp_t));
    resp->key = reqid;
    resp->next = NULL;
    resp->tvsec = trace_get_seconds(pkt);
    resp->resptype = raddata->msgtype;
    resp->savedattrs = raddata->attrs;
    //raddata->attrs = NULL;

    if (*tail == NULL) {
        *head = resp;
        *tail = resp;
        return;
    }

    (*tail)->next = resp;
    (*tail) = resp;

    /* Peel off any expired orphans */
    iter = *head;
    while (iter) {
        if (iter->tvsec + ORPHAN_EXPIRY >= resp->tvsec) {
            break;
        }
        (*head) = iter->next;
        /* XXX should really put these back in the free list */
        free_attribute_list(iter->savedattrs);
        free(iter);
        iter = *head;
        if (!warned) {
            logger(LOG_INFO,
                "OpenLI RADIUS: expired orphaned response packet.");
            logger(LOG_INFO,
                "OpenLI RADIUS: capture is possibly dropping RADIUS packets?");
            warned = 1;
        }
    }
}

static inline void *find_radius_start(libtrace_packet_t *pkt, uint32_t *rem,
        uint16_t *sourceport, uint16_t *destport) {

    void *transport, *radstart;
    uint8_t proto;
    libtrace_udp_t *udp;

    transport = trace_get_transport(pkt, &proto, rem);
    if (!transport || rem == 0) {
        return NULL;
    }

    if (proto != TRACE_IPPROTO_UDP) {
        return NULL;
    }

    udp = (libtrace_udp_t *)transport;
    *sourceport = ntohs(udp->source);
    *destport = ntohs(udp->dest);

    radstart = trace_get_payload_from_udp(udp, rem);
    return radstart;
}

static inline int grab_nas_details_from_packet(radius_parsed_t *parsed,
        libtrace_packet_t *pkt, uint8_t code, uint16_t sourceport,
        uint16_t destport) {

    struct sockaddr_storage *ipaddr_src;
    struct sockaddr_storage *ipaddr_dst;
    void *l3;
    uint16_t ethertype;
    uint32_t remaining;

    /* We must have a complete IP header to get here */
    l3 = trace_get_layer3(pkt, &ethertype, &remaining);
    if (l3 == NULL || remaining < sizeof(libtrace_ip_t)) {
        return -1;
    }

    switch(code) {
        case RADIUS_CODE_ACCESS_REQUEST:
        case RADIUS_CODE_ACCOUNT_REQUEST:
            ipaddr_src = &(parsed->nasip);
            ipaddr_dst = &(parsed->radiusip);
            parsed->sourceport = sourceport;
            break;
        case RADIUS_CODE_ACCESS_ACCEPT:
        case RADIUS_CODE_ACCESS_REJECT:
        case RADIUS_CODE_ACCOUNT_RESPONSE:
        case RADIUS_CODE_ACCESS_CHALLENGE:
            ipaddr_dst = &(parsed->nasip);
            ipaddr_src = &(parsed->radiusip);
            parsed->sourceport = destport;
            break;
        default:
            return -1;
    }

    if (ethertype == TRACE_ETHERTYPE_IP) {
        struct sockaddr_in *src4, *dst4;
        libtrace_ip_t *ip = (libtrace_ip_t *)l3;

        src4 = (struct sockaddr_in *)ipaddr_src;
        dst4 = (struct sockaddr_in *)ipaddr_dst;

        src4->sin_family = AF_INET;
        dst4->sin_family = AF_INET;
        src4->sin_port = 0;
        dst4->sin_port = 0;
        src4->sin_addr = ip->ip_src;
        dst4->sin_addr = ip->ip_dst;
    } else if (ethertype == TRACE_ETHERTYPE_IPV6) {
        struct sockaddr_in6 *src6, *dst6;
        libtrace_ip6_t *ip6 = (libtrace_ip6_t *)l3;

        src6 = (struct sockaddr_in6 *)ipaddr_src;
        dst6 = (struct sockaddr_in6 *)ipaddr_dst;

        src6->sin6_family = AF_INET6;
        dst6->sin6_family = AF_INET6;
        src6->sin6_port = 0;
        dst6->sin6_port = 0;
        src6->sin6_addr = ip6->ip_src;
        dst6->sin6_addr = ip6->ip_dst;
    } else {
        return -1;
    }


    return 0;
}

static inline void update_known_servers(radius_global_t *glob,
        radius_parsed_t *parsed) {

    radius_server_t *srv;
    radius_nas_t *nas;
    uint8_t *sockkey;
    int socklen;
    char hashkey[20];
    PWord_t pval;

    memset(hashkey, 0, sizeof(hashkey));

    sockkey = sockaddr_to_key((struct sockaddr *)&(parsed->radiusip),
            &socklen);

    if (sockkey == NULL) {
        return;
    }
    memcpy(hashkey, sockkey, socklen);
    JSLG(pval, glob->server_map, hashkey);

    if (pval == NULL) {
        srv = (radius_server_t *)malloc(sizeof(radius_server_t));
        srv->nas_map = (Pvoid_t)NULL;
        srv->servip = (uint8_t *)malloc(socklen);
        memcpy(srv->servip, sockkey, socklen);
        JSLI(pval, glob->server_map, hashkey);
        *pval = (Word_t)srv;
    } else {
        srv = (radius_server_t *)(*pval);
    }


    sockkey = sockaddr_to_key((struct sockaddr *)&(parsed->radiusip),
            &socklen);

    if (sockkey == NULL) {
        return;
    }
    memcpy(hashkey, sockkey, socklen);
    JSLG(pval, srv->nas_map, hashkey);

    if (pval == NULL) {
        nas = (radius_nas_t *)malloc(sizeof(radius_nas_t));
        nas->user_map = (Pvoid_t)NULL;
        nas->request_map = NULL;
        nas->orphans = NULL;
        nas->orphans_tail = NULL;
        nas->nasip = (uint8_t *)malloc(socklen);
        memcpy(nas->nasip, sockkey, socklen);

        JSLI(pval, srv->nas_map, hashkey);
        *pval = (Word_t)nas;
    } else {
        nas = (radius_nas_t *)(*pval);
    }

    parsed->matchednas = nas;
    parsed->matchedserv = srv;

}

static void *radius_parse_packet(access_plugin_t *p, libtrace_packet_t *pkt) {

    uint8_t *radstart, *ptr;
    uint32_t rem;
    radius_header_t *hdr;
    uint16_t len;
    radius_parsed_t *parsed;
    radius_global_t *glob;
    uint16_t sourceport = 0;
    uint16_t destport = 0;

    glob = (radius_global_t *)(p->plugindata);

    parsed = glob->parsedpkt;
    if (parsed && parsed->msgtype != 0) {
        radius_destroy_parsed_data(p, (void *)parsed);
    }

    radstart = (uint8_t *)find_radius_start(pkt, &rem, &sourceport, &destport);
    if (radstart == NULL) {
        return NULL;
    }

    if (rem < sizeof(radius_header_t)) {
        logger(LOG_INFO,
                "OpenLI: RADIUS packet did not have a complete header");
        return NULL;
    }

    hdr = (radius_header_t *)radstart;
    len = ntohs(hdr->length);

    if (len > rem) {
        logger(LOG_INFO,
                "OpenLI: RADIUS packet was truncated, some attributes may be missed.");
        logger(LOG_INFO,
                "OpenLI: RADIUS length was %u but we only had %u bytes of payload.",
                len, rem);
    }

    parsed->msgtype = hdr->code;
    parsed->msgident = hdr->identifier;
    parsed->authptr = hdr->auth;
    parsed->origpkt = pkt;
    parsed->tvsec = trace_get_seconds(pkt);

    if (grab_nas_details_from_packet(parsed, pkt, hdr->code, sourceport,
            destport) < 0) {
        return NULL;
    }

    update_known_servers(glob, parsed);

    rem -= sizeof(radius_header_t);
    ptr = radstart + sizeof(radius_header_t);

    while (rem > 2) {
        uint8_t att_type, att_len;
        radius_attribute_t *newattr;

        att_type = *ptr;
        att_len = *(ptr+1);
        ptr += 2;

        if (rem < att_len) {
            break;
        }

        if (glob->interesting_attributes[att_type]) {
            newattr = create_new_attribute(glob, att_type, att_len, ptr, 0);
            newattr->next = parsed->attrs;
            parsed->attrs = newattr;

            if (newattr->att_type == RADIUS_ATTR_ACCT_STATUS_TYPE) {
                parsed->accttype = ntohl(*((uint32_t *)newattr->att_val));
            }
        }

        rem -= att_len;
        ptr += (att_len - 2);
    }

    return parsed;
}

static inline void process_username_attribute(radius_parsed_t *raddata) {

    char userkey[256];
    int keylen;
    radius_user_t *user;
    radius_attribute_t *userattr;
    PWord_t pval;

    if (raddata->msgtype != RADIUS_CODE_ACCESS_REQUEST &&
            raddata->msgtype != RADIUS_CODE_ACCOUNT_REQUEST) {
        return;
    }

    userattr = raddata->attrs;
    while (userattr) {
        if (userattr->att_type == RADIUS_ATTR_USERNAME) {
            break;
        }
        userattr = userattr->next;
    }

    if (!userattr) {
        return;
    }

    if (userattr->att_len < 256) {
        memcpy(userkey, userattr->att_val, userattr->att_len);
        userkey[userattr->att_len] = '\0';
        keylen = userattr->att_len;
    } else {
        memcpy(userkey, userattr->att_val, 255);
        userkey[255] = '\0';
        keylen = 255;
        logger(LOG_INFO,
                "OpenLI RADIUS: User-Name is too long, truncated to %s",
                userkey);
    }

    JSLG(pval, raddata->matchednas->user_map, userkey);

    if (pval) {
        raddata->matcheduser = (radius_user_t *)(*pval);
        return;
    }

    user = (radius_user_t *)malloc(sizeof(radius_user_t));

    user->userid = fast_strdup(userkey, keylen);
    user->userid_len = keylen;
    user->nasidentifier = NULL;
    user->nasid_len = 0;
    user->current = SESSION_STATE_NEW;
    user->framedip4 = NULL;
    user->framedip6 = NULL;

    JSLI(pval, raddata->matchednas->user_map, user->userid);
    *pval = (Word_t)user;
    raddata->matcheduser = user;
}

static uint32_t assign_cin(radius_parsed_t *raddata) {

    /* CIN assignment for RADIUS sessions:
     *
     * Use the Acct-Session-ID if available -- often present in
     * Access-Requests but not guaranteed. It's a variable length
     * UTF-8 string, so we need to hash it into a 32 bit space.
     *
     * Depending on your RADIUS setup, session ID may not be unique.
     * See https://freeradius.org/rfc/acct_session_id_uniqueness.html for
     * more info.
     *
     * The fallback option is to hash the Authenticator bytes, as this
     * should be a random 16 byte number for Access-Requests. For
     * Accounting-Requests, the number is not random but there must be a
     * Acct-Session-ID in that case anyway, so we should be OK.
     */

    struct timeval tv;
    radius_attribute_t *attr;
    uint32_t hashval = 0;

    attr = raddata->attrs;
    while (attr) {
        if (attr->att_type == RADIUS_ATTR_ACCT_SESSION_ID) {
            hashval = hashlittle(attr->att_val, attr->att_len, 0xfacebeef);
            hashval = hashval % (uint32_t)(pow(2, 31));
            return hashval;
        }
        attr = attr->next;
    }

    if (raddata->msgtype == RADIUS_CODE_ACCESS_REQUEST) {
        hashval = hashlittle(raddata->authptr, 16, 0xfacebeef);
        hashval = hashval % (uint32_t)(pow(2, 31));
        return hashval;
    }

    /* We really shouldn't get here, but just in case... */

    /* Not a great solution, but probably unique enough -- are we ever
     * likely to see multiple sessions for the same user within the same
     * second AND they're not using one of the other supported ID methods??
     */
    gettimeofday(&tv, NULL);
    return (tv.tv_sec % (uint32_t)(pow(2, 31)));

}

static inline void process_nasid_attribute(radius_parsed_t *raddata) {
    char nasid[1024];
    int keylen = 0;
    uint8_t attrnum = RADIUS_ATTR_NASIDENTIFIER;

    radius_attribute_t *nasattr;

    if (!raddata->matcheduser) {
        return;
    }

    nasattr = raddata->attrs;
    while (nasattr) {
        if (nasattr->att_type == RADIUS_ATTR_NASIDENTIFIER) {
            break;
        }
        nasattr = nasattr->next;
    }

    if (!nasattr) {
        return;
    }

    if (nasattr->att_len < 256) {
        memcpy(nasid, nasattr->att_val, nasattr->att_len);
        nasid[nasattr->att_len] = '\0';
        keylen = nasattr->att_len;
    } else {
        memcpy(nasid, nasattr->att_val, 255);
        nasid[255] = '\0';
        keylen = 255;
        logger(LOG_INFO,
                "OpenLI RADIUS: NAS-Identifier is too long, truncated to %s",
                nasid);
    }

    if (raddata->matcheduser->nasidentifier) {
        if (strcmp(nasid, raddata->matcheduser->nasidentifier) != 0) {
            /*
            logger(LOG_INFO,
                    "OpenLI RADIUS: NAS-Identifier for user %s has changed from %s to %s",
                    raddata->matcheduser->userid,
                    raddata->matcheduser->nasidentifier,
                    nasid);
            */
            free(raddata->matcheduser->nasidentifier);
        } else {
            return;
        }
    }

    raddata->matcheduser->nasidentifier = fast_strdup(nasid, keylen);
    raddata->matcheduser->nasid_len = keylen;
}

static inline void process_nasport_attribute(radius_parsed_t *raddata) {
    uint8_t attrnum = RADIUS_ATTR_NASPORT;

    radius_attribute_t *nasattr;

    nasattr = raddata->attrs;
    while (nasattr) {
        if (nasattr->att_type == RADIUS_ATTR_NASPORT) {
            break;
        }
        nasattr = nasattr->next;
    }

    if (!nasattr) {
        return;
    }

    raddata->nasport = *((uint32_t *)nasattr->att_val);
}

static inline void extract_assigned_ip_address(radius_global_t *glob,
        radius_parsed_t *raddata, radius_attribute_t *attrlist,
        access_session_t *sess) {

    uint8_t attrnum;
    radius_attribute_t *attr;
    struct sockaddr_storage *sa;

    if (!raddata->matcheduser) {
        return;
    }
    if (!sess) {
        return;
    }

    /* TODO is multiple address assignment a thing that happens in reality? */
    attr = attrlist;
    while (attr) {
        if (attr->att_type == RADIUS_ATTR_FRAMED_IP_ADDRESS) {
            struct sockaddr_in *in;

            in = (struct sockaddr_in *)&(sess->sessionip.assignedip);

            in->sin_family = AF_INET;
            in->sin_port = 0;
            in->sin_addr.s_addr = *((uint32_t *)attr->att_val);

            sess->sessionip.ipfamily = AF_INET;
            sess->sessionip.prefixbits = 32;

            return;
        }

        if (attr->att_type == RADIUS_ATTR_FRAMED_IPV6_ADDRESS) {
            struct sockaddr_in6 *in6;

            in6 = (struct sockaddr_in6 *)&(sess->sessionip.assignedip);

            in6->sin6_family = AF_INET6;
            in6->sin6_port = 0;
            in6->sin6_flowinfo = 0;

            memcpy(&(in6->sin6_addr.s6_addr), attr->att_val, 16);

            sess->sessionip.ipfamily = AF_INET6;
            sess->sessionip.prefixbits = 128;
            return;
        }

        if (attr->att_type == RADIUS_ATTR_FRAMED_IPV6_PREFIX) {
            struct sockaddr_in6 *in6;
            radius_v6_prefix_attr_t *prefattr;

            in6 = (struct sockaddr_in6 *)&(sess->sessionip.assignedip);

            in6->sin6_family = AF_INET6;
            in6->sin6_port = 0;
            in6->sin6_flowinfo = 0;

            prefattr = (radius_v6_prefix_attr_t *)(attr->att_val);
            memcpy(&(in6->sin6_addr.s6_addr), prefattr->address, 16);

            sess->sessionip.ipfamily = AF_INET6;
            sess->sessionip.prefixbits = prefattr->preflength;
            return;
        }

        attr = attr->next;
    }

}

static inline void find_matching_request(radius_global_t *glob,
        radius_parsed_t *raddata) {

    uint32_t reqid;

    if (raddata->msgtype == RADIUS_CODE_ACCOUNT_RESPONSE) {
        reqid = DERIVE_REQUEST_ID(raddata, RADIUS_CODE_ACCOUNT_REQUEST);
    } else {
        reqid = DERIVE_REQUEST_ID(raddata, RADIUS_CODE_ACCESS_REQUEST);
    }

    if (raddata->msgtype == RADIUS_CODE_ACCESS_ACCEPT ||
            raddata->msgtype == RADIUS_CODE_ACCESS_REJECT ||
            raddata->msgtype == RADIUS_CODE_ACCESS_CHALLENGE ||
            raddata->msgtype == RADIUS_CODE_ACCOUNT_RESPONSE) {

        radius_saved_req_t *req = NULL;

        HASH_FIND(hh, raddata->matchednas->request_map, &reqid,
                sizeof(reqid), req);

        if (req == NULL) {
            create_orphan(glob, &(raddata->matchednas->orphans),
                    &(raddata->matchednas->orphans_tail), raddata->origpkt,
                    raddata, reqid);
            return;
        }

        assert(raddata->matcheduser == NULL ||
                req->targetuser == raddata->matcheduser);
        raddata->matcheduser = req->targetuser;
        raddata->savedreq = req;
        raddata->accttype = raddata->savedreq->statustype;

        HASH_DELETE(hh, raddata->matchednas->request_map, req);
    }

}

static char *radius_get_userid(access_plugin_t *p, void *parsed,
        int *useridlen) {

    radius_parsed_t *raddata;
    radius_global_t *glob;
    char foo[128];

    glob = (radius_global_t *)(p->plugindata);
    raddata = (radius_parsed_t *)parsed;

    *useridlen = 0;
    if (raddata->matcheduser) {
        *useridlen = raddata->matcheduser->userid_len;
        return raddata->matcheduser->userid;
    }

    if (!raddata->matchednas) {
        logger(LOG_INFO, "OpenLI RADIUS: please parse the packet before attempting to get the user id.");
        return NULL;
    }

    process_username_attribute(raddata);
    //process_nasport_attribute(raddata);

    if (!raddata->matcheduser && (
            raddata->msgtype == RADIUS_CODE_ACCESS_REQUEST ||
            raddata->msgtype == RADIUS_CODE_ACCOUNT_REQUEST)) {
        logger(LOG_INFO,
                "OpenLI RADIUS: got a request with no User-Name field?");
        return NULL;
    }

    /* This must be a response packet, try to match it to a previously
     * seen request...
     */
    find_matching_request(glob, raddata);
    if (raddata->matcheduser) {
        *useridlen = raddata->matcheduser->userid_len;
        return raddata->matcheduser->userid;
    }
    return NULL;

}

static inline void apply_fsm_logic(radius_parsed_t *raddata,
        uint8_t msgtype, uint32_t accttype, session_state_t *newstate,
        access_action_t *action) {

    *action = ACCESS_ACTION_NONE;

    /* RADIUS state machine logic goes here */
    /* TODO figure out what Access-Failed is, since it is in the ETSI spec */
    if ((raddata->matcheduser->current == SESSION_STATE_NEW ||
            raddata->matcheduser->current == SESSION_STATE_OVER) && (
            msgtype == RADIUS_CODE_ACCESS_REQUEST ||
            (msgtype == RADIUS_CODE_ACCOUNT_REQUEST &&
                accttype == RADIUS_ACCT_START))) {

        raddata->matcheduser->current = SESSION_STATE_AUTHING;
        *action = ACCESS_ACTION_ATTEMPT;
    } else if (raddata->matcheduser->current == SESSION_STATE_AUTHING && (
            msgtype == RADIUS_CODE_ACCESS_REJECT)) {

        raddata->matcheduser->current = SESSION_STATE_OVER;
        *action = ACCESS_ACTION_REJECT;

    } else if (raddata->matcheduser->current == SESSION_STATE_AUTHING && (
            msgtype == RADIUS_CODE_ACCESS_CHALLENGE)) {

        raddata->matcheduser->current = SESSION_STATE_AUTHING;
        *action = ACCESS_ACTION_RETRY;

    } else if (raddata->matcheduser->current == SESSION_STATE_AUTHING && (
            msgtype == RADIUS_CODE_ACCOUNT_REQUEST &&
            accttype == RADIUS_ACCT_STOP)) {

        raddata->matcheduser->current = SESSION_STATE_OVER;
        *action = ACCESS_ACTION_FAILED;

    } else if (raddata->matcheduser->current == SESSION_STATE_AUTHING && (
            msgtype == RADIUS_CODE_ACCESS_ACCEPT ||
            (msgtype == RADIUS_CODE_ACCOUNT_RESPONSE &&
                accttype == RADIUS_ACCT_START))) {

        raddata->matcheduser->current = SESSION_STATE_ACTIVE;
        *action = ACCESS_ACTION_ACCEPT;

    } else if (raddata->matcheduser->current == SESSION_STATE_ACTIVE && (
            msgtype == RADIUS_CODE_ACCOUNT_RESPONSE &&
            (accttype == RADIUS_ACCT_START ||
                accttype == RADIUS_ACCT_INTERIM_UPDATE))) {

        *action = ACCESS_ACTION_INTERIM_UPDATE;

    } else if (raddata->matcheduser->current == SESSION_STATE_ACTIVE && (
            msgtype == RADIUS_CODE_ACCOUNT_RESPONSE &&
            accttype == RADIUS_ACCT_STOP)) {

        raddata->matcheduser->current = SESSION_STATE_OVER;
        *action = ACCESS_ACTION_END;

    } else if ((raddata->matcheduser->current == SESSION_STATE_NEW ||
            raddata->matcheduser->current == SESSION_STATE_OVER) && (
            msgtype == RADIUS_CODE_ACCOUNT_RESPONSE &&
            accttype == RADIUS_ACCT_INTERIM_UPDATE)) {

        /* session was already underway when we started the intercept,
         * jump straight to active and try to carry on from there.
         */

        raddata->matcheduser->current = SESSION_STATE_ACTIVE;
        *action = ACCESS_ACTION_ALREADY_ACTIVE;
    }


    *newstate = raddata->matcheduser->current;
}

static radius_orphaned_resp_t *search_orphans(radius_orphaned_resp_t **head,
        radius_orphaned_resp_t **tail, uint32_t reqid, double tvsec) {

    radius_orphaned_resp_t *iter, *prev, *tmp;

    prev = NULL;
    iter = *head;
    while (iter) {
        if (iter == *head && iter->tvsec + ORPHAN_EXPIRY < tvsec) {
            *head = iter->next;
            if (*tail == iter) {
                *tail = NULL;
            }
            /* XXX should really put these back in the free list */
            free_attribute_list(iter->savedattrs);
            tmp = iter;
            iter = iter->next;
            free(tmp);
            if (!warned) {
                logger(LOG_INFO,
                    "OpenLI RADIUS: expired orphaned response packet.");
                logger(LOG_INFO,
                    "OpenLI RADIUS: capture is possibly dropping RADIUS packets?");
                warned = 1;
            }
            continue;
        }

        if (iter->key == reqid) {
            break;
        }
        prev = iter;
        iter = iter->next;
    }

    if (iter == NULL) {
        return iter;
    }

    if (prev == NULL) {
        *head = iter->next;
    } else {
        prev->next = iter->next;
    }

    if (iter == *tail) {
        *tail = prev;
        if (prev) {
            prev->next = NULL;
        }
    }

    iter->next = NULL;
    return iter;

}

static inline int64_t translate_term_cause(uint32_t *tcause) {

    /* TODO verify that these are sensible mappings */

    switch(ntohl(*tcause)) {
        case 1:     // user request
            return IPIRI_END_REASON_REGULAR;
        case 4:     // idle timeout
        case 5:     // session timeout
            return IPIRI_END_REASON_CONNECTION_TIMEOUT;
        case 2:     // lost carrier
        case 3:     // lost service
        case 6:     // admin reset
        case 7:     // admin reboot
        case 8:     // port error
        case 9:     // nas error
        case 10:    // nas request
        case 11:    // nas reboot
        case 12:    // port unneeded
        case 13:    // port preempted
        case 14:    // port suspended
        case 15:    // service unavailable
        case 16:    // callback
        case 17:    // user error
        case 18:    // host request
            return IPIRI_END_REASON_CONNECTION_LOSS;
    }

    return IPIRI_END_REASON_UNDEFINED;
}

static inline char *quickcat(char *ptr, int *rem, char *toadd, int towrite) {

    if (*rem <= 1) {
        return ptr;
    }

    if (towrite < (*rem - 1)) {
        memcpy(ptr, toadd, towrite);
        *rem -= towrite;
        ptr += towrite;
    } else {
        memcpy(ptr, toadd, (*rem - 1));
        ptr += (*rem - 1);
        *rem = 1;
    }

    *ptr = '\0';
    return (ptr + 1);
}

/* Set firstattrs and secondattrs correctly for all possible
 * state changes. Possibly do as part of apply_fsm_logic?
 *
 * Have to account for savedresp, i.e. out of order exchanges.
 *
 * firstaction:
 * attempt = attrs
 * accept = attrs
 * already active = savedreq
 * interim update = savedreq
 * end = savedreq
 *
 * secondaction:
 * attempt = impossible?
 * accept = savedresp
 * interim update = attrs
 * already active = attrs
 * end = attrs
 */

static inline void update_first_action(radius_global_t *glob,
        radius_parsed_t *raddata, access_session_t *sess) {

    switch(raddata->firstaction) {
        case ACCESS_ACTION_ACCEPT:
            raddata->firstattrs = raddata->attrs;
            TIMESTAMP_TO_TV((&(sess->started)), raddata->tvsec);
            extract_assigned_ip_address(glob, raddata, raddata->attrs, sess);
            break;
        case ACCESS_ACTION_ALREADY_ACTIVE:
            raddata->firstattrs = raddata->savedreq->attrs;
            extract_assigned_ip_address(glob, raddata, raddata->savedreq->attrs,
                    sess);
            TIMESTAMP_TO_TV((&(sess->started)), raddata->savedreq->tvsec);
            break;
        case ACCESS_ACTION_ATTEMPT:
            raddata->firstattrs = raddata->attrs;
            break;
        case ACCESS_ACTION_INTERIM_UPDATE:
        case ACCESS_ACTION_END:
            raddata->firstattrs = raddata->savedreq->attrs;
            break;
        default:
            raddata->firstattrs = NULL;
    }
}

static inline void update_second_action(radius_global_t *glob,
        radius_parsed_t *raddata, access_session_t *sess) {


    if (raddata->secondaction == ACCESS_ACTION_ACCEPT &&
            raddata->savedresp->resptype == RADIUS_CODE_ACCESS_ACCEPT) {

        raddata->secondattrs = raddata->savedresp->savedattrs;
        extract_assigned_ip_address(glob, raddata, raddata->secondattrs, sess);
        TIMESTAMP_TO_TV((&(sess->started)), raddata->savedresp->tvsec);
        return;

    } else if ((raddata->secondaction == ACCESS_ACTION_ACCEPT ||
            raddata->secondaction == ACCESS_ACTION_ALREADY_ACTIVE) &&
            raddata->savedresp->resptype == RADIUS_CODE_ACCOUNT_RESPONSE) {

        raddata->secondattrs = raddata->attrs;
        extract_assigned_ip_address(glob, raddata, raddata->secondattrs, sess);
        TIMESTAMP_TO_TV((&(sess->started)), raddata->savedresp->tvsec);
        return;
    }

    switch(raddata->secondaction) {
        case ACCESS_ACTION_INTERIM_UPDATE:
        case ACCESS_ACTION_END:
        case ACCESS_ACTION_ALREADY_ACTIVE:
            raddata->secondattrs = raddata->attrs;
            break;
        default:
            raddata->secondattrs = NULL;
    }
}
static access_session_t *radius_update_session_state(access_plugin_t *p,
        void *parsed, access_session_t **sesslist,
        session_state_t *oldstate, session_state_t *newstate,
        access_action_t *action) {

    radius_global_t *glob;
    radius_parsed_t *raddata;
    access_session_t *thissess;
    char sessionid[1024];
    char *ptr;
    int rem = 1024;

    glob = (radius_global_t *)(p->plugindata);
    raddata = (radius_parsed_t *)parsed;
    if (!raddata || raddata->matcheduser == NULL) {
        return NULL;
    }

    /* If there is a NAS Identifier, grab it and use it */
    process_nasid_attribute(raddata);

    /* TODO fall back to NAS-IP */
    if (raddata->matcheduser->nasidentifier == NULL) {
        assert(0);
    }

    ptr = sessionid;
    ptr = quickcat(ptr, &rem, raddata->matcheduser->userid,
            raddata->matcheduser->userid_len);
    ptr = quickcat(ptr, &rem, "-", 1);
    ptr = quickcat(ptr, &rem, raddata->matcheduser->nasidentifier,
            raddata->matcheduser->nasid_len);


    thissess = *sesslist;
    while (thissess != NULL) {
        if (strcmp(thissess->sessionid, sessionid) == 0) {
            break;
        }
        thissess = thissess->next;
    }

    if (!thissess) {
        thissess = (access_session_t *)malloc(sizeof(access_session_t));

        thissess->plugin = p;
        thissess->sessionid = fast_strdup(sessionid, 1024 - rem);
        thissess->statedata = NULL;
        thissess->idlength = strlen(sessionid);
        thissess->cin = assign_cin(raddata);
        memset(&(thissess->sessionip), 0, sizeof(thissess->sessionip));

        thissess->iriseqno = 0;
        thissess->started.tv_sec = 0;
        thissess->started.tv_usec = 0;
        thissess->activeipentry = NULL;

        thissess->next = *sesslist;
        *sesslist = thissess;

    }


    if (raddata->msgtype == RADIUS_CODE_ACCESS_REQUEST ||
            raddata->msgtype == RADIUS_CODE_ACCOUNT_REQUEST) {

        /* Save the request so we can match the reply later on */
        radius_saved_req_t *req = NULL;
        radius_saved_req_t *check = NULL;

        radius_orphaned_resp_t *orphan = NULL;
        radius_attribute_t *attr, *attrcopy;

        orphan = search_orphans(
                &(raddata->matchednas->orphans),
                &(raddata->matchednas->orphans_tail),
                DERIVE_REQUEST_ID(raddata, raddata->msgtype), raddata->tvsec);
        if (orphan) {
            raddata->savedresp = orphan;
        } else {

            if (glob->freeaccreqs == NULL) {
                req = (radius_saved_req_t *)malloc(sizeof(radius_saved_req_t));
            } else {
                req = glob->freeaccreqs;
                glob->freeaccreqs = req->next;
            }

            req->reqid = DERIVE_REQUEST_ID(raddata, raddata->msgtype);
            req->targetuser = raddata->matcheduser;
            req->statustype = raddata->accttype;
            req->tvsec = raddata->tvsec;
            req->next = NULL;
            req->attrs = NULL;

            if (!raddata->savedresp) {
                HASH_FIND(hh, raddata->matchednas->request_map, &(req->reqid),
                        sizeof(req->reqid), check);
                if (check) {
                    /* The old one is probably an unanswered request, replace
                     * it with this one instead. */
                    release_attribute_list(&(glob->freeattrs), check->attrs);
                    release_saved_request(&(glob->freeaccreqs), check);
                    HASH_DELETE(hh, raddata->matchednas->request_map, check);
                }

                req->attrs = raddata->attrs;

                HASH_ADD_KEYPTR(hh, raddata->matchednas->request_map,
                        &(req->reqid), sizeof(req->reqid), req);
            }
        }
    }


    *oldstate = raddata->matcheduser->current;
    apply_fsm_logic(raddata, raddata->msgtype, raddata->accttype, newstate,
            &(raddata->firstaction));
    if (raddata->savedresp) {
        apply_fsm_logic(raddata, raddata->savedresp->resptype,
                raddata->accttype, newstate, &(raddata->secondaction));
    }

    update_first_action(glob, raddata, thissess);
    update_second_action(glob, raddata, thissess);

    if (raddata->firstaction != ACCESS_ACTION_NONE) {
        *action = raddata->firstaction;
    } else if (raddata->secondaction != ACCESS_ACTION_NONE) {
        *action = raddata->secondaction;
        raddata->firstaction = raddata->secondaction;
        raddata->secondaction = ACCESS_ACTION_NONE;
        raddata->firstattrs = raddata->secondattrs;
        raddata->secondattrs = NULL;
    } else {
        *action = ACCESS_ACTION_NONE;
    }
    return thissess;
}

static int generate_iri(etsili_generic_t **paramlist,
        etsili_generic_freelist_t *freegenerics, radius_parsed_t *raddata,
        radius_attribute_t *attr,
        struct timeval *tv, uint32_t eventtype, etsili_iri_type_t *iritype) {


    etsili_generic_t *np;
    int64_t nasport;
    etsili_ipaddress_t nasip;
    ipiri_id_t nasid;
    int64_t inocts, outocts, endreason;


    /* XXX Static generics aren't going to work anymore -- we'll need to
     * copy them into memory that we control...
     */
    np = create_etsili_generic(freegenerics,
            IPIRI_CONTENTS_ACCESS_EVENT_TYPE, sizeof(uint32_t),
            (uint8_t *)(&eventtype));
    HASH_ADD_KEYPTR(hh, *paramlist, &(np->itemnum), sizeof(np->itemnum), np);

    if (*iritype == ETSILI_IRI_END) {
        np = create_etsili_generic(freegenerics,
                IPIRI_CONTENTS_ENDTIME, sizeof(struct timeval),
                (uint8_t *)tv);
        HASH_ADD_KEYPTR(hh, *paramlist, &(np->itemnum), sizeof(np->itemnum),
                np);

    }

    while (attr) {
        uint8_t iriattr = 0xff;
        uint16_t attrlen = attr->att_len;
        uint8_t *attrptr = attr->att_val;

        /* We may need to convert some of these attributes to a
         * "standard" format that etsili_core functions expect.
         */
        switch(attr->att_type) {
            case RADIUS_ATTR_NASPORT:
                /* uint32_t -> int64_t */
                iriattr = IPIRI_CONTENTS_POP_PORTNUMBER;
                attrlen = sizeof(int64_t);
                nasport = (int64_t) ntohl(*((uint32_t *)(attr->att_val)));
                attrptr = (uint8_t *)(&nasport);
                break;
            case RADIUS_ATTR_NASIP:
                /* uint32_t -> IPAddress */
                iriattr = IPIRI_CONTENTS_POP_IPADDRESS;
                etsili_create_ipaddress_v4((uint32_t *)(attr->att_val),
                        ETSILI_IPV4_SUBNET_UNKNOWN,
                        ETSILI_IPADDRESS_ASSIGNED_UNKNOWN, &nasip);
                attrlen = sizeof(etsili_ipaddress_t);
                attrptr = (uint8_t *)(&nasip);
                break;
            case RADIUS_ATTR_NASIDENTIFIER:
                /* String -> IPIRIIDType */
                iriattr = IPIRI_CONTENTS_POP_IDENTIFIER;
                if (ipiri_create_id_printable((char *)(attr->att_val),
                        attr->att_len, &nasid) < 0) {
                    logger(LOG_INFO, "OpenLI: Unable to convert RADIUS NAS Identifier attribute into a printable POP Identifier");
                    break;
                }
                attrlen = sizeof(ipiri_id_t);
                attrptr = (uint8_t *)(&nasid);
                break;
            case RADIUS_ATTR_CALLED_STATION_ID:
                /* String -> String */
                iriattr = IPIRI_CONTENTS_POP_PHONENUMBER;
                break;
            case RADIUS_ATTR_CALLING_STATION_ID:
                /* String -> String */
                iriattr = IPIRI_CONTENTS_TARGET_NETWORKID;
                break;
            case RADIUS_ATTR_ACCT_TERMINATE_CAUSE:
                /* uint32_t -> EndReason */
                iriattr = IPIRI_CONTENTS_ENDREASON;
                endreason = translate_term_cause((uint32_t *)(attr->att_val));
                attrlen = sizeof(endreason);
                attrptr = (uint8_t *)(&endreason);
                break;
            case RADIUS_ATTR_ACCT_INOCTETS:
                iriattr = IPIRI_CONTENTS_OCTETS_RECEIVED;
                inocts = (int64_t) ntohl(*((uint32_t *)(attr->att_val)));
                attrlen = sizeof(int64_t);
                attrptr = (uint8_t *)&inocts;
                break;
            case RADIUS_ATTR_ACCT_OUTOCTETS:
                iriattr = IPIRI_CONTENTS_OCTETS_TRANSMITTED;
                outocts = (int64_t) ntohl(*((uint32_t *)(attr->att_val)));
                attrlen = sizeof(int64_t);
                attrptr = (uint8_t *)&outocts;
                break;
        }
        if (iriattr != 0xff) {
            np = create_etsili_generic(freegenerics, iriattr,
                    attrlen, attrptr);
            HASH_ADD_KEYPTR(hh, *paramlist, &(np->itemnum),
                    sizeof(np->itemnum), np);
        }
        attr = attr->next;
    }

    return 0;

}

static int radius_generate_access_attempt_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freelist, radius_parsed_t *raddata,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_REPORT;

    return generate_iri(params, freelist, raddata, attrs,
            tv, IPIRI_ACCESS_ATTEMPT, iritype);
}


static int radius_generate_access_accept_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freelist, radius_parsed_t *raddata,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_BEGIN;

    return generate_iri(params, freelist, raddata, attrs,
            tv, IPIRI_ACCESS_ACCEPT, iritype);
}

static int radius_generate_interim_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freelist, radius_parsed_t *raddata,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_CONTINUE;

    return generate_iri(params, freelist, raddata, attrs,
            tv, IPIRI_INTERIM_UPDATE, iritype);
}

static int radius_generate_access_end_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freelist, radius_parsed_t *raddata,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_END;

    return generate_iri(params, freelist, raddata, attrs,
            tv, IPIRI_ACCESS_END, iritype);
}

static int radius_generate_access_reject_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freelist, radius_parsed_t *raddata,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_REPORT;

    return generate_iri(params, freelist, raddata, attrs,
            tv, IPIRI_ACCESS_REJECT, iritype);
}

static int radius_generate_access_failed_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freelist, radius_parsed_t *raddata,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_REPORT;

    return generate_iri(params, freelist, raddata, attrs,
            tv, IPIRI_ACCESS_FAILED, iritype);
}

static int radius_generate_already_active_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freelist, radius_parsed_t *raddata,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_BEGIN;

    return generate_iri(params, freelist, raddata, attrs,
            tv, IPIRI_START_WHILE_ACTIVE, iritype);
}

static inline int action_to_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freegenerics, radius_parsed_t *raddata,
        access_action_t action, radius_attribute_t *attrs,
        etsili_iri_type_t *iritype) {

    struct timeval tv;
    TIMESTAMP_TO_TV((&tv), raddata->tvsec);

    switch(action) {
        case ACCESS_ACTION_ATTEMPT:
            if (radius_generate_access_attempt_iri(params, freegenerics,
                        raddata, attrs, &tv, iritype) < 0) {
                return -1;
            }
            break;
        case ACCESS_ACTION_ACCEPT:
            if (radius_generate_access_accept_iri(params, freegenerics,
                        raddata, attrs, &tv, iritype) < 0) {
                return -1;
            }
            break;
        case ACCESS_ACTION_END:
            if (radius_generate_access_end_iri(params, freegenerics,
                        raddata, attrs, &tv, iritype) < 0) {
                return -1;
            }
            break;
        case ACCESS_ACTION_INTERIM_UPDATE:
            if (radius_generate_interim_iri(params, freegenerics,
                        raddata, attrs, &tv, iritype) < 0) {
                return -1;
            }
            break;
        case ACCESS_ACTION_REJECT:
            if (radius_generate_access_reject_iri(params, freegenerics,
                        raddata, attrs, &tv, iritype) < 0) {
                return -1;
            }
            break;
        case ACCESS_ACTION_FAILED:
            if (radius_generate_access_failed_iri(params, freegenerics,
                        raddata, attrs, &tv, iritype) < 0) {
                return -1;
            }
            break;
        case ACCESS_ACTION_ALREADY_ACTIVE:
            if (radius_generate_already_active_iri(params, freegenerics,
                        raddata, attrs, &tv, iritype) < 0) {
                return -1;
            }
            break;
        default:
            logger(LOG_INFO,
                    "OpenLI RADIUS: cannot generate IRI for unknown action %u",
                    action);
            return -1;
    }

    return 0;

}

static int radius_generate_iri_data(access_plugin_t *p, void *parseddata,
        etsili_generic_t **params, etsili_iri_type_t *iritype,
        etsili_generic_freelist_t *freelist, int iteration) {

    radius_global_t *radglob;
    radius_parsed_t *raddata;

    radglob = (radius_global_t *)(p->plugindata);
    raddata = (radius_parsed_t *)parseddata;

    if (iteration == 0) {
        if (raddata->firstaction == ACCESS_ACTION_NONE) {
            return -1;
        }

        if (action_to_iri(params, freelist, raddata, raddata->firstaction,
                raddata->firstattrs, iritype) < 0) {
            return -1;
        }

        if (raddata->secondaction != ACCESS_ACTION_NONE) {
            return 1;
        }
        return 0;
    }

    if (iteration == 1 && raddata->secondaction != ACCESS_ACTION_NONE) {
        if (action_to_iri(params, freelist, raddata, raddata->secondaction,
                raddata->secondattrs, iritype) < 0) {
            return -1;
        }
        return 0;
    }

    logger(LOG_INFO,
            "OpenLI RADIUS: invalid iteration in radius_generate_iri_data (%d)",
            iteration);
    return -1;
}

static void radius_destroy_session_data(access_plugin_t *p,
        access_session_t *sess) {

    if (sess->sessionid) {
        free(sess->sessionid);
    }

    return;
}

static access_plugin_t radiusplugin = {

    "RADIUS",
    ACCESS_RADIUS,
    NULL,

    radius_init_plugin_data,
    radius_destroy_plugin_data,
    radius_parse_packet,
    radius_destroy_parsed_data,
    radius_uncouple_parsed_data,
    radius_get_userid,
    radius_update_session_state,
    radius_generate_iri_data,
    //radius_create_iri_from_packet,
    radius_destroy_session_data
};

access_plugin_t *get_radius_access_plugin(void) {
    return &radiusplugin;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
