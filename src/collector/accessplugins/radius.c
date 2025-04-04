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
    RADIUS_ATTR_DELEGATED_IPV6_PREFIX = 123,
    RADIUS_ATTR_FRAMED_IPV6_ADDRESS = 168,
};

enum {
    RADIUS_ACCT_START = 1,
    RADIUS_ACCT_STOP = 2,
    RADIUS_ACCT_INTERIM_UPDATE = 3,
};

typedef struct radius_user radius_user_t;

typedef struct radius_session {
    uint32_t session_id;
    session_state_t current;

    uint32_t nas_port;
    int64_t octets_received;
    int64_t octets_sent;
    char *nasidentifier;
    uint8_t *nas_ip;
    int nas_ip_family;

    radius_user_t *parent;

} radius_user_session_t;

typedef struct radius_nas_t radius_nas_t;

struct radius_user {

    user_identity_method_t idmethod;
    char *userid;
    char *nasidentifier;
    int nasid_len;

    Pvoid_t sessions;
    Pvoid_t savedrequests;
    radius_nas_t *parent_nas;

    time_t inactive_since;
};

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
    uint32_t acctsess_hash;
    double tvsec;
    radius_attribute_t *attrs;

    radius_user_t *targetusers[USER_IDENT_MAX];
    int targetuser_count;
    int active_targets;

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

struct radius_nas_t {
    uint8_t *nasip;
    Pvoid_t user_map;
    radius_saved_req_t *request_map;

    radius_orphaned_resp_t *orphans;
    radius_orphaned_resp_t *orphans_tail;

};

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
    uint32_t acctsess_hash;
    uint32_t nasport;
    double tvsec;
    radius_attribute_t *attrs;

    struct sockaddr_storage nasip;
    struct sockaddr_storage radiusip;
    uint16_t sourceport;

    int muser_count;
    radius_user_t *matchedusers[USER_IDENT_MAX];
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
    parsed->matchednas = NULL;
    parsed->matchedserv = NULL;
    parsed->savedreq = NULL;
    parsed->savedresp = NULL;
    parsed->muser_count = 0;
    parsed->acctsess_hash = 0;
    memset(parsed->matchedusers, 0, sizeof(radius_user_t *) * USER_IDENT_MAX);
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
        case RADIUS_ATTR_DELEGATED_IPV6_PREFIX:
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
            attr->att_val = calloc(1, STANDARD_ATTR_ALLOC);
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

static void destroy_radius_user(radius_user_t *user, unsigned char *userind) {

    Word_t res, index;
    PWord_t pval;
    int rcint, i;

    JSLD(rcint, user->parent_nas->user_map, userind);
    if (user->userid) {
        free(user->userid);
    }
    if (user->nasidentifier) {
        free(user->nasidentifier);
    }

    index = 0;
    JLF(pval, user->sessions, index);
    while (pval) {
        radius_user_session_t *usess = (radius_user_session_t *)(*pval);
        if (usess->nasidentifier) {
            free(usess->nasidentifier);
        }
        if (usess->nas_ip) {
            free(usess->nas_ip);
        }

        free(usess);
        JLN(pval, user->sessions, index);
    }
    index = 0;
    JLF(pval, user->savedrequests, index);
    while (pval) {
        radius_saved_req_t *req = (radius_saved_req_t *)(*pval);
        for (i = 0; i < req->targetuser_count; i++) {
            if (req->targetusers[i] == NULL) {
                continue;
            }
            if (req->targetusers[i] == user) {
                req->targetusers[i] = NULL;
                req->active_targets --;
                break;
            }
        }
        if (req->active_targets <= 0) {
            HASH_DELETE(hh, user->parent_nas->request_map, req);
            free_attribute_list(req->attrs);
            free(req);
        }
        JLN(pval, user->savedrequests, index);
    }

    JLFA(res, user->savedrequests);
    JLFA(res, user->sessions);
    free(user);
}

static void destroy_radius_nas(radius_nas_t *nas) {
    radius_orphaned_resp_t *orph, *tmporph;
    radius_saved_req_t *req, *tmpreq;
    radius_user_t *user;
    PWord_t pval;
    unsigned char index[128];
    Word_t res;

    index[0] = '\0';
    JSLF(pval, nas->user_map, index);
    while (pval) {
        user = (radius_user_t *)(*pval);
        destroy_radius_user(user, index);
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
    unsigned char index[128];

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
    radius_saved_req_t *req, *tmpreq;
    PWord_t pval;
    unsigned char index[128];
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
        if (rparsed->savedresp || rparsed->muser_count == 0) {
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

static void create_orphan(radius_orphaned_resp_t **head,
        radius_orphaned_resp_t **tail, libtrace_packet_t *pkt,
        radius_parsed_t *raddata, uint32_t reqid) {

    /* Hopefully this is rare enough that we don't need a freelist of
     * orphaned responses */

    radius_orphaned_resp_t *resp, *iter;

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
    unsigned char hashkey[20];
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

    radstart = (uint8_t *)get_udp_payload(pkt, &rem, &sourceport, &destport);
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

        if (att_len <= 2) {
            break;
        }

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
            if (newattr->att_type == RADIUS_ATTR_ACCT_SESSION_ID) {
                char sessstr[24];

                memset(sessstr, 0, 24);
                if (att_len - 2 > 23) {
                    memcpy(sessstr, newattr->att_val, 23);
                } else {
                    memcpy(sessstr, newattr->att_val, att_len - 2);
                }

                parsed->acctsess_hash = hashlittle(sessstr, strlen(sessstr),
                        0x85F8B41B);
            }
        }

        rem -= att_len;
        ptr += (att_len - 2);
    }

    return parsed;
}

static radius_user_t *add_user_identity(uint8_t att_type, uint8_t *att_val,
        uint8_t att_len, radius_parsed_t *raddata) {

    char userkey[2048];
    char *nextchar;
    int keyrem = 2047;
    int index;
    radius_user_t *user;
    user_identity_method_t method = USER_IDENT_MAX;
    PWord_t pval;

    if (att_type == RADIUS_ATTR_USERNAME) {
        memcpy(userkey, "raduser-", 8);
        keyrem -= 8;
        nextchar = userkey + 8;
        method = USER_IDENT_RADIUS_USERNAME;
    } else if (att_type == RADIUS_ATTR_CALLING_STATION_ID) {
        memcpy(userkey, "radcsid-", 8);
        keyrem -= 8;
        nextchar = userkey + 8;
        method = USER_IDENT_RADIUS_CSID;
    } else {
        return NULL;
    }

    assert(keyrem > att_len);

    memcpy(nextchar, att_val, att_len);
    nextchar += att_len;
    keyrem -= att_len;

    *nextchar = '\0';

    JSLG(pval, raddata->matchednas->user_map, (unsigned char *)userkey);

    if (pval) {
        index = raddata->muser_count;
        raddata->muser_count ++;
        raddata->matchedusers[index] = (radius_user_t *)(*pval);
        raddata->matchedusers[index]->inactive_since = 0;
        return raddata->matchedusers[index];
    }

    user = (radius_user_t *)calloc(1, sizeof(radius_user_t));

    user->userid = strdup(userkey);
    user->idmethod = method;
    user->nasidentifier = NULL;
    user->nasid_len = 0;
    user->sessions = NULL;
    user->savedrequests = NULL;
    user->parent_nas = raddata->matchednas;
    user->inactive_since = 0;
    //user->current = SESSION_STATE_NEW;

    JSLI(pval, raddata->matchednas->user_map, (unsigned char *)user->userid);
    *pval = (Word_t)user;
    index = raddata->muser_count;
    raddata->matchedusers[index] = user;
    raddata->muser_count ++;
    return raddata->matchedusers[index];

}

static int process_username_attribute(radius_parsed_t *raddata) {

    radius_attribute_t *userattr;
    radius_user_t *raduser;
    int gotusername = -1;

    if (raddata->msgtype != RADIUS_CODE_ACCESS_REQUEST &&
            raddata->msgtype != RADIUS_CODE_ACCOUNT_REQUEST) {
        return 0;
    }

    userattr = raddata->attrs;
    while (userattr) {
        switch(userattr->att_type) {
            case RADIUS_ATTR_USERNAME:
                gotusername = 1;
                // fall through
            case RADIUS_ATTR_CALLING_STATION_ID:
                raduser = add_user_identity(userattr->att_type,
                        userattr->att_val, userattr->att_len, raddata);
                assert(raduser);
                break;
        }
        userattr = userattr->next;
    }

    return gotusername;
}

static uint32_t assign_cin(radius_parsed_t *raddata) {

    /* CIN assignment for RADIUS sessions:
     *
     * Use the Acct-Session-ID if available -- often present in
     * Access-Requests but not guaranteed.
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
            /* Modulo 2^31 to avoid possible issues with the CIN
             * being treated as a negative number by the recipient.
             */
            hashval = raddata->acctsess_hash % (uint32_t)(pow(2, 31));
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

static inline void nasid_to_string(radius_attribute_t *nasattr, char *strspace,
        int spacelen, int *keylen) {

    assert (spacelen >= 256);

    memcpy(strspace, nasattr->att_val, nasattr->att_len);
    strspace[nasattr->att_len] = '\0';
    *keylen = nasattr->att_len;
}

static inline void process_nasid_attribute(radius_parsed_t *raddata) {
    char nasid[1024];
    int keylen = 0, i;

    radius_attribute_t *nasattr;

    if (raddata->muser_count == 0) {
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

    nasid_to_string(nasattr, nasid, 1024, &keylen);

    for (i = 0; i < raddata->muser_count; i++) {
        if (raddata->matchedusers[i]->nasidentifier) {
            if (strcmp(nasid, raddata->matchedusers[i]->nasidentifier) != 0) {
            /*
                logger(LOG_INFO,
                        "OpenLI RADIUS: NAS-Identifier for user %s has changed from %s to %s",
                        raddata->matchedusers[i]->userid,
                        raddata->matchedusers[i]->nasidentifier,
                        nasid);
            */
                free(raddata->matchedusers[i]->nasidentifier);
            } else {
                continue;
            }
        }

        raddata->matchedusers[i]->nasidentifier = fast_strdup(nasid, keylen);
        raddata->matchedusers[i]->nasid_len = keylen;
    }
}

static inline void process_nasport_attribute(radius_parsed_t *raddata) {

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

static void update_user_session_data(radius_parsed_t *raddata,
        radius_user_session_t *usess) {

    radius_attribute_t *attr = raddata->attrs;
    char strspace[1024];
    int nasidlen = 0;

    if (usess == NULL) {
        return;
    }

    while (attr) {
        switch (attr->att_type) {
            case RADIUS_ATTR_NASPORT:
                usess->nas_port = ntohl(*((uint32_t *)attr->att_val));
                break;
            case RADIUS_ATTR_NASIDENTIFIER:
                if (usess->nasidentifier == NULL) {
                    nasid_to_string(attr, strspace, 1024, &nasidlen);
                    usess->nasidentifier = strdup(strspace);
                }
                break;
            case RADIUS_ATTR_NASIP:
                /* XXX v4 only? */
                if (usess->nas_ip == NULL) {
                    usess->nas_ip_family = AF_INET;
                    usess->nas_ip = calloc(1, sizeof(uint32_t));
                    memcpy(usess->nas_ip, attr->att_val, sizeof(uint32_t));
                }
                break;
            case RADIUS_ATTR_ACCT_INOCTETS:
                usess->octets_received =
                        (int64_t) ntohl(*((uint32_t *)(attr->att_val)));
                break;
            case RADIUS_ATTR_ACCT_OUTOCTETS:
                usess->octets_sent =
                        (int64_t) ntohl(*((uint32_t *)(attr->att_val)));
                break;
        }
        attr = attr->next;
    }
}

static inline void extract_assigned_ip_address(radius_parsed_t *raddata,
        radius_attribute_t *attrlist, access_session_t *sess) {

    radius_attribute_t *attr;

    if (!raddata->muser_count) {
        return;
    }
    if (!sess) {
        return;
    }

    attr = attrlist;
    while (attr) {
        if (attr->att_type == RADIUS_ATTR_FRAMED_IP_ADDRESS) {
            add_new_session_ip(sess, attr->att_val, AF_INET, 32, attr->att_len);
        }

        if (attr->att_type == RADIUS_ATTR_FRAMED_IPV6_ADDRESS) {
            add_new_session_ip(sess, attr->att_val, AF_INET6, 128, attr->att_len);
        }

        if (attr->att_type == RADIUS_ATTR_DELEGATED_IPV6_PREFIX ||
                attr->att_type == RADIUS_ATTR_FRAMED_IPV6_PREFIX) {

            radius_v6_prefix_attr_t *prefattr;
            prefattr = (radius_v6_prefix_attr_t *)(attr->att_val);

            add_new_session_ip(sess, prefattr->address, AF_INET6,
                    prefattr->preflength, attr->att_len - 2);

            return;
        }

        attr = attr->next;
    }

}

static inline void find_matching_request(radius_parsed_t *raddata) {

    uint32_t reqid;
    int rcint, i;

    reqid = DERIVE_REQUEST_ID(raddata, RADIUS_CODE_ACCESS_REQUEST);

    if (raddata->msgtype == RADIUS_CODE_ACCESS_ACCEPT ||
            raddata->msgtype == RADIUS_CODE_ACCESS_REJECT ||
            raddata->msgtype == RADIUS_CODE_ACCESS_CHALLENGE) {

        radius_saved_req_t *req = NULL;

        HASH_FIND(hh, raddata->matchednas->request_map, &reqid,
                sizeof(reqid), req);

        if (req == NULL) {
            create_orphan(&(raddata->matchednas->orphans),
                    &(raddata->matchednas->orphans_tail), raddata->origpkt,
                    raddata, reqid);
            return;
        }

        raddata->savedreq = req;
        raddata->accttype = raddata->savedreq->statustype;
        raddata->acctsess_hash = raddata->savedreq->acctsess_hash;

        memcpy(raddata->matchedusers, raddata->savedreq->targetusers,
                sizeof(radius_user_t *) * USER_IDENT_MAX);
        raddata->muser_count = raddata->savedreq->targetuser_count;

        for (i = 0; i < raddata->muser_count; i++) {
            if (raddata->matchedusers[i]) {
                JLD(rcint, raddata->matchedusers[i]->savedrequests, reqid);
            }
        }

        HASH_DELETE(hh, raddata->matchednas->request_map, req);
    }

}


static user_identity_t *radius_get_userid(access_plugin_t *p UNUSED,
        void *parsed, int *numberids) {

    radius_parsed_t *raddata;
    int i, idx;
    user_identity_t *idarray = NULL;

    raddata = (radius_parsed_t *)parsed;
    *numberids = 0;

    if (raddata->msgtype == RADIUS_CODE_ACCOUNT_RESPONSE) {
        raddata->muser_count = 0;
        return NULL;
    }

    if (raddata->muser_count == 0) {
        if (!raddata->matchednas) {
            logger(LOG_INFO, "OpenLI RADIUS: please parse the packet before attempting to get the user id.");
            return NULL;
        }

        if (process_username_attribute(raddata) == -1) {
            raddata->muser_count = 0;
            return NULL;
        }
    }

    //process_nasport_attribute(raddata);

    if (raddata->msgtype == RADIUS_CODE_ACCESS_REQUEST) {
        if (raddata->muser_count == 0) {
            return NULL;
        }

    } else {
        /* This must be a response packet, try to match it to a previously
         * seen request...
         */
        find_matching_request(raddata);
    }

    if (raddata->muser_count == 0) {
        return NULL;
    }

    /* If there is a NAS Identifier, grab it and use it */
    process_nasid_attribute(raddata);

    idarray = calloc(raddata->muser_count, sizeof(user_identity_t));
    idx = 0;

    for (i = 0; i < USER_IDENT_MAX; i++) {
        char *stripped;
        if (raddata->matchedusers[i] == NULL) {
            continue;
        }

        idarray[idx].method = raddata->matchedusers[i]->idmethod;

        stripped = strchr(raddata->matchedusers[i]->userid, '-');
        if (stripped == NULL) {
            idarray[idx].idstr = strdup(raddata->matchedusers[i]->userid);
        } else {
            idarray[idx].idstr = strdup(stripped + 1);
        }

        idarray[idx].idlength = strlen(idarray[idx].idstr);
        idarray[idx].plugindata = (void *)(raddata->matchedusers[i]);

        idx ++;
    }

    *numberids = idx;
    return idarray;

}

static inline void apply_fsm_logic(
        radius_user_session_t *radsess, uint8_t msgtype, uint32_t accttype,
        session_state_t *newstate, access_action_t *action) {

    *action = ACCESS_ACTION_NONE;

    /* RADIUS state machine logic goes here */
    /* TODO figure out what Access-Failed is, since it is in the ETSI spec */
    if ((radsess->current == SESSION_STATE_NEW ||
            radsess->current == SESSION_STATE_OVER) && (
            msgtype == RADIUS_CODE_ACCESS_REQUEST)) {

        radsess->current = SESSION_STATE_AUTHING;
        *action = ACCESS_ACTION_ATTEMPT;
    } else if ((radsess->current == SESSION_STATE_NEW ||
            radsess->current == SESSION_STATE_OVER) && (
            msgtype == RADIUS_CODE_ACCOUNT_REQUEST &&
                accttype == RADIUS_ACCT_START)) {

        radsess->current = SESSION_STATE_ACTIVE;
        *action = ACCESS_ACTION_ACCEPT;

    } else if (radsess->current == SESSION_STATE_AUTHING && (
            msgtype == RADIUS_CODE_ACCESS_REJECT)) {

        radsess->current = SESSION_STATE_OVER;
        *action = ACCESS_ACTION_REJECT;

    } else if (radsess->current == SESSION_STATE_AUTHING && (
            msgtype == RADIUS_CODE_ACCESS_CHALLENGE)) {

        radsess->current = SESSION_STATE_AUTHING;
        *action = ACCESS_ACTION_RETRY;

    } else if (radsess->current == SESSION_STATE_AUTHING &&
            msgtype == RADIUS_CODE_ACCESS_ACCEPT) {

        radsess->current = SESSION_STATE_ACTIVE;
        *action = ACCESS_ACTION_ACCEPT;

    } else if ((radsess->current == SESSION_STATE_ACTIVE ||
                radsess->current == SESSION_STATE_ACTIVE_NO_IP) &&
            (msgtype == RADIUS_CODE_ACCOUNT_REQUEST &&
            (accttype == RADIUS_ACCT_START ||
                accttype == RADIUS_ACCT_INTERIM_UPDATE))) {

        /* Always set to "active" -- we'll later reset to "active NO IP"
         * if we still don't have an IP before we return the sync thread.
         */
        radsess->current = SESSION_STATE_ACTIVE;
        *action = ACCESS_ACTION_INTERIM_UPDATE;

    } else if ((radsess->current == SESSION_STATE_ACTIVE ||
                radsess->current == SESSION_STATE_ACTIVE_NO_IP) &&
            (msgtype == RADIUS_CODE_ACCOUNT_REQUEST &&
            accttype == RADIUS_ACCT_STOP)) {

        radsess->current = SESSION_STATE_OVER;
        *action = ACCESS_ACTION_END;

    } else if ((radsess->current == SESSION_STATE_NEW ||
            radsess->current == SESSION_STATE_OVER) && (
            msgtype == RADIUS_CODE_ACCOUNT_REQUEST &&
            accttype == RADIUS_ACCT_INTERIM_UPDATE)) {

        /* session was already underway when we started the intercept,
         * jump straight to active and try to carry on from there.
         */

        radsess->current = SESSION_STATE_ACTIVE;
        *action = ACCESS_ACTION_ALREADY_ACTIVE;
    }

    *newstate = radsess->current;
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
    return (ptr);
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

static inline void update_first_action(radius_parsed_t *raddata,
        access_session_t *sess) {

    switch(raddata->firstaction) {
        case ACCESS_ACTION_ACCEPT:
            raddata->firstattrs = raddata->attrs;
            TIMESTAMP_TO_TV((&(sess->started)), raddata->tvsec);
            extract_assigned_ip_address(raddata, raddata->attrs, sess);
            break;
        case ACCESS_ACTION_ALREADY_ACTIVE:
            raddata->firstattrs = raddata->savedreq->attrs;
            extract_assigned_ip_address(raddata, raddata->savedreq->attrs,
                    sess);
            TIMESTAMP_TO_TV((&(sess->started)), raddata->savedreq->tvsec);
            break;
        case ACCESS_ACTION_ATTEMPT:
            if (raddata->msgtype == RADIUS_CODE_ACCOUNT_REQUEST) {
                extract_assigned_ip_address(raddata, raddata->attrs,
                        sess);
                TIMESTAMP_TO_TV((&(sess->started)), raddata->tvsec);
            }
            raddata->firstattrs = raddata->attrs;
            break;
        case ACCESS_ACTION_INTERIM_UPDATE:
            /* handle rare case where assigned IPs were missing from access
             * accept message -- seen this in the wild */
            raddata->firstattrs = raddata->savedreq->attrs;
            if (raddata->msgtype == RADIUS_CODE_ACCOUNT_REQUEST &&
                    raddata->accttype == RADIUS_ACCT_START &&
                    sess->sessipcount == 0) {
                extract_assigned_ip_address(raddata, raddata->firstattrs,
                        sess);
            }
            break;
        case ACCESS_ACTION_END:
            raddata->firstattrs = raddata->savedreq->attrs;
            break;
        default:
            raddata->firstattrs = NULL;
    }
}

static inline void update_second_action(radius_parsed_t *raddata,
        access_session_t *sess) {


    if (raddata->secondaction == ACCESS_ACTION_ACCEPT &&
            raddata->savedresp->resptype == RADIUS_CODE_ACCESS_ACCEPT) {

        raddata->secondattrs = raddata->savedresp->savedattrs;
        extract_assigned_ip_address(raddata, raddata->secondattrs, sess);
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
        void *parsed, void *plugindata, access_session_t **sesslist,
        session_state_t *oldstate, session_state_t *newstate,
        access_action_t *action) {

    radius_global_t *glob;
    radius_parsed_t *raddata;
    radius_user_t *raduser = (radius_user_t *)plugindata;
    access_session_t *thissess;
    radius_user_session_t *usess;
    radius_saved_req_t *req = NULL;

    uint32_t reqid;
    char sessionid[5000];
    char tempstr[24];
    char *ptr;
    int rem = 5000, i;
    PWord_t pval;

    glob = (radius_global_t *)(p->plugindata);
    raddata = (radius_parsed_t *)parsed;
    if (!raddata || raddata->muser_count == 0 || raduser == NULL) {
        return NULL;
    }

    /* TODO fall back to NAS-IP */
    if (raduser->nasidentifier == NULL) {
        raduser->nasidentifier = strdup("unknown");
        raduser->nasid_len = strlen(raduser->nasidentifier);
    }

    ptr = sessionid;
    ptr = quickcat(ptr, &rem, raduser->userid, strlen(raduser->userid));
    ptr = quickcat(ptr, &rem, "-", 1);
    ptr = quickcat(ptr, &rem, raduser->nasidentifier, raduser->nasid_len);
    ptr = quickcat(ptr, &rem, "-", 1);

    snprintf(tempstr, 24, "%u", raddata->acctsess_hash);
    ptr = quickcat(ptr, &rem, tempstr, strlen(tempstr));

    HASH_FIND(hh, *sesslist, sessionid, strlen(sessionid), thissess);

    if (!thissess) {
        thissess = create_access_session(p, sessionid, 5000 - rem);
        thissess->cin = assign_cin(raddata);
        thissess->identifier_type = OPENLI_ACCESS_SESSION_IP;

        HASH_ADD_KEYPTR(hh, *sesslist, thissess->sessionid,
                strlen(thissess->sessionid), thissess);
    }

    if (raddata->msgtype == RADIUS_CODE_ACCOUNT_REQUEST) {
        reqid = DERIVE_REQUEST_ID(raddata, raddata->msgtype);

        if (raddata->savedreq) {
            if (raddata->savedreq->reqid == reqid) {
                goto usessupdate;
            }
            release_attribute_list(&(glob->freeattrs),
                    raddata->savedreq->attrs);
            release_saved_request(&(glob->freeaccreqs), raddata->savedreq);
            raddata->savedreq = NULL;
        }

        if (glob->freeaccreqs == NULL) {
            req = (radius_saved_req_t *)malloc(
                    sizeof(radius_saved_req_t));
        } else {
            req = glob->freeaccreqs;
            glob->freeaccreqs = req->next;
        }

        req->reqid = reqid;
        req->statustype = raddata->accttype;
        req->acctsess_hash = raddata->acctsess_hash;
        req->tvsec = raddata->tvsec;
        req->next = NULL;
        req->attrs = raddata->attrs;
        req->targetuser_count = raddata->muser_count;
        req->active_targets = raddata->muser_count;
        memcpy(req->targetusers, raddata->matchedusers,
                sizeof(radius_user_t *) * USER_IDENT_MAX);

        raddata->savedreq = req;
    }

    if (raddata->msgtype == RADIUS_CODE_ACCESS_REQUEST) {

        /* Save the request so we can match the reply later on */
        radius_saved_req_t *check = NULL;

        radius_orphaned_resp_t *orphan = NULL;

        orphan = search_orphans(
                &(raddata->matchednas->orphans),
                &(raddata->matchednas->orphans_tail),
                DERIVE_REQUEST_ID(raddata, raddata->msgtype), raddata->tvsec);
        if (orphan) {
            raddata->savedresp = orphan;
        } else if (!raddata->savedresp) {
            reqid = DERIVE_REQUEST_ID(raddata, raddata->msgtype);

            HASH_FIND(hh, raddata->matchednas->request_map, &(reqid),
                    sizeof(reqid), check);
            if (check && raddata->tvsec == check->tvsec &&
                    raddata->acctsess_hash == check->acctsess_hash) {
                /* This *is* the same request -- we've already inserted it,
                 * probably due to having both CSID and username in the
                 * AVP list.
                 */

                 // pass

            } else {
                if (check) {
                    /* The old one is probably an unanswered request, replace
                     * it with this one instead. */
                    for (i = 0; i < check->targetuser_count; i++) {
                        int rcint;
                        if (check->targetusers[i] == NULL) {
                            continue;
                        }
                        JLD(rcint, check->targetusers[i]->savedrequests, reqid);
                    }

                    release_attribute_list(&(glob->freeattrs), check->attrs);
                    release_saved_request(&(glob->freeaccreqs), check);
                    HASH_DELETE(hh, raddata->matchednas->request_map, check);

                }

                if (glob->freeaccreqs == NULL) {
                    req = (radius_saved_req_t *)malloc(
                            sizeof(radius_saved_req_t));
                } else {
                    req = glob->freeaccreqs;
                    glob->freeaccreqs = req->next;
                }

                req->reqid = reqid;
                req->statustype = raddata->accttype;
                req->acctsess_hash = raddata->acctsess_hash;
                req->tvsec = raddata->tvsec;
                req->next = NULL;
                req->attrs = raddata->attrs;
                req->targetuser_count = raddata->muser_count;
                req->active_targets = raddata->muser_count;
                memcpy(req->targetusers, raddata->matchedusers,
                        sizeof(radius_user_t *) * USER_IDENT_MAX);

                HASH_ADD_KEYPTR(hh, raddata->matchednas->request_map,
                        &(req->reqid), sizeof(req->reqid), req);

                for (i = 0; i < raddata->muser_count; i++) {
                    JLI(pval, raddata->matchedusers[i]->savedrequests, req->reqid);
                    *pval = (Word_t)req;
                }
            }
        }
    }

usessupdate:
    JLG(pval, raduser->sessions, raddata->acctsess_hash);
    if (pval == NULL) {
        usess = calloc(1, sizeof(radius_user_session_t));

        usess->current = SESSION_STATE_NEW;
        usess->session_id = raddata->acctsess_hash;
        usess->nasidentifier = NULL;
        usess->nas_port = 0;
        usess->nas_ip = NULL;
        usess->nas_ip_family = 0;
        usess->octets_received = 0;
        usess->octets_sent = 0;
        usess->parent = raduser;

        thissess->statedata = usess;

        JLI(pval, raduser->sessions, usess->session_id);
        *pval = (Word_t)usess;
    } else {
        usess = (radius_user_session_t *)(*pval);
    }

    *oldstate = usess->current;
    apply_fsm_logic(usess, raddata->msgtype, raddata->accttype,
            newstate, &(raddata->firstaction));
    if (raddata->savedresp) {
        apply_fsm_logic(usess, raddata->savedresp->resptype,
                raddata->accttype, newstate, &(raddata->secondaction));
    }

    update_user_session_data(raddata, usess);

    update_first_action(raddata, thissess);
    update_second_action(raddata, thissess);

    /* Handle case where we're "active" but have no assigned IP yet" */
    if (thissess->sessipcount == 0 && *newstate == SESSION_STATE_ACTIVE) {
        *newstate = SESSION_STATE_ACTIVE_NO_IP;
        usess->current = SESSION_STATE_ACTIVE_NO_IP;
    }

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
        etsili_generic_freelist_t *freegenerics, radius_attribute_t *attr,
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
        etsili_generic_freelist_t *freelist,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_REPORT;

    return generate_iri(params, freelist, attrs, tv, IPIRI_ACCESS_ATTEMPT,
            iritype);
}


static int radius_generate_access_accept_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freelist,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_BEGIN;

    return generate_iri(params, freelist, attrs, tv, IPIRI_ACCESS_ACCEPT,
            iritype);
}

static int radius_generate_interim_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freelist,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_CONTINUE;

    return generate_iri(params, freelist, attrs, tv, IPIRI_INTERIM_UPDATE,
            iritype);
}

static int radius_generate_access_end_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freelist,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_END;

    return generate_iri(params, freelist, attrs, tv, IPIRI_ACCESS_END,
            iritype);
}

static int radius_generate_access_reject_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freelist,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_REPORT;

    return generate_iri(params, freelist, attrs, tv, IPIRI_ACCESS_REJECT,
            iritype);
}

static int radius_generate_access_failed_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freelist,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_REPORT;

    return generate_iri(params, freelist, attrs, tv, IPIRI_ACCESS_FAILED,
            iritype);
}

static int radius_generate_already_active_iri(etsili_generic_t **params,
        etsili_generic_freelist_t *freelist,
        radius_attribute_t *attrs, struct timeval *tv,
        etsili_iri_type_t *iritype) {

    *iritype = ETSILI_IRI_BEGIN;

    return generate_iri(params, freelist, attrs, tv, IPIRI_START_WHILE_ACTIVE,
            iritype);
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
                        attrs, &tv, iritype) < 0) {
                return -1;
            }
            break;
        case ACCESS_ACTION_ACCEPT:
            if (radius_generate_access_accept_iri(params, freegenerics,
                        attrs, &tv, iritype) < 0) {
                return -1;
            }
            break;
        case ACCESS_ACTION_END:
            if (radius_generate_access_end_iri(params, freegenerics,
                        attrs, &tv, iritype) < 0) {
                return -1;
            }
            break;
        case ACCESS_ACTION_INTERIM_UPDATE:
            if (radius_generate_interim_iri(params, freegenerics,
                        attrs, &tv, iritype) < 0) {
                return -1;
            }
            break;
        case ACCESS_ACTION_REJECT:
            if (radius_generate_access_reject_iri(params, freegenerics,
                        attrs, &tv, iritype) < 0) {
                return -1;
            }
            break;
        case ACCESS_ACTION_FAILED:
            if (radius_generate_access_failed_iri(params, freegenerics,
                        attrs, &tv, iritype) < 0) {
                return -1;
            }
            break;
        case ACCESS_ACTION_ALREADY_ACTIVE:
            if (radius_generate_already_active_iri(params, freegenerics,
                        attrs, &tv, iritype) < 0) {
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

static int radius_generate_iri_data(access_plugin_t *p UNUSED, void *parseddata,
        etsili_generic_t **params, etsili_iri_type_t *iritype,
        etsili_generic_freelist_t *freelist, int iteration) {

    radius_parsed_t *raddata;

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

static int radius_generate_iri_from_session(access_plugin_t *p UNUSED,
        access_session_t *session, etsili_generic_t **params,
        etsili_iri_type_t *iritype, etsili_generic_freelist_t *freelist,
        uint8_t trigger) {

    radius_user_session_t *usess =
            (radius_user_session_t *)(session->statedata);

    etsili_generic_t *np;
    etsili_ipaddress_t nasip;
    ipiri_id_t nasid;

    /* XXX Static generics aren't going to work anymore -- we'll need to
     * copy them into memory that we control...
     */
    if (usess->nas_port != 0) {
        np = create_etsili_generic(freelist,
                IPIRI_CONTENTS_POP_PORTNUMBER, sizeof(int64_t),
                (uint8_t *)(&usess->nas_port));
        HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);
    }

    if (usess->nasidentifier != NULL) {
        if (ipiri_create_id_printable(usess->nasidentifier,
                    strlen(usess->nasidentifier), &nasid) < 0) {
            logger(LOG_INFO, "OpenLI: Unable to convert RADIUS NAS Identifier attribute into a printable POP Identifier");
        }
        np = create_etsili_generic(freelist,
                IPIRI_CONTENTS_POP_IDENTIFIER, sizeof(ipiri_id_t),
                (uint8_t *)(&nasid));
        HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);
    }

    if (usess->nas_ip_family != 0) {
        etsili_create_ipaddress_v4((uint32_t *)(usess->nas_ip),
                ETSILI_IPV4_SUBNET_UNKNOWN,
                ETSILI_IPADDRESS_ASSIGNED_UNKNOWN, &nasip);
        np = create_etsili_generic(freelist,
                IPIRI_CONTENTS_POP_IPADDRESS, sizeof(etsili_ipaddress_t),
                (uint8_t *)(&nasip));
        HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);
    }

    np = create_etsili_generic(freelist,
            IPIRI_CONTENTS_OCTETS_RECEIVED, sizeof(int64_t),
            (uint8_t *)(&usess->octets_received));
    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);

    np = create_etsili_generic(freelist,
            IPIRI_CONTENTS_OCTETS_TRANSMITTED, sizeof(int64_t),
            (uint8_t *)(&usess->octets_sent));
    HASH_ADD_KEYPTR(hh, *params, &(np->itemnum), sizeof(np->itemnum), np);

    if (trigger == OPENLI_IPIRI_STARTWHILEACTIVE) {
        *iritype = ETSILI_IRI_BEGIN;
    }
    if (trigger == OPENLI_IPIRI_ENDWHILEACTIVE) {
        *iritype = ETSILI_IRI_REPORT;
    }
    if (trigger == OPENLI_IPIRI_SILENTLOGOFF) {
        *iritype = ETSILI_IRI_END;
    }

    return 1;
}

static void radius_destroy_session_data(access_plugin_t *p UNUSED,
        access_session_t *sess) {

    int rcint;
    Word_t rcw;
    radius_user_session_t *usess = (radius_user_session_t *)sess->statedata;

    if (usess == NULL) {
        return;
    }

    if (usess->nasidentifier) {
        free(usess->nasidentifier);
        usess->nasidentifier = NULL;
    }
    if (usess->nas_ip) {
        free(usess->nas_ip);
        usess->nas_ip = NULL;
    }

    if (usess->parent) {
        JLD(rcint, usess->parent->sessions, usess->session_id);
        JLC(rcw, usess->parent->sessions, 0, -1);
        if (rcw == 0) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            usess->parent->inactive_since = tv.tv_sec;

            // TODO expire users who have been inactive for a long time?
        }
    }

    usess->parent = NULL;
    free(usess);
}

static uint32_t radius_get_packet_sequence(access_plugin_t *p UNUSED,
        void *parseddata) {

    radius_parsed_t *raddata;
    raddata = (radius_parsed_t *)parseddata;

    return DERIVE_REQUEST_ID(raddata, raddata->msgtype);
}

static uint8_t *radius_get_ip_contents(access_plugin_t *p UNUSED,
        void *parseddata UNUSED, uint16_t *iplen, int iteration UNUSED) {

    /* TODO */

    *iplen = 0;
    return NULL;
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
    radius_generate_iri_from_session,
    //radius_create_iri_from_packet,
    radius_destroy_session_data,
    radius_get_packet_sequence,
    radius_get_ip_contents,
};

access_plugin_t *get_radius_access_plugin(void) {
    return &radiusplugin;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
