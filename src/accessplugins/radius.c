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
#include <uthash.h>
#include <libtrace_parallel.h>

#include "logger.h"
#include "internetaccess.h"
#include "util.h"

#define DERIVE_REQUEST_ID(rad) \
    ((((uint32_t)rad->msgident) << 16) + (((uint32_t)rad->sourceport)))

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
    RADIUS_ATTR_NASPORT = 5,
    RADIUS_ATTR_FRAMED_IP_ADDRESS = 8,
    RADIUS_ATTR_NASIDENTIFIER = 32,
    RADIUS_ATTR_ACCT_STATUS_TYPE = 40,
    RADIUS_ATTR_ACCT_INOCTETS = 42,
    RADIUS_ATTR_ACCT_OUTOCTETS = 43,
    RADIUS_ATTR_ACCT_SESSION_ID = 44,
    RADIUS_ATTR_FRAMED_IPV6_ADDRESS = 168,
};

enum {
    RADIUS_ACCT_START = 1,
    RADIUS_ACCT_STOP = 2,
    RADIUS_ACCT_INTERIM_UPDATE = 3,
};

typedef struct radius_user {

    char *userid;
    char *nasidentifier;
    session_state_t current;
    struct sockaddr *framedip4;
    struct sockaddr *framedip6;

    UT_hash_handle hh_username;

} radius_user_t;

typedef struct radius_access_req {
    uint32_t reqid;
    radius_user_t *targetuser;
    UT_hash_handle hh;
} radius_access_req_t;

typedef struct radius_account_req radius_account_req_t;

struct radius_account_req {

    uint32_t reqid;
    uint32_t statustype;
    uint64_t inoctets;
    uint64_t outoctets;

    radius_user_t *targetuser;
    radius_account_req_t *next;
    UT_hash_handle hh;

};

typedef struct radius_attribute radius_attribute_t;

struct radius_attribute {
    uint8_t att_type;
    uint8_t att_len;
    void *att_val;
    uint8_t copied;

    radius_attribute_t *next;
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
    radius_user_t *users;
    radius_access_req_t *requests;
    radius_account_req_t *accountings;

    radius_orphaned_resp_t *access_orphans;
    radius_orphaned_resp_t *access_orphans_tail;
    radius_orphaned_resp_t *account_orphans;
    radius_orphaned_resp_t *account_orphans_tail;

    UT_hash_handle hh;
} radius_nas_t;

typedef struct radius_server {
    uint8_t *servip;
    radius_nas_t *naslist;
    UT_hash_handle hh;
} radius_server_t;

typedef struct radius_parsed {

    libtrace_packet_t *origpkt;
    uint8_t msgtype;
    uint8_t msgident;
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

    radius_access_req_t *accessreq;
    radius_orphaned_resp_t *accessresp;

    radius_account_req_t *accountreq;
    radius_orphaned_resp_t *accountresp;

    access_action_t firstaction;
    access_action_t secondaction;

} radius_parsed_t;

typedef struct radius_global {
    radius_attribute_t *freeattrs;
    radius_account_req_t *freeaccreqs;
    radius_parsed_t parsedpkt;

    radius_server_t *servers;
} radius_global_t;

typedef struct radius_header {
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
    uint8_t auth[16];
} PACKED radius_header_t;

static int warned = 0;

static inline void reset_parsed_packet(radius_parsed_t *parsed) {

    parsed->origpkt = NULL;
    parsed->msgtype = 0;
    parsed->accttype = 0;
    parsed->msgident = 0;
    parsed->attrs = NULL;
    parsed->sourceport = 0;
    parsed->tvsec = 0;
    parsed->nasport = 0;
    parsed->matcheduser = NULL;
    parsed->matchednas = NULL;
    parsed->matchedserv = NULL;
    parsed->accessreq = NULL;
    parsed->accessresp = NULL;
    parsed->accountreq = NULL;
    parsed->accountresp = NULL;
    memset(&(parsed->nasip), 0, sizeof(struct sockaddr_storage));
    memset(&(parsed->radiusip), 0, sizeof(struct sockaddr_storage));

    parsed->firstaction = ACCESS_ACTION_NONE;
    parsed->secondaction = ACCESS_ACTION_NONE;
}

static void radius_init_plugin_data(access_plugin_t *p) {
    radius_global_t *glob;

    glob = (radius_global_t *)(malloc(sizeof(radius_global_t)));
    glob->freeattrs = NULL;
    glob->freeaccreqs = NULL;
    glob->servers = NULL;

    reset_parsed_packet(&(glob->parsedpkt));

    p->plugindata = (void *)(glob);
    return;
}

static inline void free_attribute_list(radius_attribute_t *attrlist) {
    radius_attribute_t *at, *tmp;

    at = attrlist;
    while (at) {
        tmp = at;
        at = at->next;
        free(tmp);
    }
}

static void radius_destroy_plugin_data(access_plugin_t *p) {

    radius_global_t *glob;
    radius_server_t *srv, *tmpsrv;
    radius_nas_t *nas, *tmpnas;
    radius_user_t *user, *tmpuser;
    radius_access_req_t *req, *tmpreq;
    radius_account_req_t *acc, *tmpacc;
    radius_orphaned_resp_t *orph, *tmporph;

    glob = (radius_global_t *)(p->plugindata);
    if (!glob) {
        return;
    }

    free_attribute_list(glob->freeattrs);

    acc = glob->freeaccreqs;
    while (acc) {
        tmpacc = acc;
        acc = acc->next;
        free(tmpacc);
    }

    HASH_ITER(hh, glob->servers, srv, tmpsrv) {
        HASH_ITER(hh, srv->naslist, nas, tmpnas) {
            HASH_ITER(hh_username, nas->users, user, tmpuser) {
                HASH_DELETE(hh_username, nas->users, user);
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
            }

            HASH_ITER(hh, nas->requests, req, tmpreq) {
                HASH_DELETE(hh, nas->requests, req);
                free(req);
            }

            HASH_ITER(hh, nas->accountings, acc, tmpacc) {
                HASH_DELETE(hh, nas->accountings, acc);
                free(acc);
            }

            orph = nas->account_orphans;
            while (orph) {
                tmporph = orph;
                orph = orph->next;
                free_attribute_list(tmporph->savedattrs);
                free(tmporph);
            }

            orph = nas->access_orphans;
            while (orph) {
                tmporph = orph;
                orph = orph->next;
                free_attribute_list(tmporph->savedattrs);
                free(tmporph);
            }

            HASH_DELETE(hh, srv->naslist, nas);
            if (nas->nasip) {
                free(nas->nasip);
            }
            free(nas);
        }
        HASH_DELETE(hh, glob->servers, srv);
        if (srv->servip) {
            free(srv->servip);
        }
        free(srv);
    }

    free_attribute_list(glob->parsedpkt.attrs);
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
    if (attr->copied) {
        free(attr->att_val);
    }
    attr->att_val = NULL;
}

static void radius_destroy_parsed_data(access_plugin_t *p, void *parsed) {

    radius_global_t *glob;
    radius_attribute_t *at, *tmp;
    radius_parsed_t *rparsed = (radius_parsed_t *)parsed;

    glob = (radius_global_t *)(p->plugindata);

    at = rparsed->attrs;
    while (at != NULL) {
        tmp = at;
        at = at->next;
        release_attribute(&(glob->freeattrs), tmp);
    }
    rparsed->attrs = at;

    if (rparsed->accessreq) {
        free(rparsed->accessreq);
    }
    if (rparsed->accountreq) {
        if (glob->freeaccreqs == NULL) {
            glob->freeaccreqs = rparsed->accountreq;
            glob->freeaccreqs->next = NULL;
        } else {
            rparsed->accountreq->next = glob->freeaccreqs;
            glob->freeaccreqs = rparsed->accountreq;
        }
        rparsed->accountreq = NULL;
    }
    if (rparsed->accountresp) {
        at = rparsed->accountresp->savedattrs;
        while (at) {
            tmp = at;
            at = at->next;
            release_attribute(&(glob->freeattrs), tmp);
        }
        free(rparsed->accountresp);
    }

    if (rparsed->accessresp) {
        at = rparsed->accessresp->savedattrs;
        while (at) {
            tmp = at;
            at = at->next;
            release_attribute(&(glob->freeattrs), tmp);
        }
        free(rparsed->accessresp);
    }

    reset_parsed_packet(rparsed);

}

static void create_orphan(radius_orphaned_resp_t **head,
        radius_orphaned_resp_t **tail,
        libtrace_packet_t *pkt, uint32_t reqid, uint8_t resptype) {

    /* Hopefully this is rare enough that we don't need a freelist of
     * orphaned responses */

    radius_orphaned_resp_t *resp, *iter;

    resp = (radius_orphaned_resp_t *)malloc(sizeof(radius_orphaned_resp_t));
    resp->key = reqid;
    resp->next = NULL;
    resp->tvsec = trace_get_seconds(pkt);
    resp->resptype = resptype;
    resp->savedattrs = NULL;

    /* TODO save a copy of the attributes */

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
        if (iter->tvsec + 0.1 >= resp->tvsec) {
            break;
        }
        (*head) = iter->next;
        /* XXX should really put these back in the free list */
        free_attribute_list(iter->savedattrs);
        free(iter);
        iter = *head;
        if (!warned) {
            logger(LOG_DAEMON,
                "OpenLI RADIUS: expired orphaned response packet.");
            logger(LOG_DAEMON,
                "OpenLI RADIUS: capture is possibly dropping RADIUS packets?");
            warned = 1;
        }
    }
}

static inline void *find_radius_start(libtrace_packet_t *pkt, uint32_t *rem) {

    void *transport, *radstart;
    uint8_t proto;

    transport = trace_get_transport(pkt, &proto, rem);
    if (!transport || rem == 0) {
        return NULL;
    }

    if (proto != TRACE_IPPROTO_UDP) {
        return NULL;
    }

    radstart = trace_get_payload_from_udp((libtrace_udp_t *)transport, rem);
    return radstart;
}

static inline int grab_nas_details_from_packet(radius_parsed_t *parsed,
        libtrace_packet_t *pkt, uint8_t code) {

    struct sockaddr_storage ipaddr_nas;
    struct sockaddr_storage ipaddr_rad;

    memset(&ipaddr_nas, 0, sizeof(struct sockaddr_storage));
    memset(&ipaddr_rad, 0, sizeof(struct sockaddr_storage));

    switch(code) {
        case RADIUS_CODE_ACCESS_REQUEST:
        case RADIUS_CODE_ACCOUNT_REQUEST:
            if (trace_get_source_address(pkt,
                    (struct sockaddr *)&ipaddr_nas) == NULL) {
                logger(LOG_DAEMON,
                        "Unable to get NAS address from RADIUS packet");
                return -1;
            }
            if (trace_get_destination_address(pkt,
                    (struct sockaddr *)&ipaddr_rad) == NULL) {
                logger(LOG_DAEMON,
                        "Unable to get server address from RADIUS packet");
                return -1;
            }
            parsed->sourceport = trace_get_source_port(pkt);
            break;
        case RADIUS_CODE_ACCESS_ACCEPT:
        case RADIUS_CODE_ACCESS_REJECT:
        case RADIUS_CODE_ACCOUNT_RESPONSE:
        case RADIUS_CODE_ACCESS_CHALLENGE:
            if (trace_get_destination_address(pkt,
                    (struct sockaddr *)&ipaddr_nas) == NULL) {
                logger(LOG_DAEMON,
                        "Unable to get NAS address from RADIUS packet");
                return -1;
            }
            if (trace_get_source_address(pkt,
                    (struct sockaddr *)&ipaddr_rad) == NULL) {
                logger(LOG_DAEMON,
                        "Unable to get server address from RADIUS packet");
                return -1;
            }
            parsed->sourceport = trace_get_destination_port(pkt);
            break;
        default:
            return -1;
    }

    memcpy(&(parsed->nasip), &ipaddr_nas, sizeof(struct sockaddr_storage));
    memcpy(&(parsed->radiusip), &ipaddr_rad, sizeof(struct sockaddr_storage));
    return 0;
}

static inline radius_attribute_t *create_new_attribute(radius_global_t *glob,
        radius_parsed_t *parsed, uint8_t type, uint8_t len, uint8_t *valptr,
        uint8_t copy) {

    radius_attribute_t *attr;

    if (glob->freeattrs) {
        attr = glob->freeattrs;
        glob->freeattrs = attr->next;
    } else {
        attr = (radius_attribute_t *)malloc(sizeof(radius_attribute_t));
    }

    attr->att_type = type;
    attr->att_len = len - 2;
    if (copy) {
        attr->att_val = malloc(attr->att_len);
        memcpy(attr->att_val, valptr, attr->att_len);
        attr->copied = 1;
    } else {
        attr->att_val = (void *)valptr;
        attr->copied = 0;
    }
    attr->next = parsed->attrs;

    parsed->attrs = attr;
    return attr;
}

static inline void update_known_servers(radius_global_t *glob,
        radius_parsed_t *parsed) {

    radius_server_t *srv;
    radius_nas_t *nas;
    uint8_t *sockkey;
    int socklen;

    sockkey = sockaddr_to_key((struct sockaddr *)&(parsed->radiusip),
            &socklen);

    if (sockkey == NULL) {
        return;
    }
    HASH_FIND(hh, glob->servers, sockkey, socklen, srv);

    if (!srv) {
        srv = (radius_server_t *)malloc(sizeof(radius_server_t));
        srv->naslist = NULL;
        srv->servip = (uint8_t *)malloc(socklen);
        memcpy(srv->servip, sockkey, socklen);

        HASH_ADD_KEYPTR(hh, glob->servers, srv->servip, socklen, srv);
    }


    sockkey = sockaddr_to_key((struct sockaddr *)&(parsed->radiusip),
            &socklen);

    if (sockkey == NULL) {
        return;
    }
    HASH_FIND(hh, srv->naslist, sockkey, socklen, nas);
    if (!nas) {
        nas = (radius_nas_t *)malloc(sizeof(radius_nas_t));
        nas->users = NULL;
        nas->requests = NULL;
        nas->accountings = NULL;
        nas->access_orphans = NULL;
        nas->access_orphans_tail = NULL;
        nas->account_orphans = NULL;
        nas->account_orphans_tail = NULL;
        nas->nasip = (uint8_t *)malloc(socklen);
        memcpy(nas->nasip, sockkey, socklen);

        HASH_ADD_KEYPTR(hh, srv->naslist, nas->nasip, socklen, nas);
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

    glob = (radius_global_t *)(p->plugindata);

    parsed = &(glob->parsedpkt);
    if (parsed->msgtype != 0) {
        radius_destroy_parsed_data(p, (void *)parsed);
    }

    radstart = (uint8_t *)find_radius_start(pkt, &rem);
    if (radstart == NULL) {
        return NULL;
    }

    if (rem < sizeof(radius_header_t)) {
        logger(LOG_DAEMON,
                "OpenLI: RADIUS packet did not have a complete header");
        return NULL;
    }

    hdr = (radius_header_t *)radstart;
    len = ntohs(hdr->length);

    if (len > rem) {
        logger(LOG_DAEMON,
                "OpenLI: RADIUS packet was truncated, some attributes may be missed.");
        logger(LOG_DAEMON,
                "OpenLI: RADIUS length was %u but we only had %u bytes of payload.",
                len, rem);
    }

    parsed->msgtype = hdr->code;
    parsed->msgident = hdr->identifier;
    parsed->origpkt = pkt;
    parsed->tvsec = trace_get_seconds(pkt);;

    if (grab_nas_details_from_packet(parsed, pkt, hdr->code) < 0) {
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

        newattr = create_new_attribute(glob, parsed, att_type, att_len, ptr, 0);

        if (newattr->att_type == RADIUS_ATTR_ACCT_STATUS_TYPE) {
            parsed->accttype = ntohl(*((uint32_t *)newattr->att_val));
        }

        rem -= att_len;
        ptr += (att_len - 2);
    }

    return parsed;
}

static inline void process_username_attribute(radius_parsed_t *raddata) {

    char userkey[256];
    radius_user_t *user;
    radius_attribute_t *userattr;

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
    } else {
        memcpy(userkey, userattr->att_val, 255);
        userkey[255] = '\0';
        logger(LOG_DAEMON,
                "OpenLI RADIUS: User-Name is too long, truncated to %s",
                userkey);
    }

    HASH_FIND(hh_username, raddata->matchednas->users, userkey,
            strlen(userkey), user);

    if (user) {
        raddata->matcheduser = user;
        return;
    }

    user = (radius_user_t *)malloc(sizeof(radius_user_t));

    user->userid = strdup(userkey);
    user->nasidentifier = NULL;
    user->current = SESSION_STATE_NEW;
    user->framedip4 = NULL;
    user->framedip6 = NULL;

    HASH_ADD_KEYPTR(hh_username, raddata->matchednas->users, user->userid,
            strlen(user->userid), user);
    raddata->matcheduser = user;
}

static inline void process_nasid_attribute(radius_parsed_t *raddata) {
    char nasid[1024];
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
    } else {
        memcpy(nasid, nasattr->att_val, 255);
        nasid[255] = '\0';
        logger(LOG_DAEMON,
                "OpenLI RADIUS: NAS-Identifier is too long, truncated to %s",
                nasid);
    }

    if (raddata->matcheduser->nasidentifier) {
        if (strcmp(nasid, raddata->matcheduser->nasidentifier) != 0) {
            logger(LOG_DAEMON,
                    "OpenLI RADIUS: NAS-Identifier for user %s has changed from %s to %s",
                    raddata->matcheduser->userid,
                    raddata->matcheduser->nasidentifier,
                    nasid);
            free(raddata->matcheduser->nasidentifier);
        } else {
            return;
        }
    }

    raddata->matcheduser->nasidentifier = strdup(nasid);
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

static inline void extract_assigned_ip_address(radius_parsed_t *raddata,
        radius_attribute_t *attrlist, access_session_t *sess) {

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

            sa = (struct sockaddr_storage *)malloc(
                    sizeof(struct sockaddr_storage));
            memset(sa, 0, sizeof(struct sockaddr_storage));
            in = (struct sockaddr_in *)sa;

            in->sin_family = AF_INET;
            in->sin_port = 0;
            in->sin_addr.s_addr = *((uint32_t *)attr->att_val);

            assert(sess->assignedip == NULL);
            sess->ipfamily = AF_INET;
            sess->assignedip = (struct sockaddr *)sa;
            return;
        }

        if (attr->att_type == RADIUS_ATTR_FRAMED_IPV6_ADDRESS) {
            struct sockaddr_in6 *in6;

            sa = (struct sockaddr_storage *)malloc(
                    sizeof(struct sockaddr_storage));
            memset(sa, 0, sizeof(struct sockaddr_storage));
            in6 = (struct sockaddr_in6 *)sa;

            in6->sin6_family = AF_INET6;
            in6->sin6_port = 0;
            in6->sin6_flowinfo = 0;

            memcpy(&(in6->sin6_addr.s6_addr), attr->att_val, 16);

            sess->ipfamily = AF_INET6;
            sess->assignedip = (struct sockaddr *)sa;
            return;
        }

        attr = attr->next;
    }

}

static inline void save_octet_counts(radius_parsed_t *raddata,
        radius_account_req_t *req) {

    uint8_t attrnum;
    radius_attribute_t *attr;

    if (!raddata->matcheduser) {
        return;
    }

    /* TODO what if there are duplicate attributes?? */
    attr = raddata->attrs;
    while (attr) {
        if (attr->att_type == RADIUS_ATTR_ACCT_INOCTETS) {
            req->inoctets = *((uint32_t *)attr->att_val);
        }

        if (attr->att_type == RADIUS_ATTR_ACCT_OUTOCTETS) {
            req->outoctets = *((uint32_t *)attr->att_val);
        }

        attr = attr->next;
    }

}


static inline void find_matching_request(radius_parsed_t *raddata) {

    uint32_t reqid;

    reqid = ((uint32_t)raddata->msgident << 16) + raddata->sourceport;

    if (raddata->msgtype == RADIUS_CODE_ACCESS_ACCEPT ||
            raddata->msgtype == RADIUS_CODE_ACCESS_REJECT ||
            raddata->msgtype == RADIUS_CODE_ACCESS_CHALLENGE) {

        radius_access_req_t *req = NULL;

        HASH_FIND(hh, raddata->matchednas->requests, &reqid, sizeof(reqid),
                req);
        if (req == NULL) {
            create_orphan(&(raddata->matchednas->access_orphans),
                    &(raddata->matchednas->access_orphans_tail),
                    raddata->origpkt, reqid, raddata->msgtype);
            return;
        }

        assert(raddata->matcheduser == NULL ||
                req->targetuser == raddata->matcheduser);
        raddata->matcheduser = req->targetuser;
        raddata->accessreq = req;
        HASH_DELETE(hh, raddata->matchednas->requests, req);
        return;
    }

    if (raddata->msgtype == RADIUS_CODE_ACCOUNT_RESPONSE) {
        radius_account_req_t *req = NULL;

        req = raddata->matchednas->accountings;

        HASH_FIND(hh, raddata->matchednas->accountings, &reqid, sizeof(reqid),
                req);
        if (req == NULL) {
            create_orphan(&(raddata->matchednas->account_orphans),
                    &(raddata->matchednas->account_orphans_tail),
                    raddata->origpkt, reqid, raddata->msgtype);
            return;
        }

        assert(raddata->matcheduser == NULL ||
                req->targetuser == raddata->matcheduser);
        raddata->matcheduser = req->targetuser;
        raddata->accttype = req->statustype;
        raddata->accountreq = req;
        HASH_DELETE(hh, raddata->matchednas->accountings, req);
        return;
    }

}

static char *radius_get_userid(access_plugin_t *p, void *parsed) {

    radius_parsed_t *raddata;
    char foo[128];

    raddata = (radius_parsed_t *)parsed;

    if (raddata->matcheduser) {
        return raddata->matcheduser->userid;
    }

    if (!raddata->matchednas) {
        logger(LOG_DAEMON, "OpenLI RADIUS: please parse the packet before attempting to get the user id.");
        return NULL;
    }

    process_username_attribute(raddata);
    //process_nasport_attribute(raddata);

    if (!raddata->matcheduser && (
            raddata->msgtype == RADIUS_CODE_ACCESS_REQUEST ||
            raddata->msgtype == RADIUS_CODE_ACCOUNT_REQUEST)) {
        logger(LOG_DAEMON,
                "OpenLI RADIUS: got a request with no User-Name field?");
        return NULL;
    }

    /* This must be a response packet, try to match it to a previously
     * seen request...
     */
    find_matching_request(raddata);
    if (raddata->matcheduser) {
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
        if (iter == *head && iter->tvsec + 0.1 < tvsec) {
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
                logger(LOG_DAEMON,
                    "OpenLI RADIUS: expired orphaned response packet.");
                logger(LOG_DAEMON,
                    "OpenLI RADIUS: capture is possibly dropping RADIUS packets?");
                warned = 1;
            }
            continue;
        }

        if (iter->key == reqid && tvsec < iter->tvsec + 0.1) {
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

static inline char *quickcat(char *ptr, int *rem, char *toadd) {

    int towrite = strlen(toadd);

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
    ptr = quickcat(ptr, &rem, raddata->matcheduser->userid);
    ptr = quickcat(ptr, &rem, "-");
    ptr = quickcat(ptr, &rem, raddata->matcheduser->nasidentifier);


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
        thissess->sessionid = strdup(sessionid);
        thissess->statedata = NULL;
        thissess->idlength = strlen(sessionid);
        thissess->cin = 100;     /* TODO hash the session id */
        thissess->ipfamily = AF_UNSPEC;
        thissess->assignedip = NULL;
        thissess->iriseqno = 0;
        thissess->next = *sesslist;

        *sesslist = thissess;
    }


    if (raddata->msgtype == RADIUS_CODE_ACCESS_REQUEST) {

        /* Save the request so we can match the reply later on */
        radius_access_req_t *req = NULL;
        radius_access_req_t *check = NULL;

        radius_orphaned_resp_t *orphan = NULL;

        orphan = search_orphans(
                &(raddata->matchednas->access_orphans),
                &(raddata->matchednas->access_orphans_tail),
                DERIVE_REQUEST_ID(raddata), raddata->tvsec);
        if (orphan) {
            raddata->accessresp = orphan;
            logger(LOG_DAEMON,
                    "OpenLI RADIUS: found request for access orphan: %s",
                    (char *)thissess->sessionid);
        }

        req = (radius_access_req_t *)malloc(sizeof(radius_access_req_t));
        req->reqid = DERIVE_REQUEST_ID(raddata);
        req->targetuser = raddata->matcheduser;

        if (!raddata->accessresp) {
            HASH_FIND(hh, raddata->matchednas->requests, &(req->reqid),
                    sizeof(req->reqid), check);
            if (check) {
                logger(LOG_DAEMON,
                        "OpenLI RADIUS: received duplicate request %u:%u from NAS %s",
                        raddata->msgident, raddata->sourceport,
                        raddata->matchednas->nasip);
                HASH_DELETE(hh, raddata->matchednas->requests, check);
            }

            HASH_ADD_KEYPTR(hh, raddata->matchednas->requests, &(req->reqid),
                    sizeof(req->reqid), req);
        }
    }

    if (raddata->msgtype == RADIUS_CODE_ACCOUNT_REQUEST) {

        /* Save the request so we can match the reply later on */
        radius_account_req_t *req = NULL;
        radius_account_req_t *check = NULL;
        radius_orphaned_resp_t *orphan = NULL;

        orphan = search_orphans(
                &(raddata->matchednas->account_orphans),
                &(raddata->matchednas->account_orphans_tail),
                DERIVE_REQUEST_ID(raddata), raddata->tvsec);
        if (orphan) {
            raddata->accountresp = orphan;
            logger(LOG_DAEMON,
                    "OpenLI RADIUS: found request for accounting orphan: %s",
                    (char *)thissess->sessionid);
        }

        if (glob->freeaccreqs == NULL) {
            req = (radius_account_req_t *)malloc(sizeof(radius_account_req_t));
        } else {
            req = glob->freeaccreqs;
            glob->freeaccreqs = req->next;
        }

        req->reqid = DERIVE_REQUEST_ID(raddata);
        req->targetuser = raddata->matcheduser;
        req->statustype = raddata->accttype;
        req->inoctets = 0;
        req->outoctets = 0;
        req->next = NULL;

        save_octet_counts(raddata, req);

        if (!raddata->accountresp) {
            HASH_FIND(hh, raddata->matchednas->accountings, &(req->reqid),
                    sizeof(req->reqid), check);
            if (check) {
                /* The old one is probably an unanswered request, replace
                 * it with this one instead. */
                HASH_DELETE(hh, raddata->matchednas->accountings, check);
            }

            HASH_ADD_KEYPTR(hh, raddata->matchednas->accountings, &(req->reqid),
                    sizeof(req->reqid), req);
        } else {
            raddata->accountreq = req;
        }

    }

    *oldstate = raddata->matcheduser->current;
    apply_fsm_logic(raddata, raddata->msgtype, raddata->accttype, newstate,
            &(raddata->firstaction));
    if (raddata->accountresp) {
        apply_fsm_logic(raddata, RADIUS_CODE_ACCOUNT_RESPONSE,
                raddata->accttype, newstate, &(raddata->secondaction));
    } else if (raddata->accessresp) {
        apply_fsm_logic(raddata, raddata->accessresp->resptype,
                raddata->accttype, newstate, &(raddata->secondaction));
    }

    if (raddata->firstaction == ACCESS_ACTION_ACCEPT ||
            raddata->firstaction == ACCESS_ACTION_ALREADY_ACTIVE) {

        /* Session is now active: make sure we get the IP address */
        extract_assigned_ip_address(raddata, raddata->attrs, thissess);
    }

    if (raddata->secondaction == ACCESS_ACTION_ACCEPT ||
            raddata->secondaction == ACCESS_ACTION_ALREADY_ACTIVE) {

        /* Use saved orphan attributes to get IP address */
        if (raddata->accountresp) {
            extract_assigned_ip_address(raddata,
                    raddata->accountresp->savedattrs, thissess);
        } else if (raddata->accessresp) {
            extract_assigned_ip_address(raddata,
                    raddata->accessresp->savedattrs, thissess);
        }
    }

    if (raddata->firstaction != ACCESS_ACTION_NONE) {
        *action = raddata->firstaction;
    } else {
        *action = raddata->secondaction;
    }
    return thissess;
}

static int radius_create_iri_from_packet(access_plugin_t *p,
        collector_global_t *glob, wandder_encoder_t **encoder,
        libtrace_message_queue_t *mqueue, access_session_t *sess,
        ipintercept_t *ipint, void *parsed, access_action_t action) {

    radius_global_t *radglob;
    radius_parsed_t *raddata;

    radglob = (radius_global_t *)(p->plugindata);
    raddata = (radius_parsed_t *)parsed;

    if (raddata->firstaction != ACCESS_ACTION_NONE) {
        

    }

    if (raddata->secondaction != ACCESS_ACTION_NONE) {

    }


    return 0;
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
    radius_get_userid,
    radius_update_session_state,
    radius_create_iri_from_packet,
    radius_destroy_session_data
};

access_plugin_t *get_radius_access_plugin(void) {
    return &radiusplugin;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
