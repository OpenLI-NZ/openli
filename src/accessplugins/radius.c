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

#include <uthash.h>

#include "logger.h"
#include "internetaccess.h"

enum {
    RADIUS_CODE_ACCESS_REQUEST = 1,
    RADIUS_CODE_ACCESS_ACCEPT = 2,
    RADIUS_CODE_ACCESS_REJECT = 3,
    RADIUS_CODE_ACCOUNT_REQUEST = 4,
    RADIUS_CODE_ACCOUNT_RESPONSE = 5,
    RADIUS_CODE_ACCESS_CHALLENGE = 11
};

typedef struct radius_access_req {
    uint8_t identifier;
} radius_access_req_t;

typedef struct radius_account_req {

    uint8_t identifier;
    uint32_t statustype;
    uint64_t inoctets;
    uint64_t outoctets;

} radius_account_req_t;

typedef struct radius_state {

    struct sockaddr *nasip;
    uint16_t nasport;
    char *nasidentifier;

    session_state_t current;

    radius_access_req_t *requests;
    radius_account_req_t *accountings;

    struct sockaddr *framedip4;
    struct sockaddr *framedip6;

} radius_state_t;


typedef struct radius_attribute radius_attribute_t;

struct radius_attribute {
    uint8_t att_type;
    uint8_t att_len;
    void *att_val;

    radius_attribute_t *nextfree;
    UT_hash_handle hh;
};

typedef struct radius_parsed {

    uint8_t msgtype;
    radius_attribute_t *attrs;

    struct sockaddr_storage nasip;
    uint16_t nasport;

} radius_parsed_t;

typedef struct radius_global {
    radius_attribute_t *freeattrs;
    radius_parsed_t parsedpkt;
} radius_global_t;

typedef struct radius_header {
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
    uint8_t auth[16];
} PACKED radius_header_t;

static void radius_init_plugin_data(access_plugin_t *p) {
    radius_global_t *glob;

    glob = (radius_global_t *)(malloc(sizeof(radius_global_t)));
    glob->freeattrs = NULL;

    glob->parsedpkt.msgtype = 0;
    glob->parsedpkt.attrs = NULL;
    memset(&(glob->parsedpkt.nasip), 0, sizeof(struct sockaddr_storage));
    glob->parsedpkt.nasport = 0;

    p->plugindata = (void *)(glob);
    return;
}

static void radius_destroy_plugin_data(access_plugin_t *p) {

    radius_global_t *glob;
    radius_attribute_t *at, *tmp;

    glob = (radius_global_t *)(p->plugindata);
    if (!glob) {
        return;
    }

    at = glob->freeattrs;
    while (at) {
        tmp = at;
        at = at->nextfree;
        free(tmp);
    }

    HASH_ITER(hh, glob->parsedpkt.attrs, at, tmp) {
        HASH_DELETE(hh, glob->parsedpkt.attrs, at);
        free(at);
    }
    free(glob);
    return;
}

static void radius_destroy_parsed_data(access_plugin_t *p, void *parsed) {

    radius_global_t *glob;
    radius_attribute_t *at, *tmp;
    radius_parsed_t *rparsed = (radius_parsed_t *)parsed;

    glob = (radius_global_t *)(p->plugindata);

    HASH_ITER(hh, rparsed->attrs, at, tmp) {
        HASH_DELETE(hh, rparsed->attrs, at);
        if (glob->freeattrs == NULL) {
            glob->freeattrs = at;
            at->nextfree = NULL;
        } else {
            at->nextfree = glob->freeattrs;
            glob->freeattrs = at;
        }
    }

    rparsed->attrs = NULL;
    rparsed->msgtype = 0;
    memset(&(rparsed->nasip), 0, sizeof(struct sockaddr_storage));
    rparsed->nasport = 0;

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

    struct sockaddr_storage ipaddr;
    uint16_t port;

    switch(code) {
        case RADIUS_CODE_ACCESS_REQUEST:
        case RADIUS_CODE_ACCOUNT_REQUEST:
            if (trace_get_source_address(pkt,
                    (struct sockaddr *)&ipaddr) == NULL) {
                logger(LOG_DAEMON,
                        "Unable to get NAS address from RADIUS packet");
                return -1;
            }
            port = trace_get_source_port(pkt);
            break;
        case RADIUS_CODE_ACCESS_ACCEPT:
        case RADIUS_CODE_ACCESS_REJECT:
        case RADIUS_CODE_ACCOUNT_RESPONSE:
        case RADIUS_CODE_ACCESS_CHALLENGE:
            if (trace_get_destination_address(pkt,
                    (struct sockaddr *)&ipaddr) == NULL) {
                logger(LOG_DAEMON,
                        "Unable to get NAS address from RADIUS packet");
                return -1;
            }
            port = trace_get_destination_port(pkt);
            break;
    }

    if (port == 0) {
        logger(LOG_DAEMON, "Unable to get NAS port from RADIUS packet");
        return -1;
    }

    parsed->nasport = port;
    memcpy(&(parsed->nasip), &ipaddr, sizeof(struct sockaddr_storage));
    return 0;
}

static inline radius_attribute_t *create_new_attribute(radius_global_t *glob,
        uint8_t type, uint8_t len, uint8_t *valptr) {

    radius_attribute_t *attr;

    if (glob->freeattrs) {
        attr = glob->freeattrs;
        glob->freeattrs = attr->nextfree;
    } else {
        attr = (radius_attribute_t *)malloc(sizeof(radius_attribute_t));
    }

    attr->att_type = type;
    attr->att_len = len;
    attr->att_val = (void *)valptr;
    attr->nextfree = NULL;

    return attr;
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
    if (grab_nas_details_from_packet(parsed, pkt, hdr->code) < 0) {
        return NULL;
    }

    rem -= sizeof(radius_header_t);
    ptr = radstart + sizeof(radius_header_t);

    while (rem > 2) {
        uint8_t att_type, att_len;
        radius_attribute_t *newattr, *existing;

        att_type = *ptr;
        att_len = *(ptr+1);
        ptr += 2;

        if (rem < att_len) {
            break;
        }

        newattr = create_new_attribute(glob, att_type, att_len, ptr);
        /* Some attributes can appear more than once, but none of these
         * are important for OpenLI so just keep the first instance. */
        HASH_FIND(hh, parsed->attrs, &(newattr->att_type), sizeof(uint8_t),
                existing);

        if (!existing) {
            HASH_ADD_KEYPTR(hh, parsed->attrs, &(newattr->att_type),
                    sizeof(uint8_t), newattr);
        }

        rem -= att_len;
        ptr += (att_len - 2);
    }

    return parsed;
}

static char *radius_get_userid(access_plugin_t *p,
        void *parsed) {

    return NULL;
}

static access_session_t *radius_update_session_state(access_plugin_t *p,
        void *parsed, access_session_t *sesslist,
        session_state_t *oldstate, session_state_t *newstate,
        access_action_t *action) {

    return NULL;
}

static int radius_create_iri_from_packet(access_plugin_t *p,
        collector_global_t *glob, wandder_encoder_t **encoder,
        libtrace_message_queue_t *mqueue, access_session_t *sess,
        ipintercept_t *ipint, void *parsed, access_action_t action) {

    return 0;
}

static void radius_destroy_session_data(access_plugin_t *p,
        access_session_t *sess) {

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
