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

#include <libtrace_parallel.h>
#include <assert.h>
#include <uthash.h>
#include <arpa/inet.h>

#include "logger.h"
#include "collector.h"
#include "collector_push_messaging.h"
#include "intercept.h"
#include "internetaccess.h"

static int remove_rtp_stream(colthread_local_t *loc, char *rtpstreamkey) {
    rtpstreaminf_t *rtp;

    HASH_FIND(hh, loc->activertpintercepts, rtpstreamkey, strlen(rtpstreamkey),
            rtp);

    if (rtp == NULL) {
        logger(LOG_DAEMON, "OpenLI: collector thread was unable to remove RTP stream %s, as it was not present in its intercept set.",
                rtpstreamkey);
        return 0;
    }

    HASH_DELETE(hh, loc->activertpintercepts, rtp);

    return 1;
}

static int add_ipv4_intercept(colthread_local_t *loc, ipsession_t *sess) {

    uint32_t v4addr;
    struct sockaddr_in *sin;
    ipv4_target_t *tgt;
    ipsession_t *check;

    sin = (struct sockaddr_in *)(sess->targetip);
    if (sin == NULL) {
        logger(LOG_DAEMON, "OpenLI: attempted to add IPv4 intercept but target IP was NULL?");
        return -1;
    }

    v4addr = sin->sin_addr.s_addr;

    HASH_FIND(hh, loc->activeipv4intercepts, &v4addr, sizeof(v4addr), tgt);
    if (tgt == NULL) {
        tgt = (ipv4_target_t *)malloc(sizeof(ipv4_target_t));
        if (!tgt) {
            logger(LOG_DAEMON, "OpenLI: ran out of memory while adding IPv4 intercept address.");
            return -1;
        }
        tgt->address = v4addr;
        tgt->intercepts = NULL;
        HASH_ADD(hh, loc->activeipv4intercepts, address, sizeof(uint32_t),
                tgt);
    }

    HASH_FIND(hh, tgt->intercepts, sess->streamkey, strlen(sess->streamkey),
            check);
    assert(check == NULL);
    HASH_ADD_KEYPTR(hh, tgt->intercepts, sess->streamkey,
            strlen(sess->streamkey), sess);

    return 0;
}

static int add_ipv6_intercept(colthread_local_t *loc, ipsession_t *sess) {

    uint8_t *v6addr;
    struct sockaddr_in6 *sin6;
    ipv6_target_t *tgt;
    ipsession_t *check;

    sin6 = (struct sockaddr_in6 *)(sess->targetip);
    if (sin6 == NULL) {
        logger(LOG_DAEMON, "OpenLI: attempted to add IPv6 intercept but target IP was NULL?");
        return -1;
    }

    v6addr = sin6->sin6_addr.s6_addr;

    HASH_FIND(hh, loc->activeipv6intercepts, v6addr, 16, tgt);
    if (tgt == NULL) {
        tgt = (ipv6_target_t *)malloc(sizeof(ipv6_target_t));
        if (!tgt) {
            logger(LOG_DAEMON, "OpenLI: ran out of memory while adding IPv6 intercept address.");
            return -1;
        }
        memcpy(tgt->address, v6addr, 16);
        tgt->intercepts = NULL;
        HASH_ADD_KEYPTR(hh, loc->activeipv6intercepts, tgt->address, 16, tgt);
    }

    HASH_FIND(hh, tgt->intercepts, sess->streamkey, strlen(sess->streamkey),
            check);
    assert(check == NULL);
    HASH_ADD_KEYPTR(hh, tgt->intercepts, sess->streamkey,
            strlen(sess->streamkey), sess);

    return 0;
}

static int remove_ipv4_intercept(colthread_local_t *loc, ipsession_t *torem) {

    ipv4_target_t *v4;
    struct sockaddr_in *sin;
    uint32_t v4addr;
    ipsession_t *found;

    sin = (struct sockaddr_in *)(torem->targetip);
    if (sin == NULL) {
        logger(LOG_DAEMON, "OpenLI: attempted to remove IPv4 intercept but target IP was NULL?");
        return -1;
    }

    v4addr = sin->sin_addr.s_addr;
    HASH_FIND(hh, loc->activeipv4intercepts, &v4addr, sizeof(v4addr), v4);
    if (!v4) {
        return 0;
    }

    HASH_FIND(hh, v4->intercepts, torem->streamkey, strlen(torem->streamkey),
            found);
    if (!found) {
        return 0;
    }

    HASH_DELETE(hh, v4->intercepts, found);
    free_single_ipsession(found);

    if (HASH_CNT(hh, v4->intercepts) == 0) {
        HASH_DELETE(hh, loc->activeipv4intercepts, v4);
        free(v4);
    }

    return 1;
}

static int remove_ipv6_intercept(colthread_local_t *loc, ipsession_t *torem) {

    ipv6_target_t *v6;
    struct sockaddr_in6 *sin6;
    uint8_t *v6addr;
    ipsession_t *found;

    sin6 = (struct sockaddr_in6 *)(torem->targetip);
    if (sin6 == NULL) {
        logger(LOG_DAEMON, "OpenLI: attempted to remove IPv6 intercept but target IP was NULL?");
        return -1;
    }

    v6addr = sin6->sin6_addr.s6_addr;
    HASH_FIND(hh, loc->activeipv6intercepts, v6addr, 16, v6);
    if (!v6) {
        return 0;
    }

    HASH_FIND(hh, v6->intercepts, torem->streamkey, strlen(torem->streamkey),
            found);
    if (!found) {
        return 0;
    }

    HASH_DELETE(hh, v6->intercepts, found);
    free_single_ipsession(found);

    if (HASH_CNT(hh, v6->intercepts) == 0) {
        HASH_DELETE(hh, loc->activeipv6intercepts, v6);
        free(v6);
    }

    return 1;
}


void handle_push_aluintercept(libtrace_thread_t *t, colthread_local_t *loc,
        aluintercept_t *alu) {
    HASH_ADD_KEYPTR(hh, loc->activealuintercepts, &(alu->aluinterceptid),
            sizeof(alu->aluinterceptid), alu);
}

void handle_halt_aluintercept(libtrace_thread_t *t, colthread_local_t *loc,
        aluintercept_t *alu) {

    aluintercept_t *found;

    HASH_FIND(hh, loc->activealuintercepts, &(alu->aluinterceptid),
            sizeof(alu->aluinterceptid), found);

    if (found == NULL) {
        logger(LOG_DAEMON, "OpenLI: collector thread was unable to remove ALU intercept %u, as it was not present in its intercept set.",
                alu->aluinterceptid);
    } else {
        HASH_DELETE(hh, loc->activealuintercepts, found);
    }
}

void handle_push_ipintercept(libtrace_thread_t *t, colthread_local_t *loc,
        ipsession_t *sess) {

    if (sess->ai_family == AF_INET) {
        if (add_ipv4_intercept(loc, sess) != 0) {
            free_single_ipsession(sess);
            return;
        }
    } else if (sess->ai_family == AF_INET6) {
        if (add_ipv6_intercept(loc, sess) != 0) {
            free_single_ipsession(sess);
            return;
        }
    } else {
        logger(LOG_DAEMON,
                 "OpenLI: invalid address family for new IP intercept: %d",
                 sess->ai_family);
        free_single_ipsession(sess);
        return;
    }
    logger(LOG_DAEMON,
            "OpenLI: collector thread %d has started intercepting %s IP session %s",
            trace_get_perpkt_thread_id(t),
            accesstype_to_string(sess->accesstype), sess->streamkey);
}

void handle_push_ipmmintercept(libtrace_thread_t *t, colthread_local_t *loc,
        rtpstreaminf_t *rtp) {

    HASH_ADD_KEYPTR(hh, loc->activertpintercepts, rtp->streamkey,
            strlen(rtp->streamkey), rtp);
    logger(LOG_DAEMON,
            "OpenLI: collector thread %d has started intercepting RTP stream %s",
            trace_get_perpkt_thread_id(t), rtp->streamkey);
}

void handle_halt_ipmmintercept(libtrace_thread_t *t, colthread_local_t *loc,
        char *streamkey) {
    if (remove_rtp_stream(loc, streamkey) != 0) {
        logger(LOG_DAEMON,
                "OpenLI: collector thread %d has stopped intercepting RTP stream %s",
                trace_get_perpkt_thread_id(t), streamkey);
    }
    free(streamkey);
}

void handle_halt_ipintercept(libtrace_thread_t *t , colthread_local_t *loc,
        ipsession_t *sess) {

    if (sess->ai_family == AF_INET) {
        if (remove_ipv4_intercept(loc, sess) > 0) {
            logger(LOG_DAEMON,
                    "OpenLI: collector thread %d has stopped intercepting IP session %s",
                    trace_get_perpkt_thread_id(t), sess->streamkey);

        }
    } else if (sess->ai_family == AF_INET6) {
        if (remove_ipv6_intercept(loc, sess) > 0) {
            logger(LOG_DAEMON,
                    "OpenLI: collector thread %d has stopped intercepting IP session %s",
                    trace_get_perpkt_thread_id(t), sess->streamkey);

        }
    } else {
        logger(LOG_DAEMON,
                 "OpenLI: invalid address family for new IP intercept: %d",
                 sess->ai_family);
    }
    free_single_ipsession(sess);
}

void handle_push_coreserver(libtrace_thread_t *t, colthread_local_t *loc,
        coreserver_t *cs) {
    coreserver_t *found, **servlist;

    switch(cs->servertype) {
        case OPENLI_CORE_SERVER_RADIUS:
            servlist = &(loc->radiusservers);
            break;
        case OPENLI_CORE_SERVER_SIP:
            servlist = &(loc->sipservers);
            break;
        default:
            logger(LOG_DAEMON,
                    "OpenLI: unexpected core server type received by collector thread %d: %d",
                    trace_get_perpkt_thread_id(t), cs->servertype);
            return;
    }
    HASH_FIND(hh, *servlist, cs->serverkey, strlen(cs->serverkey), found);
    if (!found) {
        HASH_ADD_KEYPTR(hh, *servlist, cs->serverkey, strlen(cs->serverkey),
                cs);
        logger(LOG_DAEMON, "OpenLI: collector thread %d has added %s to its %s core server list.",
                trace_get_perpkt_thread_id(t),
                cs->serverkey, coreserver_type_to_string(cs->servertype));
    } else {
        free_single_coreserver(cs);
    }

}

void handle_remove_coreserver(libtrace_thread_t *t, colthread_local_t *loc,
        coreserver_t *cs) {
    coreserver_t *found, **servlist;

    switch(cs->servertype) {
        case OPENLI_CORE_SERVER_RADIUS:
            servlist = &(loc->radiusservers);
            break;
        case OPENLI_CORE_SERVER_SIP:
            servlist = &(loc->sipservers);
            break;
        default:
            logger(LOG_DAEMON,
                    "OpenLI: unexpected core server type received by collector thread %d: %d",
                    trace_get_perpkt_thread_id(t), cs->servertype);
            return;
    }
    HASH_FIND(hh, *servlist, cs->serverkey, strlen(cs->serverkey), found);
    if (found) {
        HASH_DELETE(hh, *servlist, found);
        logger(LOG_DAEMON, "OpenLI: collector thread %d has removed %s from its %s core server list.",
                trace_get_perpkt_thread_id(t),
                cs->serverkey, coreserver_type_to_string(cs->servertype));
        free_single_coreserver(found);
    }
    free_single_coreserver(cs);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
