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
        logger(LOG_INFO, "OpenLI: collector thread was unable to remove RTP stream %s, as it was not present in its intercept set.",
                rtpstreamkey);
        return 0;
    }

    HASH_DELETE(hh, loc->activertpintercepts, rtp);
    free_single_rtpstream(rtp);
    return 1;
}

static int add_ipv4_intercept(colthread_local_t *loc, ipsession_t *sess) {

    uint32_t v4addr;
    struct sockaddr_in *sin;
    ipv4_target_t *tgt;
    ipsession_t *check;

    sin = (struct sockaddr_in *)(sess->targetip);
    if (sin == NULL) {
        logger(LOG_INFO, "OpenLI: attempted to add IPv4 intercept but target IP was NULL?");
        return -1;
    }

    v4addr = sin->sin_addr.s_addr;

    HASH_FIND(hh, loc->activeipv4intercepts, &v4addr, sizeof(v4addr), tgt);
    if (tgt == NULL) {
        tgt = (ipv4_target_t *)malloc(sizeof(ipv4_target_t));
        if (!tgt) {
            logger(LOG_INFO, "OpenLI: ran out of memory while adding IPv4 intercept address.");
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
        logger(LOG_INFO, "OpenLI: attempted to add IPv6 intercept but target IP was NULL?");
        return -1;
    }

    v6addr = sin6->sin6_addr.s6_addr;

    HASH_FIND(hh, loc->activeipv6intercepts, v6addr, 16, tgt);
    if (tgt == NULL) {
        tgt = (ipv6_target_t *)malloc(sizeof(ipv6_target_t));
        if (!tgt) {
            logger(LOG_INFO, "OpenLI: ran out of memory while adding IPv6 intercept address.");
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
        logger(LOG_INFO, "OpenLI: attempted to remove IPv4 intercept but target IP was NULL?");
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
        logger(LOG_INFO, "OpenLI: attempted to remove IPv6 intercept but target IP was NULL?");
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

void handle_push_mirror_intercept(libtrace_thread_t *t, colthread_local_t *loc,
        vendmirror_intercept_t *vmi) {
    HASH_ADD_KEYPTR(hh, loc->activemirrorintercepts,
            &(vmi->interceptid), sizeof(vmi->interceptid), vmi);
}

void handle_halt_mirror_intercept(libtrace_thread_t *t,
        colthread_local_t *loc, vendmirror_intercept_t *vmi) {
    vendmirror_intercept_t *found;

    HASH_FIND(hh, loc->activemirrorintercepts, &(vmi->interceptid),
            sizeof(vmi->interceptid), found);

    if (found == NULL) {
        logger(LOG_INFO, "OpenLI: collector thread was unable to remove JMirror intercept %u, as it was not present in its intercept set.",
                vmi->interceptid);
    } else {
        HASH_DELETE(hh, loc->activemirrorintercepts, found);
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
        logger(LOG_INFO,
                 "OpenLI: invalid address family for new IP intercept: %d",
                 sess->ai_family);
        free_single_ipsession(sess);
        return;
    }
    /*
    logger(LOG_INFO,
            "OpenLI: collector thread %d has started intercepting %s IP session %s",
            trace_get_perpkt_thread_id(t),
            accesstype_to_string(sess->accesstype), sess->streamkey);
    */
}

void handle_push_ipmmintercept(libtrace_thread_t *t, colthread_local_t *loc,
        rtpstreaminf_t *rtp) {

    HASH_ADD_KEYPTR(hh, loc->activertpintercepts, rtp->streamkey,
            strlen(rtp->streamkey), rtp);
    /*
    logger(LOG_INFO,
            "OpenLI: collector thread %d has started intercepting RTP stream %s",
            trace_get_perpkt_thread_id(t), rtp->streamkey);
    */
}

void handle_halt_ipmmintercept(libtrace_thread_t *t, colthread_local_t *loc,
        char *streamkey) {
    if (remove_rtp_stream(loc, streamkey) != 0) {
        /*
        logger(LOG_INFO,
                "OpenLI: collector thread %d has stopped intercepting RTP stream %s",
                trace_get_perpkt_thread_id(t), streamkey);
        */
    }
    free(streamkey);
}

void handle_halt_ipintercept(libtrace_thread_t *t , colthread_local_t *loc,
        ipsession_t *sess) {

    if (sess->ai_family == AF_INET) {
        if (remove_ipv4_intercept(loc, sess) > 0) {
            /*
            logger(LOG_INFO,
                    "OpenLI: collector thread %d has stopped intercepting IP session %s",
                    trace_get_perpkt_thread_id(t), sess->streamkey);
            */

        }
    } else if (sess->ai_family == AF_INET6) {
        if (remove_ipv6_intercept(loc, sess) > 0) {
            /*
            logger(LOG_INFO,
                    "OpenLI: collector thread %d has stopped intercepting IP session %s",
                    trace_get_perpkt_thread_id(t), sess->streamkey);
            */

        }
    } else {
        logger(LOG_INFO,
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
            logger(LOG_INFO,
                    "OpenLI: unexpected core server type received by collector thread %d: %d",
                    trace_get_perpkt_thread_id(t), cs->servertype);
            return;
    }
    HASH_FIND(hh, *servlist, cs->serverkey, strlen(cs->serverkey), found);
    if (!found) {
        HASH_ADD_KEYPTR(hh, *servlist, cs->serverkey, strlen(cs->serverkey),
                cs);
        /*
        logger(LOG_INFO, "OpenLI: collector thread %d has added %s to its %s core server list.",
                trace_get_perpkt_thread_id(t),
                cs->serverkey, coreserver_type_to_string(cs->servertype));
        */
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
            logger(LOG_INFO,
                    "OpenLI: unexpected core server type received by collector thread %d: %d",
                    trace_get_perpkt_thread_id(t), cs->servertype);
            return;
    }
    HASH_FIND(hh, *servlist, cs->serverkey, strlen(cs->serverkey), found);
    if (found) {
        HASH_DELETE(hh, *servlist, found);
        /*
        logger(LOG_INFO, "OpenLI: collector thread %d has removed %s from its %s core server list.",
                trace_get_perpkt_thread_id(t),
                cs->serverkey, coreserver_type_to_string(cs->servertype));
        */
        free_single_coreserver(found);
    }
    free_single_coreserver(cs);
}

void handle_iprange(libtrace_thread_t *t, colthread_local_t *loc,
        staticipsession_t *ipr) {

    patricia_node_t *node = NULL;
    liid_set_t **all, *found;
    prefix_t *prefix = NULL;
    staticipsession_t *newsess, *ipr_exist;

    prefix = ascii2prefix(0, ipr->rangestr);
    if (prefix == NULL) {
        logger(LOG_INFO,
                "OpenLI: error converting %s into a valid IP prefix in thread %d",
                ipr->rangestr, trace_get_perpkt_thread_id(t));
        free_single_staticipsession(ipr);
        return;
    }

    if (prefix->family == AF_INET) {
        node = patricia_lookup(loc->staticv4ranges, prefix);
    } else if (prefix->family == AF_INET6) {
        node = patricia_lookup(loc->staticv6ranges, prefix);
    }

    if (!node) {
        logger(LOG_INFO,
                "OpenLI: error while adding static IP prefix %s to LIID %s for thread %d",
                ipr->rangestr, ipr->common.liid, trace_get_perpkt_thread_id(t));
        free_single_staticipsession(ipr);
        free(prefix);
        return;
    }

    all = (liid_set_t **)&(node->data);
    if (*all != NULL) {
        free(prefix);
    } else {
        prefix->ref_count --;
    }

    HASH_FIND(hh, *all, ipr->common.liid, ipr->common.liid_len, found);
    if (found) {
        free_single_staticipsession(ipr);
    } else {
        char key[128];

        found = (liid_set_t *)malloc(sizeof(liid_set_t));
        found->liid = strdup(ipr->common.liid);
        found->cin = ipr->cin;

        snprintf(key, 127, "%s-%u", found->liid, found->cin);
        found->key = strdup(key);
        found->keylen = strlen(found->key);


        HASH_ADD_KEYPTR(hh, *all, found->liid, strlen(found->liid), found);
        /*
        logger(LOG_INFO,
                "OpenLI: added LIID %s:%u to prefix %s (%d refs total)",
                ipr->common.liid, ipr->cin, ipr->rangestr, HASH_CNT(hh, *all));
        */

        HASH_FIND(hh, loc->activestaticintercepts, ipr->key,
                strlen(ipr->key), ipr_exist);
        if (!ipr_exist) {
            ipr->references = 1;
            HASH_ADD_KEYPTR(hh, loc->activestaticintercepts, ipr->key,
                    strlen(ipr->key), ipr);
        } else {
            ipr_exist->references ++;
            free_single_staticipsession(ipr);
        }
    }
}

void handle_modify_iprange(libtrace_thread_t *t, colthread_local_t *loc,
        staticipsession_t *ipr) {

    liid_set_t *found = NULL, **all;
    staticipsession_t *sessrec, *ipr_exist;
    char key[128];
    patricia_node_t *node = NULL;
    prefix_t *prefix;

    prefix = ascii2prefix(0, ipr->rangestr);
    if (prefix == NULL) {
        logger(LOG_INFO,
                "OpenLI: error converting %s into a valid IP prefix in thread %d",
                ipr->rangestr, trace_get_perpkt_thread_id(t));
        goto bailmodrange;
    }

    if (prefix->family == AF_INET) {
        node = patricia_search_exact(loc->staticv4ranges, prefix);
    } else if (prefix->family == AF_INET6) {
        node = patricia_search_exact(loc->staticv6ranges, prefix);
    }

    if (!node) {
        logger(LOG_INFO,
                "OpenLI: thread %d was supposed to modify IP prefix %s for LIID %s but no such prefix exists in the tree.",
                trace_get_perpkt_thread_id(t), ipr->rangestr, ipr->common.liid);
        goto bailmodrange;
    }

    all = (liid_set_t **)&(node->data);
    HASH_FIND(hh, *all, ipr->common.liid, ipr->common.liid_len, found);
    if (!found) {
        logger(LOG_INFO,
                "OpenLI: thread %d was supposed to modify IP prefix %s for LIID %s but the LIID is not associated with that prefix.",
                trace_get_perpkt_thread_id(t), ipr->rangestr, ipr->common.liid);
        goto bailmodrange;
    }

    HASH_FIND(hh, loc->activestaticintercepts, found->key, strlen(found->key),
            sessrec);

    if (sessrec) {
        sessrec->references --;
        if (sessrec->references == 0) {
            HASH_DELETE(hh, loc->activestaticintercepts, sessrec);
            free_single_staticipsession(sessrec);
        }
    } else {
        logger(LOG_INFO,
                "OpenLI: no static IP session exists for key %s, but we are supposed to be modifying the range for it.",
                found->key);
    }

    found->cin = ipr->cin;
    free(found->key);
    snprintf(key, 127, "%s-%u", found->liid, found->cin);
    found->key = strdup(key);
    found->keylen = strlen(found->key);

    HASH_FIND(hh, loc->activestaticintercepts, found->key,
            strlen(found->key), ipr_exist);
    if (!ipr_exist) {
        ipr->references = 1;
        HASH_ADD_KEYPTR(hh, loc->activestaticintercepts, found->key,
                strlen(found->key), ipr);
        ipr = NULL;
    } else {
        ipr_exist->references ++;
    }


bailmodrange:
    if (prefix) {
        free(prefix);
    }
    if (ipr) {
        free_single_staticipsession(ipr);
    }
    return;
}

void handle_remove_iprange(libtrace_thread_t *t, colthread_local_t *loc,
        staticipsession_t *ipr) {

    patricia_node_t *node = NULL;
    prefix_t *prefix;
    liid_set_t **all, *found;
    liid_set_t *a, *b;
    staticipsession_t *sessrec;

    prefix = ascii2prefix(0, ipr->rangestr);
    if (prefix == NULL) {
        logger(LOG_INFO,
                "OpenLI: error converting %s into a valid IP prefix in thread %d",
                ipr->rangestr, trace_get_perpkt_thread_id(t));
        goto bailremoverange;
    }

    if (prefix->family == AF_INET) {
        node = patricia_search_exact(loc->staticv4ranges, prefix);
    } else if (prefix->family == AF_INET6) {
        node = patricia_search_exact(loc->staticv6ranges, prefix);
    }

    if (!node) {
        logger(LOG_INFO,
                "OpenLI: thread %d was supposed to remove IP prefix %s for LIID %s but no such prefix exists in the tree.",
                trace_get_perpkt_thread_id(t), ipr->rangestr, ipr->common.liid);
        goto bailremoverange;
    }

    all = (liid_set_t **)&(node->data);
    HASH_FIND(hh, *all, ipr->common.liid, ipr->common.liid_len, found);
    if (!found) {
        logger(LOG_INFO,
                "OpenLI: thread %d was supposed to remove IP prefix %s for LIID %s but the LIID is not associated with that prefix.",
                trace_get_perpkt_thread_id(t), ipr->rangestr, ipr->common.liid);
        goto bailremoverange;
    }

    HASH_FIND(hh, loc->activestaticintercepts, ipr->key, strlen(ipr->key),
            sessrec);
    if (sessrec) {
        sessrec->references --;
        if (sessrec->references == 0) {
            HASH_DELETE(hh, loc->activestaticintercepts, sessrec);
            free_single_staticipsession(sessrec);
        }
    } else {
        logger(LOG_INFO,
                "OpenLI: no static IP session exists for key %s, but we are supposed to be removing a range for it.",
                ipr->key);
    }

    HASH_DELETE(hh, *all, found);
    /*
    logger(LOG_INFO,
            "OpenLI: removed LIID %s from prefix %s (%d refs remaining)",
            ipr->common.liid, ipr->rangestr, HASH_CNT(hh, *all));
    */
    if (*all == NULL) {
        if (prefix->family == AF_INET) {
            patricia_remove(loc->staticv4ranges, node);
        } else {
            patricia_remove(loc->staticv6ranges, node);
        }
    }
    free(found->liid);
    free(found->key);
    free(found);



bailremoverange:
    if (prefix) {
        free(prefix);
    }
    free_single_staticipsession(ipr);
    return;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
