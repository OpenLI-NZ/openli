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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <libwandder.h>
#include <libwandder_etsili.h>
#include <libtrace_parallel.h>

#include "logger.h"
#include "collector.h"
#include "collector_publish.h"
#include "etsili_core.h"
#include "ipcc.h"

static inline static_ipcache_t *find_static_cached(prefix_t *prefix,
        colthread_local_t *loc) {

    static_ipcache_t *found;
    HASH_FIND(hh, loc->staticcache, prefix, sizeof(prefix_t), found);

    if (found) {
        /* Push it back to the front of the queue so it doesn't expire */
        HASH_DELETE(hh, loc->staticcache, found);
        HASH_ADD_KEYPTR(hh, loc->staticcache, &(found->prefix),
                sizeof(prefix_t), found);
    }
    return found;

}

static inline int add_static_cached(prefix_t *prefix, patricia_node_t *pnode,
        colthread_local_t *loc) {

    static_ipcache_t *ent, *tmp;

    ent = (static_ipcache_t *)malloc(sizeof(static_ipcache_t));
    memcpy(&(ent->prefix), prefix, sizeof(prefix_t));
    ent->pnode = pnode;

    HASH_ADD_KEYPTR(hh, loc->staticcache, &(ent->prefix), sizeof(prefix_t),
            ent);

    if (HASH_COUNT(loc->staticcache) >= 1000000) {
        HASH_ITER(hh, loc->staticcache, ent, tmp) {
            HASH_DELETE(hh, loc->staticcache, ent);
            free(ent);
            break;
        }
    }
    return 0;
}

static inline int lookup_static_ranges(struct sockaddr *cmp,
        int family, libtrace_packet_t *pkt, uint8_t dir,
        colthread_local_t *loc, struct timeval *tv) {

    int matched = 0;
    patricia_node_t *pnode = NULL;
    prefix_t prefix;
    openli_export_recv_t *msg;
    static_ipcache_t *cached = NULL;

    memset(&prefix, 0, sizeof(prefix_t));

    if (family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)cmp;
        memcpy(&(prefix.add.sin), &(in->sin_addr), 4);
        prefix.bitlen = 32;
        prefix.family = AF_INET;
        prefix.ref_count = 0;
    } else {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)cmp;
        memcpy(&(prefix.add.sin6), &(in6->sin6_addr), 16);
        prefix.bitlen = 128;
        prefix.family = AF_INET6;
        prefix.ref_count = 0;
    }


    //cached = find_static_cached(&prefix, loc);
    if (cached) {
        pnode = cached->pnode;
    } else {
        if (family == AF_INET) {
            pnode = patricia_search_best2(loc->staticv4ranges, &prefix, 1);
        } else {
            pnode = patricia_search_best2(loc->staticv6ranges, &prefix, 1);
        }
        //add_static_cached(&prefix, pnode, loc);
    }

    while (pnode) {
        liid_set_t **all, *sliid, *tmp2;

        all = (liid_set_t **)(&(pnode->data));
        HASH_ITER(hh, *all, sliid, tmp2) {
            staticipsession_t *matchsess;
            HASH_FIND(hh, loc->activestaticintercepts, sliid->key,
                    sliid->keylen, matchsess);
            if (!matchsess) {
                logger(LOG_INFO,
                        "OpenLI: matched an IP range for intercept %s but this is not present in activestaticintercepts",
                        sliid->key);
            } else {
                if (matchsess->common.tomediate ==
                        OPENLI_INTERCEPT_OUTPUTS_IRIONLY) {
                    continue;
                }

                if (tv->tv_sec < matchsess->common.tostart_time) {
                    continue;
                }

                if (matchsess->common.toend_time > 0 &&
                        tv->tv_sec >= matchsess->common.toend_time) {
                    continue;
                }

                matched ++;
                msg = create_ipcc_job(matchsess->cin, matchsess->common.liid,
                        matchsess->common.destid, pkt, dir);
                publish_openli_msg(loc->zmq_pubsocks[0], msg);  //FIXME
            }
        }
        pnode = pnode->parent;
    }
    return matched;
}

static void singlev6_conn_contents(struct sockaddr_in6 *cmp,
        colthread_local_t *loc, int *matched, libtrace_packet_t *pkt,
        struct timeval *tv) {

    patricia_node_t *pnode = NULL;
    prefix_t prefix;
    openli_export_recv_t *msg;
    ipv6_target_t *tgt;
    ipsession_t *sess, *tmp;

    memset(&prefix, 0, sizeof(prefix_t));
    memcpy(&(prefix.add.sin6), &(cmp->sin6_addr), 16);
    prefix.bitlen = 128;
    prefix.family = AF_INET6;
    prefix.ref_count = 0;

    pnode = patricia_search_best2(loc->dynamicv6ranges, &prefix, 1);

    while (pnode) {
        liid_set_t **all, *sliid, *tmp2;

        all = (liid_set_t **)(&(pnode->data));
        HASH_ITER(hh, *all, sliid, tmp2) {
            HASH_FIND(hh, loc->activeipv6intercepts, sliid->key, sliid->keylen,
                    tgt);
            if (!tgt) {
                logger(LOG_INFO,
                        "OpenLI: matched an IPv6 range for intercept %s but this intercept is not present in activeipv6intercepts?",
                        sliid->key);
            } else {
                HASH_ITER(hh, tgt->intercepts, sess, tmp) {
                    if (sess->common.tomediate ==
                            OPENLI_INTERCEPT_OUTPUTS_IRIONLY) {
                        continue;
                    }

                    if (tv->tv_sec < sess->common.tostart_time) {
                        continue;
                    }

                    if (sess->common.toend_time > 0 && tv->tv_sec >=
                            sess->common.toend_time) {
                        continue;
                    }

                    *matched = ((*matched) + 1);
                    msg = create_ipcc_job(sess->cin, sess->common.liid,
                            sess->common.destid, pkt, 0);
                    if (sess->accesstype == INTERNET_ACCESS_TYPE_MOBILE && msg)
                    {
                        msg->type = OPENLI_EXPORT_UMTSCC;
                    }
                    if (msg != NULL) {
                        publish_openli_msg(loc->zmq_pubsocks[0], msg);  //FIXME
                    }
                }
            }
        }
        pnode = pnode->parent;
    }
}

int ipv6_comm_contents(libtrace_packet_t *pkt, packet_info_t *pinfo,
        libtrace_ip6_t *ip, uint32_t rem, colthread_local_t *loc) {

    struct sockaddr_in6 *cmp;
    int matched = 0;

    if (rem < sizeof(libtrace_ip6_t)) {
        /* Truncated IP header */
        logger(LOG_INFO, "OpenLI: Got IPv6 packet with truncated header?");
        return 0;
    }

    /* Check if ipsrc or ipdst match any of our active intercepts.
     * NOTE: a packet can match multiple intercepts so don't break early.
     */
    cmp = (struct sockaddr_in6 *)(&pinfo->srcip);
    singlev6_conn_contents(cmp, loc, &matched, pkt, &pinfo->tv);

    cmp = (struct sockaddr_in6 *)(&pinfo->destip);
    singlev6_conn_contents(cmp, loc, &matched, pkt, &pinfo->tv);

    matched += lookup_static_ranges((struct sockaddr *)(&pinfo->srcip),
            AF_INET6, pkt, 0, loc, &pinfo->tv);
    matched += lookup_static_ranges((struct sockaddr *)(&pinfo->destip),
            AF_INET6, pkt, 1, loc, &pinfo->tv);

    return matched;
}


int ipv4_comm_contents(libtrace_packet_t *pkt, packet_info_t *pinfo,
        libtrace_ip_t *ip, uint32_t rem, colthread_local_t *loc) {

    struct sockaddr_in *cmp;
    openli_export_recv_t *msg;
    int matched = 0;
    ipv4_target_t *tgt;
    ipsession_t *sess, *tmp;

    if (rem < sizeof(libtrace_ip_t)) {
        /* Truncated IP header */
        logger(LOG_INFO, "OpenLI: Got IPv4 packet with truncated header?");
        return 0;
    }

    /* Check if ipsrc or ipdst match any of our active intercepts.
     * NOTE: a packet can match multiple intercepts so don't break early.
     */

    cmp = (struct sockaddr_in *)(&pinfo->srcip);
    HASH_FIND(hh, loc->activeipv4intercepts, &(cmp->sin_addr.s_addr),
            sizeof(cmp->sin_addr.s_addr), tgt);

    if (tgt) {
        HASH_ITER(hh, tgt->intercepts, sess, tmp) {
            if (sess->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_IRIONLY) {
                continue;
            }
            if (pinfo->tv.tv_sec < sess->common.tostart_time) {
                continue;
            }

            if (sess->common.toend_time > 0 && pinfo->tv.tv_sec >=
                    sess->common.toend_time) {
                continue;
            }

            matched ++;
            msg = create_ipcc_job(sess->cin, sess->common.liid,
                    sess->common.destid, pkt, 0);
            if (sess->accesstype == INTERNET_ACCESS_TYPE_MOBILE && msg) {
                msg->type = OPENLI_EXPORT_UMTSCC;
            }
            if (msg != NULL) {
                publish_openli_msg(loc->zmq_pubsocks[0], msg);  //FIXME
            }
        }
    }

    cmp = (struct sockaddr_in *)(&pinfo->destip);
    HASH_FIND(hh, loc->activeipv4intercepts, &(cmp->sin_addr.s_addr),
            sizeof(cmp->sin_addr.s_addr), tgt);

    if (tgt) {
        HASH_ITER(hh, tgt->intercepts, sess, tmp) {
            if (sess->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_IRIONLY) {
                continue;
            }
            if (pinfo->tv.tv_sec < sess->common.tostart_time) {
                continue;
            }

            if (sess->common.toend_time > 0 && pinfo->tv.tv_sec >=
                    sess->common.toend_time) {
                continue;
            }

            matched ++;
            msg = create_ipcc_job(sess->cin, sess->common.liid,
                    sess->common.destid, pkt, 1);
            if (sess->accesstype == INTERNET_ACCESS_TYPE_MOBILE && msg) {
                msg->type = OPENLI_EXPORT_UMTSCC;
            }
            if (msg != NULL) {
                publish_openli_msg(loc->zmq_pubsocks[0], msg);  //FIXME
            }
        }
    }

    if (loc->staticv4ranges == NULL) {
        goto ipv4ccdone;
    }

    matched += lookup_static_ranges((struct sockaddr *)(&pinfo->srcip),
            AF_INET, pkt, 0, loc, &pinfo->tv);
    matched += lookup_static_ranges((struct sockaddr *)(&pinfo->destip),
            AF_INET, pkt, 1, loc, &pinfo->tv);


ipv4ccdone:
    return matched;

}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
