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

static inline void update_intercept_common(intercept_common_t *found,
        intercept_common_t *replace) {

    char *tmp;
    tmp = found->authcc;
    found->authcc = replace->authcc;
    found->authcc_len = replace->authcc_len;
    replace->authcc = tmp;

    tmp = found->delivcc;
    found->delivcc = replace->delivcc;
    found->delivcc_len = replace->delivcc_len;
    replace->delivcc = tmp;

    found->tostart_time = replace->tostart_time;
    found->toend_time = replace->toend_time;
    found->tomediate = replace->tomediate;
    found->encrypt = replace->encrypt;

    tmp = found->encryptkey;
    found->encryptkey = replace->encryptkey;
    replace->encryptkey = tmp;

    tmp = found->targetagency;
    found->targetagency = replace->targetagency;
    replace->targetagency = tmp;
}

static int remove_rtp_stream(colthread_local_t *loc, char *rtpstreamkey) {
    rtpstreaminf_t *rtp;

    HASH_FIND(hh, loc->activertpintercepts, rtpstreamkey, strlen(rtpstreamkey),
            rtp);

    if (rtp == NULL) {
        return 0;
    }

    HASH_DELETE(hh, loc->activertpintercepts, rtp);
    free_single_rtpstream(rtp);
    return 1;
}

int add_iprange_to_patricia(patricia_tree_t *ptree, char *iprangestr,
        intercept_common_t *common, uint32_t cin) {

    patricia_node_t *node = NULL;
    liid_set_t **all, *found;
    prefix_t *prefix = NULL;

    prefix = ascii2prefix(0, iprangestr);
    if (prefix == NULL) {
        logger(LOG_INFO,
                "OpenLI: error converting %s into a valid IP prefix",
                iprangestr);
        return -1;
    }

    node = patricia_lookup(ptree, prefix);

    if (!node) {
        logger(LOG_INFO,
                "OpenLI: error while adding IP prefix %s to LIID %s",
                iprangestr, common->liid);
        free(prefix);
        return -1;
    }

    all = (liid_set_t **)&(node->data);
    if (*all != NULL) {
        free(prefix);
    } else {
        prefix->ref_count --;
    }

    HASH_FIND(hh, *all, common->liid, common->liid_len, found);
    if (found) {
        return 0;
    } else {
        char key[128];

        found = (liid_set_t *)malloc(sizeof(liid_set_t));
        found->liid = strdup(common->liid);
        found->cin = cin;

        snprintf(key, 127, "%s-%u", found->liid, found->cin);
        found->key = strdup(key);
        found->keylen = strlen(found->key);


        HASH_ADD_KEYPTR(hh, *all, found->liid, strlen(found->liid), found);
        /*
        logger(LOG_INFO,
                "OpenLI: added LIID %s:%u to prefix %s (%d refs total)",
                common->liid, cin, iprangestr, HASH_CNT(hh, *all));
        */
    }
    return 1;

}

void remove_iprange_from_patricia(patricia_tree_t *ptree, char *iprangestr,
        intercept_common_t *common) {

    patricia_node_t *node = NULL;
    prefix_t *prefix = NULL;
    liid_set_t **all, *found;

    prefix = ascii2prefix(0, iprangestr);
    if (prefix == NULL) {
        logger(LOG_INFO,
                "OpenLI: error converting %s into a valid IP prefix",
                iprangestr);
        goto bailremoverange;
    }

    node = patricia_search_exact(ptree, prefix);

    if (!node) {
        logger(LOG_INFO,
                "OpenLI: supposed to remove IP prefix %s for LIID %s but no such prefix exists in the tree.",
                iprangestr, common->liid);
        goto bailremoverange;
    }

    all = (liid_set_t **)&(node->data);
    HASH_FIND(hh, *all, common->liid, common->liid_len, found);
    if (!found) {
        logger(LOG_INFO,
                "OpenLI: supposed to remove IP prefix %s for LIID %s but the LIID is not associated with that prefix.",
                iprangestr, common->liid);
        goto bailremoverange;
    }

    HASH_DELETE(hh, *all, found);
    /*
    logger(LOG_INFO,
            "OpenLI: removed LIID %s from prefix %s (%d refs remaining)",
            common->liid, iprangestr, HASH_CNT(hh, *all));
    */
    if (*all == NULL) {
        patricia_remove(ptree, node);
    }
    free(found->liid);
    free(found->key);
    free(found);

bailremoverange:
    if (prefix) {
        free(prefix);
    }
    return;
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
    if (check) {
        logger(LOG_INFO, "OpenLI: encountered duplicate stream key '%s' for address %u -- replacing...", sess->streamkey, tgt->address);
        HASH_DELETE(hh, tgt->intercepts, check);
        free_single_ipsession(check);
    }

    HASH_ADD_KEYPTR(hh, tgt->intercepts, sess->streamkey,
            strlen(sess->streamkey), sess);

    return 0;
}

static int add_ipv6_intercept(colthread_local_t *loc, ipsession_t *sess) {

    struct sockaddr_in6 *sin6;
    ipv6_target_t *tgt;
    ipsession_t *check;
    char prefixstr[100];
    char inet[INET6_ADDRSTRLEN];

    sin6 = (struct sockaddr_in6 *)(sess->targetip);
    if (sin6 == NULL) {
        logger(LOG_INFO, "OpenLI: attempted to add IPv6 intercept but target IP was NULL?");
        return -1;
    }

    if (inet_ntop(AF_INET6, &(sin6->sin6_addr), inet, INET6_ADDRSTRLEN)
            == NULL) {
        logger(LOG_INFO, "OpenLI: IPv6 intercept prefix does not contain a valid IPv6 address");
        return -1;
    }

    snprintf(prefixstr, 100, "%s/%u", inet, sess->prefixlen);

    if (add_iprange_to_patricia(loc->dynamicv6ranges, prefixstr,
            &(sess->common), sess->cin) < 0) {
        return -1;
    }

    HASH_FIND(hh, loc->activeipv6intercepts, prefixstr, strlen(prefixstr), tgt);
    if (tgt == NULL) {
        tgt = (ipv6_target_t *)malloc(sizeof(ipv6_target_t));
        if (!tgt) {
            logger(LOG_INFO, "OpenLI: ran out of memory while adding IPv6 intercept address.");
            return -1;
        }
        memcpy(tgt->address, sin6->sin6_addr.s6_addr, 16);
        tgt->prefixlen = sess->prefixlen;
        tgt->prefixstr = strdup(prefixstr);
        tgt->intercepts = NULL;
        HASH_ADD_KEYPTR(hh, loc->activeipv6intercepts, tgt->prefixstr,
                strlen(tgt->prefixstr), tgt);
    }

    HASH_FIND(hh, tgt->intercepts, sess->streamkey, strlen(sess->streamkey),
            check);
    if (check) {
        logger(LOG_INFO, "OpenLI: encountered duplicate stream key '%s' for address %s -- replacing...", sess->streamkey, prefixstr);
        HASH_DELETE(hh, tgt->intercepts, check);
        free_single_ipsession(check);
    }
    HASH_ADD_KEYPTR(hh, tgt->intercepts, sess->streamkey,
            strlen(sess->streamkey), sess);

    return 0;
}

static inline ipsession_t *find_ipv4_intercept(colthread_local_t *loc,
        ipsession_t *tofind, ipv4_target_t **v4) {

    struct sockaddr_in *sin;
    uint32_t v4addr;
    ipsession_t *found;

    sin = (struct sockaddr_in *)(tofind->targetip);
    if (sin == NULL) {
        logger(LOG_INFO, "OpenLI: attempted to find IPv4 intercept but target IP was NULL?");
        return NULL;
    }

    v4addr = sin->sin_addr.s_addr;
    *v4 = NULL;
    HASH_FIND(hh, loc->activeipv4intercepts, &v4addr, sizeof(v4addr), *v4);
    if ((*v4) == NULL) {
        return NULL;
    }

    HASH_FIND(hh, (*v4)->intercepts, tofind->streamkey,
            strlen(tofind->streamkey), found);
    return found;
}

static int update_ipv4_intercept(colthread_local_t *loc, ipsession_t *toup) {

    ipsession_t *found;
    ipv4_target_t *v4;

    found = find_ipv4_intercept(loc, toup, &v4);
    if (!found) {
        return 0;
    }

    update_intercept_common(&(found->common), &(toup->common));
    return 1;
}

static int remove_ipv4_intercept(colthread_local_t *loc, ipsession_t *torem) {

    ipsession_t *found;
    ipv4_target_t *v4;

    found = find_ipv4_intercept(loc, torem, &v4);
    if (!found || v4 == NULL) {
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

static inline ipsession_t *find_ipv6_intercept(colthread_local_t *loc,
        ipsession_t *tofind, ipv6_target_t **v6, char *prefixstr,
        int pfxstrlen) {

    struct sockaddr_in6 *sin6;
    ipsession_t *found;
    char inet[INET6_ADDRSTRLEN];

    sin6 = (struct sockaddr_in6 *)(tofind->targetip);
    if (sin6 == NULL) {
        logger(LOG_INFO, "OpenLI: attempted to find IPv6 intercept but target IP was NULL?");
        return NULL;
    }

    if (inet_ntop(AF_INET6, &(sin6->sin6_addr), inet, INET6_ADDRSTRLEN)
            == NULL) {
        logger(LOG_INFO, "OpenLI: IPv6 intercept prefix does not contain a valid IPv6 address");
        return NULL;
    }

    snprintf(prefixstr, pfxstrlen, "%s/%u", inet, tofind->prefixlen);
    *v6 = NULL;

    HASH_FIND(hh, loc->activeipv6intercepts, prefixstr, strlen(prefixstr), *v6);
    if ((*v6) == NULL) {
        return NULL;
    }

    HASH_FIND(hh, (*v6)->intercepts, tofind->streamkey,
            strlen(tofind->streamkey), found);
    return found;
}

static int update_ipv6_intercept(colthread_local_t *loc, ipsession_t *toup) {

    ipsession_t *found;
    ipv6_target_t *v6;
    char prefixstr[100];

    found = find_ipv6_intercept(loc, toup, &v6, prefixstr, 100);
    if (!found) {
        return 0;
    }

    update_intercept_common(&(found->common), &(toup->common));
    return 1;
}

static int remove_ipv6_intercept(colthread_local_t *loc, ipsession_t *torem) {

    ipsession_t *found;
    ipv6_target_t *v6;
    char prefixstr[100];

    found = find_ipv6_intercept(loc, torem, &v6, prefixstr, 100);
    if (!found || v6 == NULL) {
        return 0;
    }

    remove_iprange_from_patricia(loc->dynamicv6ranges, prefixstr,
            &(found->common));

    HASH_DELETE(hh, v6->intercepts, found);
    free_single_ipsession(found);

    if (HASH_CNT(hh, v6->intercepts) == 0) {
        HASH_DELETE(hh, loc->activeipv6intercepts, v6);
        free(v6->prefixstr);
        free(v6);
    }

    return 1;
}

void handle_push_mirror_intercept(libtrace_thread_t *t, colthread_local_t *loc,
        vendmirror_intercept_t *vmi) {

    vendmirror_intercept_list_t *vmilist = NULL;
    vendmirror_intercept_t *found = NULL;

    HASH_FIND(hh, loc->activemirrorintercepts, &(vmi->sessionid),
            sizeof(vmi->sessionid), vmilist);

    if (!vmilist) {
        vmilist = calloc(1, sizeof(vendmirror_intercept_list_t));

        vmilist->sessionid = vmi->sessionid;
        vmilist->intercepts = NULL;
        HASH_ADD_KEYPTR(hh, loc->activemirrorintercepts, &(vmi->sessionid),
                sizeof(vmi->sessionid), vmilist);
    }

    HASH_FIND(hh, vmilist->intercepts, vmi->common.liid, (vmi->common.liid_len),
            found);
    if (!found) {
        HASH_ADD_KEYPTR(hh, vmilist->intercepts, vmi->common.liid,
                vmi->common.liid_len, vmi);
    } else {
        logger(LOG_INFO, "OpenLI: collector received duplicate vendmirror intercept %u:%s, ignoring. %d", vmi->sessionid, vmi->common.liid,
                trace_get_perpkt_thread_id(t));
        free_single_vendmirror_intercept(vmi);
    }

}

void handle_halt_mirror_intercept(libtrace_thread_t *t,
        colthread_local_t *loc, vendmirror_intercept_t *vmi) {
    vendmirror_intercept_t *found;
    vendmirror_intercept_list_t *parent;

    HASH_FIND(hh, loc->activemirrorintercepts, &(vmi->sessionid),
            sizeof(vmi->sessionid), parent);

    if (parent == NULL) {
        logger(LOG_INFO, "OpenLI: collector thread was unable to remove JMirror intercept %u:%s, as the session ID was not present in its intercept set.",
                vmi->sessionid, vmi->common.liid);
        return;
    }

    HASH_FIND(hh, parent->intercepts, vmi->common.liid, vmi->common.liid_len,
            found);
    if (found == NULL) {
        logger(LOG_INFO, "OpenLI: collector thread was unable to remove JMirror intercept %u:%s, as the LIID was not present in its intercept list.",
                vmi->sessionid, vmi->common.liid);
        return;
    }

    HASH_DELETE(hh, parent->intercepts, found);
    free_single_vendmirror_intercept(found);

    if (HASH_CNT(hh, parent->intercepts) == 0) {
        HASH_DELETE(hh, loc->activemirrorintercepts, parent);
        free(parent);
    }
    free_single_vendmirror_intercept(vmi);
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
    logger(LOG_INFO,
            "OpenLI: collector thread %d has started intercepting %s IP session %s",
            trace_get_perpkt_thread_id(t),
            accesstype_to_string(sess->accesstype), sess->streamkey);
}

void handle_push_ipmmintercept(libtrace_thread_t *t, colthread_local_t *loc,
        rtpstreaminf_t *rtp) {

    /* If stream key already exists, remove it and replace it */
    remove_rtp_stream(loc, rtp->streamkey);

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
        case OPENLI_CORE_SERVER_SMTP:
            servlist = &(loc->smtpservers);
            break;
        case OPENLI_CORE_SERVER_IMAP:
            servlist = &(loc->imapservers);
            break;
        case OPENLI_CORE_SERVER_POP3:
            servlist = &(loc->pop3servers);
            break;
        case OPENLI_CORE_SERVER_GTP:
            servlist = &(loc->gtpservers);
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
        case OPENLI_CORE_SERVER_SMTP:
            servlist = &(loc->smtpservers);
            break;
        case OPENLI_CORE_SERVER_IMAP:
            servlist = &(loc->imapservers);
            break;
        case OPENLI_CORE_SERVER_POP3:
            servlist = &(loc->pop3servers);
            break;
        case OPENLI_CORE_SERVER_GTP:
            servlist = &(loc->gtpservers);
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

    staticipsession_t *ipr_exist;
    patricia_tree_t *ptree = NULL;

    if (strchr(ipr->rangestr, ':')) {
        ptree = loc->staticv6ranges;
    } else {
        ptree = loc->staticv4ranges;
    }

    if (add_iprange_to_patricia(ptree, ipr->rangestr, &(ipr->common),
            ipr->cin) <= 0) {

        free_single_staticipsession(ipr);
        return;
    }

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

    staticipsession_t *sessrec;
    patricia_tree_t *ptree;

    if (strchr(ipr->rangestr, ':')) {
        ptree = loc->staticv6ranges;
    } else {
        ptree = loc->staticv4ranges;
    }

    remove_iprange_from_patricia(ptree, ipr->rangestr, &(ipr->common));

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

    free_single_staticipsession(ipr);
    return;
}

void handle_change_voip_intercept(libtrace_thread_t *t, colthread_local_t *loc,
        rtpstreaminf_t *tochange) {

    rtpstreaminf_t *rtp;

    if (tochange->streamkey == NULL) {
        return;
    }

    HASH_FIND(hh, loc->activertpintercepts, tochange->streamkey,
            strlen(tochange->streamkey), rtp);

    if (rtp == NULL) {
        logger(LOG_INFO, "OpenLI: collector thread was unable to modify RTP stream %s, as it was not present in its intercept set.",
                tochange->streamkey);
        return;
    }

    update_intercept_common(&(rtp->common), &(tochange->common));
    free_single_rtpstream(tochange);
}

void handle_change_vendmirror_intercept(libtrace_thread_t *t,
        colthread_local_t *loc, vendmirror_intercept_t *vend) {

    vendmirror_intercept_t *found;
    vendmirror_intercept_list_t *parent;

    HASH_FIND(hh, loc->activemirrorintercepts, &(vend->sessionid),
            sizeof(vend->sessionid), parent);

    if (parent == NULL) {
        logger(LOG_INFO, "OpenLI: collector thread was unable to modify Vendor Mirror intercept %u:%s, as the session ID was not present in its intercept set.",
                vend->sessionid, vend->common.liid);
        return;
    }

    HASH_FIND(hh, parent->intercepts, vend->common.liid, vend->common.liid_len,
            found);
    if (found == NULL) {
        logger(LOG_INFO, "OpenLI: collector thread was unable to modify Vendor Mirror intercept %u:%s, as the LIID was not present in its intercept list.",
                vend->sessionid, vend->common.liid);
        return;
    }

    update_intercept_common(&(found->common), &(vend->common));
    free_single_vendmirror_intercept(vend);
}

void handle_change_iprange_intercept(libtrace_thread_t *t,
        colthread_local_t *loc, staticipsession_t *ipr) {

    staticipsession_t *sessrec;

    HASH_FIND(hh, loc->activestaticintercepts, ipr->key, strlen(ipr->key),
            sessrec);
    if (sessrec) {
        update_intercept_common(&(sessrec->common), &(ipr->common));
    }

    free_single_staticipsession(ipr);
}

void handle_change_ipint_intercept(libtrace_thread_t *t, colthread_local_t *loc,
        ipsession_t *sess) {

    if (sess->ai_family == AF_INET) {
        if (update_ipv4_intercept(loc, sess) > 0) {

        }
    } else if (sess->ai_family == AF_INET6) {
        if (update_ipv6_intercept(loc, sess) > 0) {

        }
    } else {
        logger(LOG_INFO,
                 "OpenLI: invalid address family for new IP intercept: %d",
                 sess->ai_family);
    }
    free_single_ipsession(sess);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
