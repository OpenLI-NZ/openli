/*
 *
 * Copyright (c) 2024 Searchlight New Zealand Ltd.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * OpenLI was originally developed by the University of Waikato WAND
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
#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <libtrace.h>
#include <sys/timerfd.h>

#include "gtp_worker.h"
#include "collector.h"
#include "logger.h"
#include "util.h"
#include "intercept.h"
#include "netcomms.h"

static void remove_gtp_intercept(openli_gtp_worker_t *worker,
        ipintercept_t *ipint) {

    /* The sync thread should tell the collector threads that the intercept
     * is over, so we don't need to "withdraw" any IP sessions that we've
     * announced.
     */

    remove_intercept_from_user_intercept_list(&worker->userintercepts, ipint);
    HASH_DELETE(hh_liid, worker->ipintercepts, ipint);
    free_single_ipintercept(ipint);
}

static void disable_unconfirmed_gtp_intercepts(openli_gtp_worker_t *worker) {
    ipintercept_t *ipint, *tmp;

    HASH_ITER(hh_liid, worker->ipintercepts, ipint, tmp) {
        if (ipint->awaitingconfirm) {
            remove_gtp_intercept(worker, ipint);
        }
    }
}

static void flag_gtp_intercepts(ipintercept_t *cepts) {
    ipintercept_t *ipint, *tmp;

    /* Don't worry about statics, because we should not be dealing with
     * them here anyway */
    HASH_ITER(hh_liid, cepts, ipint, tmp) {
        ipint->awaitingconfirm = 1;
    }

}

static void push_existing_ip_sessions(openli_gtp_worker_t *worker UNUSED,
        ipintercept_t *ipint UNUSED) {

    /* TODO */
}

static int init_gtp_intercept(openli_gtp_worker_t *worker,
        ipintercept_t *ipint) {

    if (ipint->accesstype != INTERNET_ACCESS_TYPE_MOBILE) {
        /* Only care about "mobile" intercepts */
        free_single_ipintercept(ipint);
        return 0;
    }

    /* Discard any static IPs announced for this intercept, as they are
     * irrelevant for the purposes of this thread.
     */
    free_all_staticipranges(&(ipint->statics));
    ipint->statics = NULL;

    if (worker->tracker_threads <= 1) {
        ipint->common.seqtrackerid = 0;
    } else {
        ipint->common.seqtrackerid = hash_liid(ipint->common.liid) %
                worker->tracker_threads;
    }

    add_intercept_to_user_intercept_list(&worker->userintercepts, ipint);
    HASH_ADD_KEYPTR(hh_liid, worker->ipintercepts, ipint->common.liid,
            ipint->common.liid_len, ipint);
    ipint->awaitingconfirm = 0;
    return 1;
}

static void update_modified_gtp_intercept(openli_gtp_worker_t *worker,
        ipintercept_t *found, ipintercept_t *ipint) {

    int changed = 0;

    if (ipint->accesstype != INTERNET_ACCESS_TYPE_MOBILE) {
        /* Intercept has changed to be NOT mobile, so just remove it */
        remove_intercept_from_user_intercept_list(&worker->userintercepts,
                found);
        HASH_DELETE(hh_liid, worker->ipintercepts, found);
        free_single_ipintercept(ipint);
        free_single_ipintercept(found);
        return;
    }

    update_modified_intercept_common(&(found->common), &(ipint->common),
            OPENLI_INTERCEPT_TYPE_IP, &changed);
    if (strcmp(ipint->username, found->username) != 0 ||
            ipint->mobileident != found->mobileident) {
        remove_intercept_from_user_intercept_list(&worker->userintercepts,
                found);
        free(found->username);
        found->username = ipint->username;
        found->username_len = ipint->username_len;
        found->mobileident = ipint->mobileident;
        ipint->username = NULL;
        add_intercept_to_user_intercept_list(&worker->userintercepts,
                found);

        push_existing_ip_sessions(worker, found);
    }
    found->awaitingconfirm = 0;
    free_single_ipintercept(ipint);
}

static int add_new_gtp_intercept(openli_gtp_worker_t *worker,
        provisioner_msg_t *msg) {

    ipintercept_t *ipint, *found;
    int ret = 0;

    ipint = calloc(1, sizeof(ipintercept_t));
    if (decode_ipintercept_start(msg->msgbody, msg->msglen, ipint) < 0) {
        logger(LOG_INFO, "OpenLI: GTP worker %d failed to decode mobile IP intercept start message from provisioner", worker->workerid);
        return -1;
    }

    HASH_FIND(hh_liid, worker->ipintercepts, ipint->common.liid,
            ipint->common.liid_len, found);

    if (found) {
        update_modified_gtp_intercept(worker, found, ipint);
        found->awaitingconfirm = 0;
        ret = 0;
    } else {
        ret = init_gtp_intercept(worker, ipint);
    }
    return ret;
}

static int modify_gtp_intercept(openli_gtp_worker_t *worker,
        provisioner_msg_t *msg) {
    ipintercept_t *ipint, *found;

    ipint = calloc(1, sizeof(ipintercept_t));
    if (decode_ipintercept_modify(msg->msgbody, msg->msglen, ipint) < 0) {
        logger(LOG_INFO, "OpenLI: GTP worker %d failed to decode mobile IP intercept modify message from provisioner", worker->workerid);
        return -1;
    }

    HASH_FIND(hh_liid, worker->ipintercepts, ipint->common.liid,
            ipint->common.liid_len, found);
    if (!found) {
        return init_gtp_intercept(worker, ipint);
    } else {
        update_modified_gtp_intercept(worker, found, ipint);
    }
    return 0;
}

static int halt_gtp_intercept(openli_gtp_worker_t *worker,
        provisioner_msg_t *msg) {
    ipintercept_t *ipint, *found;

    ipint = calloc(1, sizeof(ipintercept_t));
    if (decode_ipintercept_halt(msg->msgbody, msg->msglen, ipint) < 0) {
        logger(LOG_INFO, "OpenLI: GTP worker %d failed to decode mobile IP intercept halt message from provisioner", worker->workerid);
        return -1;
    }

    HASH_FIND(hh_liid, worker->ipintercepts, ipint->common.liid,
            ipint->common.liid_len, found);
    if (found) {
        remove_gtp_intercept(worker, found);
    }
    free_single_ipintercept(ipint);
    return 0;
}

static int gtp_worker_handle_provisioner_message(openli_gtp_worker_t *worker,
        openli_export_recv_t *msg) {

    int ret = 0;
    switch(msg->data.provmsg.msgtype) {
        case OPENLI_PROTO_NOMORE_INTERCEPTS:
            disable_unconfirmed_gtp_intercepts(worker);
            break;
        case OPENLI_PROTO_DISCONNECT:
            flag_gtp_intercepts(worker->ipintercepts);
            break;
        case OPENLI_PROTO_START_IPINTERCEPT:
            ret = add_new_gtp_intercept(worker, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_HALT_IPINTERCEPT:
            ret = halt_gtp_intercept(worker, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_MODIFY_IPINTERCEPT:
            ret = modify_gtp_intercept(worker, &(msg->data.provmsg));
            break;
        default:
            logger(LOG_INFO, "OpenLI: GTP worker thread %d received unexpected message type from provisioner: %u",
                    worker->workerid, msg->data.provmsg.msgtype);
            ret = -1;
    }

    if (msg->data.provmsg.msgbody) {
        free(msg->data.provmsg.msgbody);
    }
    return ret;
}

static int gtp_worker_process_sync_thread_message(openli_gtp_worker_t *worker) {

    openli_export_recv_t *msg;
    int x;

    do {
        x = zmq_recv(worker->zmq_ii_sock, &msg, sizeof(msg), ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error while receiving II in GTP thread %d: %s",
                    worker->workerid, strerror(errno));
            return -1;
        }

        if (x <= 0) {
            break;
        }

        if (msg->type == OPENLI_EXPORT_HALT) {
            free(msg);
            return -1;
        }

        if (msg->type == OPENLI_EXPORT_PROVISIONER_MESSAGE) {
            if (gtp_worker_handle_provisioner_message(worker, msg) < 0) {
                free(msg);
                return -1;
            }
        }

        free(msg);
    } while (x > 0);

    return 1;
}

static inline internet_user_t *lookup_gtp_userid(openli_gtp_worker_t *worker,
        user_identity_t *userid) {

    internet_user_t *iuser;

    iuser = lookup_user_by_identity(worker->allusers, userid);

    if (iuser == NULL) {
        iuser = (internet_user_t *)malloc(sizeof(internet_user_t));
        if (!iuser) {
            logger(LOG_INFO,
                    "OpenLI: unable to allocate memory for new Internet user in GTP worker %d",
                    worker->workerid);
            return NULL;
        }
        iuser->userid = NULL;
        iuser->sessions = NULL;

        add_userid_to_allusers_map(&(worker->allusers), iuser, userid);
    }
    return iuser;
}

static void push_gtp_session_over(openli_gtp_worker_t *worker,
        user_intercept_list_t *userint, access_session_t *sess) {

    ipintercept_t *ipint, *tmp;
    sync_sendq_t *sendq, *tmpq, *queues;

    queues = (sync_sendq_t *)worker->collector_queues;

    if (userint == NULL || sess == NULL ) {
        return;
    }

    /* For each intercept associated with this user identity, tell
     * all of the collector threads to stop intercepting traffic for
     * the IP address(es) that belongs to that session.
     */
    HASH_ITER(hh_user, userint->intlist, ipint, tmp) {
        HASH_ITER(hh, queues, sendq, tmpq) {
            push_session_update_to_collector_queue(sendq->q, ipint, sess,
                    OPENLI_PUSH_HALT_IPINTERCEPT);
        }
    }
}

static void add_teid_to_session_mapping(openli_gtp_worker_t *worker,
        access_session_t *sess, uint32_t teid, internet_user_t *iuser) {

    teid_to_session_t *found;
    char keystr[1024];

    memset(keystr, 0, 1024);

    if (teid == 0) {
        logger(LOG_INFO, "OpenLI: called add_teid_to_session_mapping() but the assigned TEID is zero for the session?");
        return;
    }
    snprintf(keystr, 1024, "%s-%u", sess->gtp_tunnel_endpoints, teid);

    //printf("TEID ID: %s\n", keystr);

    HASH_FIND(hh, worker->all_data_teids, keystr, strlen(keystr), found);
    if (found && found->cin == sess->cin) {
        found->session = realloc(found->session,
                (found->sessioncount + 1) * sizeof(access_session_t *));
        found->owner = realloc(found->owner,
                (found->sessioncount + 1) * sizeof(internet_user_t *));
        found->session[found->sessioncount] = sess;
        found->owner[found->sessioncount] = iuser;
        found->sessioncount ++;
        return;
    } else if (found) {
        /* a silent log-off scenario? XXX do we need to generate an IRI? */

        /* For now, just delete the old entry and fall through... */
        HASH_DELETE(hh, worker->all_data_teids, found);
        free(found->idstring);
        free(found->session);
        free(found->owner);
        free(found);
    }

    found = calloc(1, sizeof(teid_to_session_t));
    found->idstring = strdup(keystr);
    found->teid = teid;
    found->cin = sess->cin;
    found->sessioncount = 1;
    found->session = calloc(1, sizeof(access_session_t *));
    found->owner = calloc(1, sizeof(internet_user_t *));
    found->session[0] = sess;
    found->owner[0] = iuser;

    HASH_ADD_KEYPTR(hh, worker->all_data_teids, &(found->teid),
            sizeof(found->teid), found);
}

static void remove_teid_to_session_mapping(openli_gtp_worker_t *worker,
        access_session_t *sess, uint32_t teid) {

    teid_to_session_t *found;
    int nullsess = 0, i;
    char keystr[1024];

    if (!sess->teids_mapped) {
        return;
    }
    snprintf(keystr, 1024, "%s-%u", sess->gtp_tunnel_endpoints, teid);
    //printf("DELETING %s\n", keystr);

    HASH_FIND(hh, worker->all_data_teids, keystr, strlen(keystr), found);
    if (!found) {
        /* Weird, but ok we'll just ignore this */
        return;
    }

    for (i = 0; i < found->sessioncount; i++) {
        if (found->session[i] == NULL) {
            nullsess ++;
            continue;
        }
        if (found->session[i] == sess) {
            found->session[i] = NULL;
            found->owner[i] = NULL;
            nullsess ++;
        }
    }
    if (nullsess == found->sessioncount) {
        /* All sessions relating to this TEID have been removed, so
         * free the entire object
         */
        HASH_DELETE(hh, worker->all_data_teids, found);
        free(found->idstring);
        free(found->session);
        free(found->owner);
        free(found);
    }

}

static void newly_active_gtp_session(openli_gtp_worker_t *worker,
        user_intercept_list_t *userint, access_session_t *sess,
        internet_user_t *iuser) {

    ipintercept_t *ipint, *tmp;
    sync_sendq_t *sendq, *tmpq;

    if (userint == NULL || sess == NULL) {
        return;
    }

    /* Save the Data TEIDs for this session as we have to now
     * intercept GTP-U for those TEIDs from now on -- TODO
     */
    if (sess->identifier_type & OPENLI_ACCESS_SESSION_TEID) {
        add_teid_to_session_mapping(worker, sess, sess->teids[0], iuser);
        add_teid_to_session_mapping(worker, sess, sess->teids[1], iuser);
        sess->teids_mapped = 1;
    }

    if (sess->sessipcount == 0) {
        return;
    }

    /* Tell the collector threads about any IPs associated with this
     * newly active session.
     */
    HASH_ITER(hh_user, userint->intlist, ipint, tmp) {
        HASH_ITER(hh, (sync_sendq_t *)(worker->collector_queues), sendq,
                tmpq) {
            push_session_ips_to_collector_queue(sendq->q, ipint, sess);
        }
    }

}

static void export_raw_gtp_c_packet_content(openli_gtp_worker_t *worker UNUSED,
        ipintercept_t *ipint UNUSED, void *parseddata UNUSED,
        uint32_t seqno UNUSED, uint32_t cin UNUSED) {

    /* Generate a RAW IRI encoding job for each GTP-C packet that contributed
     * to the current GTP "action", so that pcapdisk intercepts can
     * write them into the pcap file nicely */

    /* TODO */

}

static void create_iri_from_gtp_action(openli_gtp_worker_t *worker,
        ipintercept_t *ipint, access_session_t *sess, void *parseddata) {

    struct timeval now;
    access_plugin_t *p = worker->gtpplugin;
    openli_export_recv_t *irimsg;
    int tracker = ipint->common.seqtrackerid;
    int ret;

    if (ipint->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_CCONLY) {
        return;
    }

    gettimeofday(&now, NULL);
    if (!INTERCEPT_IS_ACTIVE(ipint, now)) {
        return;
    }

    irimsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    irimsg->destid = ipint->common.destid;
    irimsg->data.mobiri.liid = strdup(ipint->common.liid);
    irimsg->data.mobiri.cin = sess->cin;
    irimsg->data.mobiri.iritype = ETSILI_IRI_NONE;
    irimsg->data.mobiri.customparams = NULL;

    if (gtp_get_parsed_version(parseddata) == 1) {
        irimsg->type = OPENLI_EXPORT_UMTSIRI;
    } else {
        irimsg->type = OPENLI_EXPORT_EPSIRI;
    }

    ret = p->generate_iri_data(p, parseddata,
            &(irimsg->data.mobiri.customparams),
            &(irimsg->data.mobiri.iritype), worker->freegenerics, 0);
    if (ret == -1) {
        logger(LOG_INFO,
                "OpenLI: error while creating IRI from GTP session state change for %s (worker=%d)", irimsg->data.mobiri.liid, worker->workerid);
        free(irimsg->data.mobiri.liid);
        free(irimsg);
        return;
    }

    if (irimsg->data.mobiri.iritype == ETSILI_IRI_NONE) {
        free(irimsg->data.mobiri.liid);
        free(irimsg);
        return;
    }
    pthread_mutex_lock(worker->stats_mutex);
    worker->stats->mobiri_created ++;
    pthread_mutex_unlock(worker->stats_mutex);
    publish_openli_msg(worker->zmq_pubsocks[tracker], irimsg);
}

static void generate_encoding_jobs(openli_gtp_worker_t *worker,
        user_intercept_list_t *userint, access_session_t *sess,
        void *parseddata, access_action_t action) {

    ipintercept_t *ipint, *tmp;
    access_plugin_t *p = worker->gtpplugin;

    if (userint == NULL) {
        return;
    }

    HASH_ITER(hh_user, userint->intlist, ipint, tmp) {
        if (ipint->common.targetagency == NULL ||
                strcmp(ipint->common.targetagency, "pcapdisk") == 0) {
            uint32_t seqno;
            seqno = p->get_packet_sequence(p, parseddata);

            export_raw_gtp_c_packet_content(worker, ipint, parseddata,
                    seqno, sess->cin);
        } else if (action != ACCESS_ACTION_NONE) {
            create_iri_from_gtp_action(worker, ipint, sess, parseddata);
        }
    }
}

static void process_gtp_u_packet(openli_gtp_worker_t *worker UNUSED,
        libtrace_packet_t *packet, uint8_t *payload UNUSED,
        uint32_t plen UNUSED, uint32_t teid) {

    void *l3;
    uint16_t ethertype;
    uint32_t rem;

    char keystr[1024];

    l3 = trace_get_layer3(packet, &ethertype, &rem);
    if (l3 == NULL || rem < sizeof(libtrace_ip_t)) {
        return;
    }
    if (ethertype == TRACE_ETHERTYPE_IP) {
        libtrace_ip_t *ip = (libtrace_ip_t *)l3;

        if (ip->ip_src.s_addr < ip->ip_dst.s_addr) {
            snprintf(keystr, 1024, "%u-%u-%u", ip->ip_src.s_addr,
                    ip->ip_dst.s_addr, teid);
        } else {
            snprintf(keystr, 1024, "%u-%u-%u", ip->ip_dst.s_addr,
                    ip->ip_src.s_addr, teid);
        }
    } else if (ethertype == TRACE_ETHERTYPE_IPV6) {
        libtrace_ip6_t *ip6 = (libtrace_ip6_t *)l3;
        if (rem < sizeof(libtrace_ip6_t)) {
            return;
        }
        if (memcmp(&(ip6->ip_src.s6_addr), &(ip6->ip_dst.s6_addr), 16) < 0) {
            snprintf(keystr, 1024, "%lu-%lu-%lu-%lu-%u",
                    *(uint64_t *)(&(ip6->ip_src.s6_addr)),
                    *(uint64_t *)(&(ip6->ip_src.s6_addr[8])),
                    *(uint64_t *)(&(ip6->ip_dst.s6_addr)),
                    *(uint64_t *)(&(ip6->ip_dst.s6_addr[8])),
                    teid);
        } else {
            snprintf(keystr, 1024, "%lu-%lu-%lu-%lu-%u",
                    *(uint64_t *)(&(ip6->ip_dst.s6_addr)),
                    *(uint64_t *)(&(ip6->ip_dst.s6_addr[8])),
                    *(uint64_t *)(&(ip6->ip_src.s6_addr)),
                    *(uint64_t *)(&(ip6->ip_src.s6_addr[8])),
                    teid);
        }
    } else {
        return;
    }

    //printf("GTP-U: lookup for %s\n", keystr);

}

static void process_gtp_c_packet(openli_gtp_worker_t *worker,
        libtrace_packet_t *packet) {

    access_plugin_t *p = worker->gtpplugin;
    void *parseddata;
    user_identity_t *identities = NULL;
    int useridcnt = 0, i;
    internet_user_t *iuser;
    access_session_t *sess = NULL;
    session_state_t oldstate, newstate;
    access_action_t accessaction;
    user_intercept_list_t *userint;

    parseddata = p->process_packet(p, packet);
    if (parseddata == NULL) {
        logger(LOG_INFO,
                "OpenLI: GTP worker %d was unable to parse GTP-C packet",
                worker->workerid);
        pthread_mutex_lock(worker->stats_mutex);
        worker->stats->bad_ip_session_packets ++;
        pthread_mutex_unlock(worker->stats_mutex);
        return;
    }

    identities = p->get_userid(p, parseddata, &useridcnt);
    if (identities == NULL) {
        goto end_gtpc_processing;
    }

    oldstate = SESSION_STATE_NEW;
    newstate = SESSION_STATE_NEW;

    for (i = 0; i < useridcnt; i++) {
        iuser = lookup_gtp_userid(worker, &identities[i]);

        if (iuser == NULL) {
            break;
        }
        sess = p->update_session_state(p, parseddata, identities[i].plugindata,
                &(iuser->sessions), &oldstate, &newstate, &accessaction);
        if (sess == NULL) {
            /* Unable to match packet to a session, ignore it */
            continue;
        }

        HASH_FIND(hh, worker->userintercepts, iuser->userid,
                strlen(iuser->userid), userint);

        if (oldstate != newstate) {
            if (newstate == SESSION_STATE_ACTIVE) {
                newly_active_gtp_session(worker, userint, sess, iuser);

            } else if (newstate == SESSION_STATE_OVER) {
                push_gtp_session_over(worker, userint, sess);
                remove_teid_to_session_mapping(worker, sess, sess->teids[0]);
                remove_teid_to_session_mapping(worker, sess, sess->teids[1]);
            }
        }

        generate_encoding_jobs(worker, userint, sess, parseddata, accessaction);

        if (oldstate != newstate && newstate == SESSION_STATE_OVER) {
            /* TODO remove data TEID from list of intercepted TEIDs */
            HASH_DELETE(hh, iuser->sessions, sess);
            free_single_session(sess);
        }
    }

end_gtpc_processing:
    if (parseddata) {
        p->destroy_parsed_data(p, parseddata);
    }

    if (identities) {
        for (i = 0; i < useridcnt; i++) {
            if (identities[i].idstr) {
                free(identities[i].idstr);
            }
        }
        free(identities);
    }

}

static void process_gtp_packet(openli_gtp_worker_t *worker,
        libtrace_packet_t *packet) {
    uint8_t *payload;
    uint32_t plen;
    uint8_t proto;
    uint32_t rem;
    void *transport;
    uint8_t msgtype;
    uint32_t teid;

    if (packet == NULL) {
        return;
    }

    transport = trace_get_transport(packet, &proto, &rem);
    if (transport == NULL || rem == 0) {
        return;
    }

    plen = trace_get_payload_length(packet);
    if (proto != TRACE_IPPROTO_UDP) {
        /* should be UDP only */
        return;
    }
    payload = (uint8_t *)trace_get_payload_from_udp((libtrace_udp_t *)transport,
            &rem);
    if (rem < plen) {
        plen = rem;
    }

    if (((*payload) & 0xe8) == 0x48) {
        /* GTPv2 */
        gtpv2_header_teid_t *v2hdr = (gtpv2_header_teid_t *)payload;

        if (plen <= sizeof(gtpv2_header_teid_t)) {
            return;
        }

        msgtype = v2hdr->msgtype;
        teid = v2hdr->teid;
        payload += sizeof(gtpv2_header_teid_t);
        plen -= sizeof(gtpv2_header_teid_t);

    } else if (((*payload) & 0xe0) == 0x20) {
        /* GTPv1 */
        gtpv1_header_t *v1hdr = (gtpv1_header_t *)payload;

        if (plen <= sizeof(gtpv1_header_t)) {
            return;
        }

        msgtype = v1hdr->msgtype;
        teid = v1hdr->teid;
        payload += sizeof(gtpv1_header_t);
        plen -= sizeof(gtpv1_header_t);
    } else {
        return;
    }

    if (msgtype == 0xff) {
        /* This is GTP-U */
        process_gtp_u_packet(worker, packet, payload, plen, teid);
    } else {
        /* This is GTP-C */
        process_gtp_c_packet(worker, packet);
    }
}

static int gtp_worker_process_packet(openli_gtp_worker_t *worker) {
    openli_state_update_t recvd;
    int rc;

    do {
        rc = zmq_recv(worker->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (rc < 0) {
            if (errno == EAGAIN) {
                return 0;
            }
            logger(LOG_INFO,
                    "OpenLI: error while receiving packet in SMS worker thread %d: %s",
                    worker->workerid, strerror(errno));
            return -1;
        }

        if (recvd.type != OPENLI_UPDATE_GTP) {
            logger(LOG_INFO,
                    "OpenLI: GTP worker thread %d received unexpected update type %u",
                    worker->workerid, recvd.type);
            break;
        }

        process_gtp_packet(worker, recvd.data.pkt);

        if (recvd.data.pkt) {
            trace_destroy_packet(recvd.data.pkt);
        }
    } while (rc > 0);

    return 0;
}

static void gtp_worker_main(openli_gtp_worker_t *worker) {

    zmq_pollitem_t *topoll;
    sync_epoll_t purgetimer;
    struct itimerspec its;
    int x;

    logger(LOG_INFO, "OpenLI: starting GTP worker thread %d",
            worker->workerid);

    topoll = calloc(3, sizeof(zmq_pollitem_t));

    its.it_value.tv_sec = 60;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    purgetimer.fdtype = 0;
    purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(purgetimer.fd, 0, &its, NULL);

    while (1) {
        topoll[0].socket = worker->zmq_ii_sock;
        topoll[0].events = ZMQ_POLLIN;

        topoll[1].socket = worker->zmq_colthread_recvsock;
        topoll[1].events = ZMQ_POLLIN;

        topoll[2].socket = NULL;
        topoll[2].fd = purgetimer.fd;
        topoll[2].events = ZMQ_POLLIN;

        if ((x = zmq_poll(topoll, 3, 50)) < 0) {
            if (errno == EINTR) {
                continue;
            }
            logger(LOG_INFO,
                    "OpenLI: error while polling in GTP worker thread %d: %s",
                    worker->workerid, strerror(errno));
            break;
        }

        if (x == 0) {
            continue;
        }

        if (topoll[0].revents & ZMQ_POLLIN) {
            x = gtp_worker_process_sync_thread_message(worker);
            if (x < 0) {
                break;
            }
            topoll[0].revents = 0;
        }

        if (topoll[1].revents & ZMQ_POLLIN) {
            x = gtp_worker_process_packet(worker);
            if (x < 0) {
                break;
            }
            topoll[1].revents = 0;
        }

        if (topoll[2].revents & ZMQ_POLLIN) {
            topoll[2].revents = 0;
            close(topoll[2].fd);

            /* TODO purge "inactive" sessions */

            purgetimer.fdtype = 0;
            purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
            timerfd_settime(purgetimer.fd, 0, &its, NULL);

            topoll[2].fd = purgetimer.fd;
        }
    }

    free(topoll);
}

void *gtp_thread_begin(void *arg) {
    openli_gtp_worker_t *worker = (openli_gtp_worker_t *)arg;
    char sockname[256];
    int zero = 0, x;
    openli_state_update_t recvd;
    teid_to_session_t *iter, *tmp;

    worker->zmq_pubsocks = calloc(worker->tracker_threads, sizeof(void *));
    init_zmq_socket_array(worker->zmq_pubsocks, worker->tracker_threads,
            "inproc://openlipub", worker->zmq_ctxt);

    worker->zmq_ii_sock = zmq_socket(worker->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openligtpcontrol_sync-%d",
            worker->workerid);

    if (zmq_bind(worker->zmq_ii_sock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: GTP processing thread %d failed to bind to II zmq: %s", worker->workerid, strerror(errno));
        goto haltgtpworker;
    }

    if (zmq_setsockopt(worker->zmq_ii_sock, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
        logger(LOG_INFO, "OpenLI: GTP processing thread %d failed to configure II zmq: %s", worker->workerid, strerror(errno));
        goto haltgtpworker;
    }

    worker->zmq_colthread_recvsock = zmq_socket(worker->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openligtpworker-colrecv%d",
            worker->workerid);

    if (zmq_bind(worker->zmq_colthread_recvsock, sockname) < 0) {
        logger(LOG_INFO, "OpenLI: GTP processing thread %d failed to bind to colthread zmq: %s", worker->workerid, strerror(errno));
        goto haltgtpworker;
    }

    if (zmq_setsockopt(worker->zmq_colthread_recvsock, ZMQ_LINGER, &zero,
           sizeof(zero)) != 0) {
        logger(LOG_INFO, "OpenLI: GTP processing thread %d failed to configure colthread zmq: %s", worker->workerid, strerror(errno));
        goto haltgtpworker;
    }

    gtp_worker_main(worker);

    do {
        x = zmq_recv(worker->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (x > 0) {
            trace_destroy_packet(recvd.data.pkt);
        }
    } while (x > 0);

haltgtpworker:
    logger(LOG_INFO, "OpenLI: halting GTP processing thread %d",
            worker->workerid);

    HASH_ITER(hh, worker->all_data_teids, iter, tmp) {
        HASH_DELETE(hh, worker->all_data_teids, iter);
        free(iter->idstring);
        free(iter->session);
        free(iter->owner);
        free(iter);
    }

    zmq_close(worker->zmq_ii_sock);
    zmq_close(worker->zmq_colthread_recvsock);
    free_all_users(worker->allusers);
    clear_user_intercept_list(worker->userintercepts);
    free_all_ipintercepts(&(worker->ipintercepts));
    clear_zmq_socket_array(worker->zmq_pubsocks, worker->tracker_threads);
    free_etsili_generics(worker->freegenerics);

    if (worker->gtpplugin) {
        destroy_gtp_access_plugin(worker->gtpplugin);
    }

    pthread_exit(NULL);
}

int start_gtp_worker_thread(openli_gtp_worker_t *worker, int id,
        void *globarg) {
    collector_global_t *glob = (collector_global_t *)globarg;
    char name[1024];

    snprintf(name, 1024, "gtpworker-%d", id);

    pthread_mutex_init(&(worker->col_queue_mutex), NULL);

    worker->zmq_ctxt = glob->zmq_ctxt;
    worker->workerid = id;
    worker->stats_mutex = &(glob->stats_mutex);
    worker->stats = &(glob->stats);
    worker->shared = &(glob->sharedinfo);
    worker->zmq_ii_sock = NULL;
    worker->zmq_pubsocks = NULL;
    worker->zmq_colthread_recvsock = NULL;
    worker->collector_queues = NULL;
    worker->tracker_threads = glob->seqtracker_threads;
    worker->ipintercepts = NULL;
    worker->allusers = NULL;
    worker->all_data_teids = NULL;
    worker->userintercepts = NULL;
    worker->gtpplugin = get_gtp_access_plugin();
    worker->freegenerics = create_etsili_generic_freelist(1);

    pthread_create(&(worker->threadid), NULL, gtp_thread_begin,
            (void *)worker);
    pthread_setname_np(worker->threadid, name);

    return 1;
}

