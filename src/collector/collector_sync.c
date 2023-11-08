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


#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libtrace_parallel.h>
#include <assert.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/timerfd.h>

#include "etsili_core.h"
#include "collector.h"
#include "collector_sync.h"
#include "collector_sync_voip.h"
#include "collector_publish.h"
#include "configparser.h"
#include "logger.h"
#include "intercept.h"
#include "netcomms.h"
#include "util.h"
#include "ipmmiri.h"
#include "umtsiri.h"
#include "ipiri.h"

#define INTERCEPT_IS_ACTIVE(cept, now) \
    (cept->common.tostart_time <= now.tv_sec && ( \
        cept->common.toend_time == 0 || cept->common.toend_time > now.tv_sec))

collector_sync_t *init_sync_data(collector_global_t *glob) {

	collector_sync_t *sync = (collector_sync_t *)
			malloc(sizeof(collector_sync_t));
    int i;
    char sockname[128];

    sync->glob = &(glob->syncip);
    sync->intersyncq = &(glob->intersyncq);
    sync->allusers = NULL;
    sync->ipintercepts = NULL;
    sync->knownvoips = NULL;
    sync->userintercepts = NULL;
    sync->coreservers = NULL;
    sync->defaultradiususers = NULL;
    sync->instruct_fd = -1;
    sync->instruct_fail = 0;
    sync->instruct_log = 1;
    sync->instruct_events = ZMQ_POLLIN | ZMQ_POLLOUT;
    sync->hellosreceived = 0;

    sync->outgoing = NULL;
    sync->incoming = NULL;
    sync->info = &(glob->sharedinfo);
    sync->info_mutex = &(glob->config_mutex);

    sync->upcoming_intercept_events = NULL;
    sync->upcomingtimerfd = -1;

    sync->radiusplugin = init_access_plugin(ACCESS_RADIUS);
    sync->gtpplugin = init_access_plugin(ACCESS_GTP);
    sync->freegenerics = glob->syncgenericfreelist;
    sync->activeips = NULL;

    sync->pubsockcount = glob->seqtracker_threads;
    sync->forwardcount = glob->forwarding_threads;
    sync->emailcount = glob->email_threads;

    sync->zmq_pubsocks = calloc(sync->pubsockcount, sizeof(void *));
    sync->zmq_fwdctrlsocks = calloc(sync->forwardcount, sizeof(void *));
    sync->zmq_emailsocks = calloc(sync->emailcount, sizeof(void *));

    sync->ctx = glob->sslconf.ctx;
    sync->ssl = NULL;

    sync->zmq_colsock = zmq_socket(glob->zmq_ctxt, ZMQ_PULL);
    if (zmq_bind(sync->zmq_colsock, "inproc://openli-ipsync") != 0) {
        logger(LOG_INFO, "OpenLI: colsync thread unable to bind to zmq socket for collector updates: %s",
                strerror(errno));
        zmq_close(sync->zmq_colsock);
        sync->zmq_colsock = NULL;
    }

    for (i = 0; i < sync->forwardcount; i++) {
        sync->zmq_fwdctrlsocks[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
        snprintf(sockname, 128, "inproc://openliforwardercontrol_sync-%d", i);
        if (zmq_connect(sync->zmq_fwdctrlsocks[i], sockname) != 0) {
            logger(LOG_INFO, "OpenLI: colsync thread unable to connect to zmq control socket for forwarding threads: %s",
                    strerror(errno));
            zmq_close(sync->zmq_fwdctrlsocks[i]);
            sync->zmq_fwdctrlsocks[i] = NULL;
        }
    }

    for (i = 0; i < sync->emailcount; i++) {
        sync->zmq_emailsocks[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
        snprintf(sockname, 128, "inproc://openliemailcontrol_sync-%d", i);
        if (zmq_connect(sync->zmq_emailsocks[i], sockname) != 0) {
            logger(LOG_INFO, "OpenLI: colsync thread unable to connect to zmq control socket for email threads: %s",
                    strerror(errno));
            zmq_close(sync->zmq_emailsocks[i]);
            sync->zmq_emailsocks[i] = NULL;
        }
    }

    for (i = 0; i < sync->pubsockcount; i++) {
        sync->zmq_pubsocks[i] = zmq_socket(glob->zmq_ctxt, ZMQ_PUSH);
        snprintf(sockname, 128, "inproc://openlipub-%d", i);
        if (zmq_connect(sync->zmq_pubsocks[i], sockname) < 0) {
            logger(LOG_INFO,
                    "OpenLI: colsync thread failed to bind to publishing zmq: %s",
                    strerror(errno));
            zmq_close(sync->zmq_pubsocks[i]);
            sync->zmq_pubsocks[i] = NULL;
        }

        /* Do we need to set a HWM? */
    }

    return sync;

}

static int send_halt_message_over_zmq(void *zmqsock) {
    openli_export_recv_t *haltmsg;
    int zero = 0, ret;

    if (zmqsock == NULL) {
        return 1;
    }

    /* Send a halt message to get the tracker thread to stop */
    haltmsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    haltmsg->type = OPENLI_EXPORT_HALT;
    ret = zmq_send(zmqsock, &haltmsg, sizeof(haltmsg), ZMQ_NOBLOCK);
    if (ret < 0 && errno == EAGAIN) {
        free(haltmsg);
        return 0;
    } else if (ret <= 0) {
        free(haltmsg);
    }

    zmq_setsockopt(zmqsock, ZMQ_LINGER, &zero, sizeof(zero));
    zmq_close(zmqsock);
    return 1;
}

void clean_sync_data(collector_sync_t *sync) {

    int i = 0, zero=0;
    int haltattempts = 0, haltfails = 0;
    ip_to_session_t *iter, *tmp;
    default_radius_user_t *raditer, *radtmp;

	if (sync->instruct_fd != -1) {
		close(sync->instruct_fd);
        sync->instruct_fd = -1;
	}

    HASH_ITER(hh, sync->activeips, iter, tmp) {
        HASH_DELETE(hh, sync->activeips, iter);
        free(iter->session);
        free(iter->owner);
        free(iter);
    }

    HASH_ITER(hh, sync->defaultradiususers, raditer, radtmp) {
        HASH_DELETE(hh, sync->defaultradiususers, raditer);
        if (raditer->name) {
            free(raditer->name);
        }
        free(raditer);
    }

    clear_intercept_time_events(&(sync->upcoming_intercept_events));
    if (sync->upcomingtimerfd != -1) {
        close(sync->upcomingtimerfd);
    }

    free_all_users(sync->allusers);
    clear_user_intercept_list(sync->userintercepts);
    free_all_ipintercepts(&(sync->ipintercepts));
    free_coreserver_list(sync->coreservers);
    free_all_voipintercepts(&(sync->knownvoips));

    if (sync->outgoing) {
        destroy_net_buffer(sync->outgoing, NULL);
    }

    if (sync->incoming) {
        destroy_net_buffer(sync->incoming, NULL);
    }

    if (sync->radiusplugin) {
        destroy_access_plugin(sync->radiusplugin);
    }

    if (sync->gtpplugin) {
        destroy_access_plugin(sync->gtpplugin);
    }

    if(sync->ssl){
        SSL_free(sync->ssl);
    }

    sync->allusers = NULL;
    sync->ipintercepts = NULL;
    sync->knownvoips = NULL;
    sync->defaultradiususers = NULL;
    sync->userintercepts = NULL;
    sync->outgoing = NULL;
    sync->incoming = NULL;
    sync->radiusplugin = NULL;
    sync->gtpplugin = NULL;
    sync->activeips = NULL;

    while (haltattempts < 10) {
        haltfails = 0;

        if (sync->zmq_colsock) {
            int x;
            openli_state_update_t recvd;

            do {
                x = zmq_recv(sync->zmq_colsock, &recvd, sizeof(recvd),
                        ZMQ_DONTWAIT);
                if (x < 0 && errno == EAGAIN) {
                    continue;
                }
                if (x < 0) {
                    break;
                }

                if (recvd.type == OPENLI_UPDATE_RADIUS ||
                        recvd.type == OPENLI_UPDATE_GTP) {
                    trace_destroy_packet(recvd.data.pkt);
                }
            } while (x >= 0);
            zmq_setsockopt(sync->zmq_colsock, ZMQ_LINGER, &zero, sizeof(zero));
            zmq_close(sync->zmq_colsock);
            sync->zmq_colsock = NULL;
        }

        for (i = 0; i < sync->pubsockcount; i++) {
            int r;

            r = send_halt_message_over_zmq(sync->zmq_pubsocks[i]);
            if (r == 0) {
                haltfails ++;
                if (haltattempts < 9) {
                    continue;
                }
            }
            sync->zmq_pubsocks[i] = NULL;
        }

        for (i = 0; i < sync->forwardcount; i++) {
            int r;

            r = send_halt_message_over_zmq(sync->zmq_fwdctrlsocks[i]);
            if (r == 0) {
                haltfails ++;
                if (haltattempts < 9) {
                    i--;
                    continue;
                }
            }
            sync->zmq_fwdctrlsocks[i] = NULL;
        }

        for (i = 0; i < sync->emailcount; i++) {
            int r;

            r = send_halt_message_over_zmq(sync->zmq_emailsocks[i]);
            if (r == 0) {
                haltfails ++;
                if (haltattempts < 9) {
                    i--;
                    continue;
                }
            }
            sync->zmq_emailsocks[i] = NULL;
        }

        if (haltfails == 0) {
            break;
        }
        haltattempts ++;
        usleep(250000);
    }

    free(sync->zmq_emailsocks);
    free(sync->zmq_pubsocks);
    free(sync->zmq_fwdctrlsocks);

}

static int forward_provmsg_to_email_workers(collector_sync_t *sync,
        uint8_t *provmsg, uint16_t msglen, openli_proto_msgtype_t msgtype) {

    openli_export_recv_t *topush;
    int i, ret, errcount = 0;

    for (i = 0; i < sync->emailcount; i++) {
        topush = (openli_export_recv_t *)calloc(1,
                sizeof(openli_export_recv_t));

        topush->type = OPENLI_EXPORT_PROVISIONER_MESSAGE;
        topush->data.provmsg.msgtype = msgtype;
        topush->data.provmsg.msgbody = (uint8_t *)malloc(msglen);
        memcpy(topush->data.provmsg.msgbody, provmsg, msglen);
        topush->data.provmsg.msglen = msglen;

        ret = zmq_send(sync->zmq_emailsocks[i], &topush, sizeof(topush), 0);
        if (ret < 0) {
            logger(LOG_INFO, "Unable to forward provisioner message to email worker %d: %s", i, strerror(errno));

            free(topush->data.provmsg.msgbody);
            free(topush);

            errcount ++;
            continue;
        }
    }

    return 1;

}

static int forward_provmsg_to_voipsync(collector_sync_t *sync,
        uint8_t *provmsg, uint16_t msglen, openli_proto_msgtype_t msgtype) {

    openli_intersync_msg_t topush;

    topush.msgtype = msgtype;
    topush.msgbody = (uint8_t *)malloc(msglen);
    memcpy(topush.msgbody, provmsg, msglen);
    topush.msglen = msglen;

    libtrace_message_queue_put(sync->intersyncq, &topush);
    return 1;

}

static inline void push_coreserver_msg(collector_sync_t *sync,
        coreserver_t *cs, uint8_t msgtype) {

    sync_sendq_t *sendq, *tmp;
    pthread_mutex_lock(&(sync->glob->mutex));
    HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues), sendq, tmp) {
        openli_pushed_t msg;

        memset(&msg, 0, sizeof(openli_pushed_t));
        msg.type = msgtype;
        msg.data.coreserver = deep_copy_coreserver(cs);
        libtrace_message_queue_put(sendq->q, (void *)(&msg));
    }
    pthread_mutex_unlock(&(sync->glob->mutex));
}

void sync_thread_publish_reload(collector_sync_t *sync) {

    int i;
    openli_export_recv_t *expmsg;

    for (i = 0; i < sync->pubsockcount; i++) {
        expmsg = (openli_export_recv_t *)calloc(1,
                sizeof(openli_export_recv_t));
        expmsg->type = OPENLI_EXPORT_RECONFIGURE_INTERCEPTS;
        expmsg->data.packet = NULL;

        publish_openli_msg(sync->zmq_pubsocks[i], expmsg);
    }
    forward_provmsg_to_voipsync(sync, NULL, 0, OPENLI_PROTO_CONFIG_RELOADED);
}

static int export_raw_sync_packet_content(access_plugin_t *p,
        collector_sync_t *sync, ipintercept_t *ipint, void *parseddata,
        uint32_t seqno, uint32_t cin) {

    openli_export_recv_t *msg;
    uint8_t *ipptr = NULL;
    uint16_t iplen;
    struct timeval tv;
    openli_pcap_header_t *pcap;

    int iteration = 0;

    do {
        ipptr = p->get_ip_contents(p, parseddata, &iplen, iteration);

        if (!ipptr) {
            break;
        }

        msg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
        msg->type = OPENLI_EXPORT_RAW_SYNC;
        msg->destid = ipint->common.destid;
        msg->data.rawip.liid = strdup(ipint->common.liid);

        msg->data.rawip.ipcontent = malloc(iplen +
                sizeof(openli_pcap_header_t));
        memcpy(msg->data.rawip.ipcontent + sizeof(openli_pcap_header_t), ipptr,
                iplen);
        msg->data.rawip.ipclen = iplen + sizeof(openli_pcap_header_t);
        msg->data.rawip.seqno = seqno;
        msg->data.rawip.cin = cin;

        /* XXX should probably add a plugin callback to get the timestamp
         * for the packet, but since this code path is GTP specific and I'm
         * planning to rewrite GTP handling soon, I'll just use 'now' as
         * a substitute in the meantime.
         */
        gettimeofday(&tv, NULL);
        pcap = (openli_pcap_header_t *)msg->data.rawip.ipcontent;
        pcap->ts_sec = tv.tv_sec;
        pcap->ts_usec = tv.tv_usec;
        pcap->wirelen = iplen;
        pcap->caplen = iplen;
        iteration ++;

        publish_openli_msg(sync->zmq_pubsocks[ipint->common.seqtrackerid], msg);
    } while (ipptr);

    return iteration;
}

static int create_iri_from_packet_event(collector_sync_t *sync,
        access_session_t *sess, ipintercept_t *ipint, access_plugin_t *p,
        void *parseddata) {
	struct timeval now;

    if (ipint->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_CCONLY) {
        return 0;
    }

	gettimeofday(&now, NULL);
	if (!INTERCEPT_IS_ACTIVE(ipint, now)) {
		return 0;
	}

    if (ipint->accesstype == INTERNET_ACCESS_TYPE_MOBILE) {
        return create_mobiri_job_from_packet(sync, sess, ipint, p, parseddata);
    }

    return create_ipiri_job_from_packet(sync, sess, ipint, p, parseddata);
}

static int create_iri_from_session(collector_sync_t *sync,
        access_session_t *sess, ipintercept_t *ipint, uint8_t special) {

	struct timeval now;

    if (ipint->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_CCONLY) {
        return 0;
    }

	gettimeofday(&now, NULL);
	if (!INTERCEPT_IS_ACTIVE(ipint, now)) {
		return 0;
	}

    if (ipint->accesstype == INTERNET_ACCESS_TYPE_MOBILE) {
        return create_mobiri_job_from_session(sync, sess, ipint, special);
    }

    return create_ipiri_job_from_session(sync, sess, ipint, special);

}

static void generate_startend_ipiris(collector_sync_t *sync,
		ipintercept_t *ipint, time_t tstamp) {

    int irirequired;
    access_session_t *sess, *tmp2;
    static_ipranges_t *ipr, *tmpr;
    internet_user_t *user;

    if (ipint->common.toend_time <= tstamp && ipint->common.toend_time != 0) {
        irirequired = OPENLI_IPIRI_ENDWHILEACTIVE;
    } else if (ipint->common.tostart_time <= tstamp &&
				ipint->common.tostart_time != 0) {
        irirequired = OPENLI_IPIRI_STARTWHILEACTIVE;
    } else {
        return;
    }

    HASH_ITER(hh, ipint->statics, ipr, tmpr) {
        create_ipiri_job_from_iprange(sync, ipr, ipint, irirequired);
    }

    HASH_FIND(hh, sync->allusers, ipint->username, ipint->username_len,
            user);

    if (user == NULL) {
        return;
    }

    /* Update all IP sessions for the target */
    HASH_ITER(hh, user->sessions, sess, tmp2) {
        create_iri_from_session(sync, sess, ipint, irirequired);
    }
}


static inline void push_static_iprange_to_collectors(
        libtrace_message_queue_t *q, ipintercept_t *ipint,
        static_ipranges_t *ipr) {

    openli_pushed_t msg;
    staticipsession_t *staticsess = NULL;

    if (ipr->liid == NULL || ipr->rangestr == NULL) {
        return;
    }

    staticsess = create_staticipsession(ipint, ipr->rangestr, ipr->cin);

    memset(&msg, 0, sizeof(openli_pushed_t));
    msg.type = OPENLI_PUSH_IPRANGE;
    msg.data.iprange = staticsess;

    libtrace_message_queue_put(q, (void *)(&msg));

}

static inline void push_static_iprange_modify_to_collectors(
        libtrace_message_queue_t *q, ipintercept_t *ipint,
        static_ipranges_t *ipr) {

    openli_pushed_t msg;
    staticipsession_t *staticsess = NULL;

    if (ipr->liid == NULL || ipr->rangestr == NULL) {
        return;
    }

    staticsess = create_staticipsession(ipint, ipr->rangestr, ipr->cin);
    memset(&msg, 0, sizeof(openli_pushed_t));
    msg.type = OPENLI_PUSH_MODIFY_IPRANGE;
    msg.data.iprange = staticsess;

    libtrace_message_queue_put(q, (void *)(&msg));
}

static inline void push_static_iprange_remove_to_collectors(
        libtrace_message_queue_t *q, ipintercept_t *ipint,
        static_ipranges_t *ipr) {

    openli_pushed_t msg;
    staticipsession_t *staticsess = NULL;

    if (ipr->liid == NULL || ipr->rangestr == NULL) {
        return;
    }

    staticsess = create_staticipsession(ipint, ipr->rangestr, ipr->cin);
    memset(&msg, 0, sizeof(openli_pushed_t));
    msg.type = OPENLI_PUSH_REMOVE_IPRANGE;
    msg.data.iprange = staticsess;

    libtrace_message_queue_put(q, (void *)(&msg));

}

static inline void push_single_ipintercept(collector_sync_t *sync,
        libtrace_message_queue_t *q, ipintercept_t *ipint,
        access_session_t *session) {

    ipsession_t *ipsess;
    openli_pushed_t msg;
    int i;

    for (i = 0; i < session->sessipcount; i++) {

        ipsess = create_ipsession(ipint, session->cin,
            session->sessionips[i].ipfamily,
            (struct sockaddr *)&(session->sessionips[i].assignedip),
            session->sessionips[i].prefixbits);

        if (!ipsess) {
            logger(LOG_INFO,
                    "OpenLI: ran out of memory while creating IP session message.");
            return;
        }
        memset(&msg, 0, sizeof(openli_pushed_t));
        msg.type = OPENLI_PUSH_IPINTERCEPT;
        msg.data.ipsess = ipsess;

        libtrace_message_queue_put(q, (void *)(&msg));
    }
}

static inline void push_single_vendmirrorid(libtrace_message_queue_t *q,
        ipintercept_t *ipint, uint8_t msgtype) {

    vendmirror_intercept_t *jm;
    openli_pushed_t msg;

    if (ipint->vendmirrorid == OPENLI_VENDOR_MIRROR_NONE) {
        return;
    }

    jm = create_vendmirror_intercept(ipint);
    if (!jm) {
        logger(LOG_INFO,
                "OpenLI: ran out of memory while creating JMirror intercept message.");
        return;
    }

    memset(&msg, 0, sizeof(openli_pushed_t));
    msg.type = msgtype;
    msg.data.mirror = jm;

    libtrace_message_queue_put(q, (void *)(&msg));
}

static void push_all_coreservers(coreserver_t *servers,
        libtrace_message_queue_t *q) {

    coreserver_t *cs, *tmp;
    HASH_ITER(hh, servers, cs, tmp) {
        openli_pushed_t msg;

        memset(&msg, 0, sizeof(openli_pushed_t));
        msg.type = OPENLI_PUSH_CORESERVER;
        msg.data.coreserver = deep_copy_coreserver(cs);
        libtrace_message_queue_put(q, (void *)(&msg));
    }
}

static int send_to_provisioner(collector_sync_t *sync) {

    int ret;
    openli_proto_msgtype_t err;

    ret = transmit_net_buffer(sync->outgoing, &err);
    if (ret == -1) {
        /* Something went wrong */
        if (sync->instruct_log) {
            nb_log_transmit_error(err);
            logger(LOG_INFO,
                    "OpenLI: error sending message from collector to provisioner.");
        }
        return -1;
    }

    if (ret == 0) {
        /* Everything has been sent successfully, no more to send right now. */
        sync->instruct_events = ZMQ_POLLIN;
    }

    return 1;
}

static int new_staticiprange(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    static_ipranges_t *ipr, *found;
    ipintercept_t *ipint;
    sync_sendq_t *tmp, *sendq;
	struct timeval now;

    ipr = (static_ipranges_t *)malloc(sizeof(static_ipranges_t));

    if (decode_staticip_announcement(intmsg, msglen, ipr) == -1) {
        if (sync->instruct_log) {
            logger(LOG_INFO,
                    "OpenLI: received invalid static IP range from provisioner.");
        }
        free(ipr);
        return -1;
    }

    HASH_FIND(hh_liid, sync->ipintercepts, ipr->liid, strlen(ipr->liid), ipint);
    if (!ipint) {
        if (sync->instruct_log) {
            logger(LOG_INFO,
                "OpenLI: received static IP range for LIID %s, but this LIID is unknown?",
                ipr->liid);
        }
        free(ipr);
        return -1;
    }

    HASH_FIND(hh, ipint->statics, ipr->rangestr, strlen(ipr->rangestr), found);
    if (found) {
        found->awaitingconfirm = 0;
        free_single_staticiprange(ipr);
        return 1;
    }

    logger(LOG_INFO,
            "OpenLI: intercepting static IP range %s for LIID %s, AuthCC %s",
            ipr->rangestr, ipint->common.liid, ipint->common.authcc);

    /* XXX assumes each range corresponds to a unique session, not
     * necessarily true but probably doesn't matter too much as this is just
     * some informational stat tracking */
    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->ipsessions_added_diff ++;
    sync->glob->stats->ipsessions_added_total ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);

    HASH_ADD_KEYPTR(hh, ipint->statics, ipr->rangestr,
            strlen(ipr->rangestr), ipr);

    if (ipint->common.tomediate != OPENLI_INTERCEPT_OUTPUTS_CCONLY) {
    	gettimeofday(&now, NULL);
	    if (INTERCEPT_IS_ACTIVE(ipint, now)) {
	        create_ipiri_job_from_iprange(sync, ipr, ipint, OPENLI_IPIRI_STARTWHILEACTIVE);
	    }
    }

    HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues),
            sendq, tmp) {
        push_static_iprange_to_collectors(sendq->q, ipint, ipr);
    }

    return 1;
}

static int modify_staticiprange(collector_sync_t *sync, static_ipranges_t *ipr)
{

    static_ipranges_t *found;
    ipintercept_t *ipint;
    sync_sendq_t *tmp, *sendq;


    HASH_FIND(hh_liid, sync->ipintercepts, ipr->liid, strlen(ipr->liid), ipint);
    if (!ipint) {
        if (sync->instruct_log) {
            logger(LOG_INFO,
                "OpenLI: received static IP range to modify for LIID %s, but this LIID is unknown?",
                ipr->liid);
        }
        free(ipr);
        return -1;
    }

    HASH_FIND(hh, ipint->statics, ipr->rangestr, strlen(ipr->rangestr), found);
    if (found) {
        logger(LOG_INFO, "OpenLI: modifying capture of IP prefix %s for LIID %s -- CIN was %u, now %u",
                ipr->rangestr, ipr->liid, found->cin, ipr->cin);
        found->cin = ipr->cin;
        HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues),
                sendq, tmp) {
            push_static_iprange_modify_to_collectors(sendq->q, ipint, found);
        }
    }

    return 1;
}

static int update_staticiprange(collector_sync_t *sync, static_ipranges_t *ipr,
        ipintercept_t *ipint, int irirequired) {

    static_ipranges_t *found;
    sync_sendq_t *tmp, *sendq;

    HASH_FIND(hh, ipint->statics, ipr->rangestr, strlen(ipr->rangestr), found);
    if (found) {
        openli_pushed_t pmsg;
        if (irirequired != -1) {
            create_ipiri_job_from_iprange(sync, found, ipint, irirequired);
        }
        HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues),
                sendq, tmp) {

            memset(&pmsg, 0, sizeof(pmsg));
            pmsg.type = OPENLI_PUSH_UPDATE_IPRANGE_INTERCEPT;
            pmsg.data.iprange = create_staticipsession(ipint, found->rangestr,
                    found->cin);
            libtrace_message_queue_put(sendq->q, &pmsg);
        }
    }
    return 0;
}

static int remove_staticiprange(collector_sync_t *sync, static_ipranges_t *ipr)
{

    static_ipranges_t *found;
    ipintercept_t *ipint;
    sync_sendq_t *tmp, *sendq;


    HASH_FIND(hh_liid, sync->ipintercepts, ipr->liid, strlen(ipr->liid), ipint);
    if (!ipint) {
        if (sync->instruct_log) {
            logger(LOG_INFO,
                "OpenLI: received static IP range to remove for LIID %s, but this LIID is unknown?",
                ipr->liid);
        }
        free(ipr);
        return -1;
    }

    HASH_FIND(hh, ipint->statics, ipr->rangestr, strlen(ipr->rangestr), found);
    if (found) {
        create_ipiri_job_from_iprange(sync, found, ipint,
                OPENLI_IPIRI_ENDWHILEACTIVE);
        HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues),
                sendq, tmp) {
            push_static_iprange_remove_to_collectors(sendq->q, ipint, ipr);
        }

        logger(LOG_INFO, "OpenLI: removing capture of IP prefix %s for LIID %s",
                ipr->rangestr, ipr->liid);

        /* XXX assumes each range corresponds to a unique session, not
         * necessarily true but probably doesn't matter too much as this is just
         * some informational stat tracking */
        pthread_mutex_lock(sync->glob->stats_mutex);
        sync->glob->stats->ipsessions_ended_diff ++;
        sync->glob->stats->ipsessions_ended_total ++;
        pthread_mutex_unlock(sync->glob->stats_mutex);
        HASH_DELETE(hh, ipint->statics, found);
        free_single_staticiprange(found);
    }

    return 1;
}

static void update_vendmirror_intercept(collector_sync_t *sync,
        ipintercept_t *ipint, int irirequired) {

    openli_pushed_t pmsg;
    vendmirror_intercept_t *mirror;
    sync_sendq_t *sendq, *tmp;

    HASH_ITER(hh, (sync_sendq_t *)sync->glob->collector_queues, sendq, tmp) {
        mirror = create_vendmirror_intercept(ipint);
        memset(&pmsg, 0, sizeof(openli_pushed_t));
        pmsg.type = OPENLI_PUSH_UPDATE_VENDMIRROR_INTERCEPT;

        pmsg.data.mirror = mirror;
        libtrace_message_queue_put(sendq->q, &pmsg);
    }

    /* TODO create an IRI for this vendmirror intercept, if required */
    /* This requires us to know the CIN, which we currently do not have
     * access to -- just another bit of information we need to get from the
     * collector threads eventually...
     */
}


/* Used to push either OPENLI_PUSH_HALT_IPINTERCEPT or
 * OPENLI_PUSH_UPDATE_IPINTERCEPT to all collector threads.
 */
static void push_session_update_to_threads(void *sendqs,
        access_session_t *sess, ipintercept_t *ipint, int updatetype) {

    sync_sendq_t *sendq, *tmp;
    int i;

    for (i = 0; i < sess->sessipcount; i++) {
        openli_pushed_t pmsg;
        ipsession_t *sessdup;

        HASH_ITER(hh, (sync_sendq_t *)sendqs, sendq, tmp) {
            memset(&pmsg, 0, sizeof(openli_pushed_t));
            pmsg.type = updatetype;
            sessdup = create_ipsession(ipint, sess->cin,
                    sess->sessionips[i].ipfamily,
                    (struct sockaddr *)&(sess->sessionips[i].assignedip),
                    sess->sessionips[i].prefixbits);

            pmsg.data.ipsess = sessdup;
            libtrace_message_queue_put(sendq->q, &pmsg);
        }

    }

}

static inline void push_ipintercept_halt_to_threads(collector_sync_t *sync,
        ipintercept_t *ipint) {

    internet_user_t *user;
    access_session_t *sess, *tmp2;
    static_ipranges_t *ipr, *tmpr;

    logger(LOG_INFO, "OpenLI: collector will stop intercepting traffic for target %s (LIID = %s)", ipint->username, ipint->common.liid);

    /* Remove all static IP ranges for this intercept -- its over */
    HASH_ITER(hh, ipint->statics, ipr, tmpr) {
        remove_staticiprange(sync, ipr);
    }

    HASH_FIND(hh, sync->allusers, ipint->username, ipint->username_len,
            user);

    if (user == NULL) {
        return;
    }

    /* Cancel all IP sessions for the target */
    HASH_ITER(hh, user->sessions, sess, tmp2) {
        /* TODO skip sessions that were never active */

        create_iri_from_session(sync, sess, ipint, OPENLI_IPIRI_ENDWHILEACTIVE);
        push_session_update_to_threads(sync->glob->collector_queues, sess,
                ipint, OPENLI_PUSH_HALT_IPINTERCEPT);
    }

}

static void push_ipintercept_update_to_threads(collector_sync_t *sync,
        ipintercept_t *ipint, ipintercept_t *modified) {

    internet_user_t *user;
    access_session_t *sess, *tmp2;
    static_ipranges_t *ipr, *tmpr;
    struct timeval now;
    int irirequired = -1;
    char *tmp;

    logger(LOG_INFO, "OpenLI: collector is updating intercept for target %s (LIID = %s)", ipint->username, ipint->common.liid);

    /* In cases where a change to start or end time have changed whether
     * an active session is now being intercepted or not, we need to force
     * an appropriate IRI.
     */
    gettimeofday(&now, NULL);

    if (ipint->common.toend_time > now.tv_sec &&
            (modified->common.toend_time > 0 &&
             modified->common.toend_time <= now.tv_sec) &&
            ipint->common.tostart_time < now.tv_sec) {
        /* End time has been brought forward and intercept is now inactive */
        irirequired = OPENLI_IPIRI_ENDWHILEACTIVE;
    } else if (ipint->common.tostart_time >= now.tv_sec &&
            modified->common.tostart_time < now.tv_sec &&
            (modified->common.toend_time == 0 ||
             modified->common.toend_time > now.tv_sec)) {
        /* Start time has come forward and intercept is now active */
        irirequired = OPENLI_IPIRI_STARTWHILEACTIVE;
    } else if (modified->common.tostart_time < now.tv_sec &&
            ipint->common.tostart_time < now.tv_sec &&
            ipint->common.toend_time != 0 &&
            ipint->common.toend_time <= now.tv_sec &&
            (modified->common.toend_time == 0 ||
             modified->common.toend_time > now.tv_sec)) {
        /* Catch case where an intercept had ended, but has been extended
         * to become active again.
         *
         * XXX can LEAs handle the combination of IRIs that is going to
         * result? does the spec say anything about this?
         */
        irirequired = OPENLI_IPIRI_STARTWHILEACTIVE;
    }

    tmp = ipint->common.authcc;
    ipint->common.authcc = modified->common.authcc;
    ipint->common.authcc_len = modified->common.authcc_len;
    modified->common.authcc = tmp;

    tmp = ipint->common.delivcc;
    ipint->common.delivcc = modified->common.delivcc;
    ipint->common.delivcc_len = modified->common.delivcc_len;
    modified->common.delivcc = tmp;

    tmp = ipint->common.encryptkey;
    ipint->common.encryptkey = modified->common.encryptkey;
    modified->common.encryptkey = tmp;

    ipint->common.tostart_time = modified->common.tostart_time;
    ipint->common.toend_time = modified->common.toend_time;
    ipint->common.tomediate = modified->common.tomediate;
    ipint->common.encrypt = modified->common.encrypt;

    /* Update all static IP ranges for this intercept */
    HASH_ITER(hh, ipint->statics, ipr, tmpr) {
        update_staticiprange(sync, ipr, ipint, irirequired);
    }

    /* If this is a vendmirror intercept, update it */
    if (ipint->vendmirrorid == modified->vendmirrorid) {
        if (ipint->vendmirrorid != OPENLI_VENDOR_MIRROR_NONE) {
            update_vendmirror_intercept(sync, ipint, irirequired);
        }
    }

    HASH_FIND(hh, sync->allusers, ipint->username, ipint->username_len,
            user);

    if (user == NULL) {
        return;
    }

    /* Update all IP sessions for the target */
    HASH_ITER(hh, user->sessions, sess, tmp2) {
        if (irirequired != -1) {
            create_iri_from_session(sync, sess, ipint, irirequired);
        }

        push_session_update_to_threads(sync->glob->collector_queues, sess,
                ipint, OPENLI_PUSH_UPDATE_IPINTERCEPT);
    }

}

static int new_mediator(collector_sync_t *sync, uint8_t *provmsg,
        uint16_t msglen) {

    int i;
    openli_mediator_t med;
    openli_export_recv_t *expmsg;

    if (decode_mediator_announcement(provmsg, msglen, &med) == -1) {
        if (sync->instruct_log) {
            logger(LOG_INFO, "OpenLI: received invalid mediator announcement from provisioner.");
        }
        return -1;
    }

    logger(LOG_INFO, "OpenLI: new mediator announcement for %s:%s",
            med.ipstr, med.portstr);
    for (i = 0; i < sync->forwardcount; i++) {
        expmsg = (openli_export_recv_t *)calloc(1,
                sizeof(openli_export_recv_t));
        expmsg->type = OPENLI_EXPORT_MEDIATOR;
        expmsg->data.med.mediatorid = med.mediatorid;
        expmsg->data.med.ipstr = med.ipstr;
        expmsg->data.med.portstr = med.portstr;

        publish_openli_msg(sync->zmq_fwdctrlsocks[i], expmsg);
    }

    return 1;
}

static int remove_mediator(collector_sync_t *sync, uint8_t *provmsg,
        uint16_t msglen) {

    int i;
    openli_mediator_t med;
    openli_export_recv_t *expmsg;

    if (decode_mediator_withdraw(provmsg, msglen, &med) == -1) {
        if (sync->instruct_log) {
            logger(LOG_INFO, "OpenLI: received invalid mediator withdrawal from provisioner.");
        }
        return -1;
    }

    for (i = 0; i < sync->forwardcount; i++) {
        expmsg = (openli_export_recv_t *)calloc(1,
                sizeof(openli_export_recv_t));
        expmsg->type = OPENLI_EXPORT_DROP_SINGLE_MEDIATOR;
        expmsg->data.med.mediatorid = med.mediatorid;
        expmsg->data.med.ipstr = NULL;
        expmsg->data.med.portstr = NULL;

        publish_openli_msg(sync->zmq_fwdctrlsocks[i], expmsg);
    }

    free(med.ipstr);
    free(med.portstr);
    return 1;
}


static int forward_new_coreserver(collector_sync_t *sync, uint8_t *provmsg,
        uint16_t msglen) {
    coreserver_t *cs, *found;

    cs = (coreserver_t *)calloc(1, sizeof(coreserver_t));

    if (decode_coreserver_announcement(provmsg, msglen, cs) == -1) {
        if (sync->instruct_log) {
            logger(LOG_INFO, "OpenLI: received invalid core server announcement from provisioner.");
        }
        free_single_coreserver(cs);
        return -1;
    }

    HASH_FIND(hh, sync->coreservers, cs->serverkey, strlen(cs->serverkey),
            found);
    if (found) {
        /* Already in the core server list? */
        found->awaitingconfirm = 0;
        free_single_coreserver(cs);
    } else {
        /* New core server, pass on to all collector threads */
        HASH_ADD_KEYPTR(hh, sync->coreservers, cs->serverkey,
                strlen(cs->serverkey), cs);
        push_coreserver_msg(sync, cs, OPENLI_PUSH_CORESERVER);
        logger(LOG_INFO,
                "OpenLI: collector has added %s to its %s core server list.",
                cs->serverkey, coreserver_type_to_string(cs->servertype));
    }
    return 1;
}

static int forward_remove_coreserver(collector_sync_t *sync, uint8_t *provmsg,
        uint16_t msglen) {

    coreserver_t *cs, *found;

    cs = (coreserver_t *)calloc(1, sizeof(coreserver_t));
    if (decode_coreserver_withdraw(provmsg, msglen, cs) == -1) {
        if (sync->instruct_log) {
            logger(LOG_INFO, "OpenLI: received invalid core server withdrawal from provisioner.");
        }
        free_single_coreserver(cs);
        return -1;
    }

    HASH_FIND(hh, sync->coreservers, cs->serverkey, strlen(cs->serverkey),
            found);
    if (!found) {
        if (sync->instruct_log) {
            logger(LOG_INFO, "OpenLI sync: asked to remove %s server %s, but we don't have any record of it?",
                    coreserver_type_to_string(cs->servertype), cs->serverkey);
        }
    } else {
        push_coreserver_msg(sync, cs, OPENLI_PUSH_REMOVE_CORESERVER);
        logger(LOG_INFO,
                "OpenLI: collector has removed %s from its %s core server list.",
                cs->serverkey, coreserver_type_to_string(cs->servertype));
        HASH_DELETE(hh, sync->coreservers, found);
        free_single_coreserver(found);
    }
    free_single_coreserver(cs);
    return 1;
}

static inline openli_export_recv_t *create_intercept_details_msg(
        intercept_common_t *common) {

    openli_export_recv_t *expmsg;
    expmsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    expmsg->type = OPENLI_EXPORT_INTERCEPT_DETAILS;
    expmsg->data.cept.liid = strdup(common->liid);
    expmsg->data.cept.authcc = strdup(common->authcc);
    expmsg->data.cept.delivcc = strdup(common->delivcc);
    expmsg->data.cept.encryptmethod = common->encrypt;
    if (common->encryptkey) {
        expmsg->data.cept.encryptkey = strdup(common->encryptkey);
    } else {
        expmsg->data.cept.encryptkey = NULL;
    }
    expmsg->data.cept.seqtrackerid = common->seqtrackerid;

    return expmsg;
}

static inline void announce_vendormirror_id(collector_sync_t *sync,
        ipintercept_t *ipint) {

    sync_sendq_t *sendq, *tmp;
    logger(LOG_INFO,
            "OpenLI: received IP intercept from provisioner for Vendor Mirrored ID %u (LIID %s, authCC %s, start time %lu, end time %lu), target is %s",
            ipint->vendmirrorid, ipint->common.liid, ipint->common.authcc,
            ipint->common.tostart_time,
            ipint->common.toend_time,
            ipint->username ? ipint->username : "unknown");
    HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues),
            sendq, tmp) {
        push_single_vendmirrorid(sendq->q, ipint,
                OPENLI_PUSH_VENDMIRROR_INTERCEPT);
    }

    /* TODO Do we need to create an IRI-Begin here too? Probably */
    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->ipsessions_added_diff ++;
    sync->glob->stats->ipsessions_added_total ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);
}

static void push_existing_user_sessions(collector_sync_t *sync,
        ipintercept_t *cept) {

    sync_sendq_t *tmp, *sendq;
    internet_user_t *user;

    HASH_FIND(hh, sync->allusers, cept->username, cept->username_len, user);

    if (user) {
        access_session_t *sess, *tmp2;

        HASH_ITER(hh, user->sessions, sess, tmp2) {
            HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues),
                    sendq, tmp) {
                push_single_ipintercept(sync, sendq->q, cept, sess);
            }

            create_iri_from_session(sync, sess, cept,
                    OPENLI_IPIRI_STARTWHILEACTIVE);
        }
    }

}

static int insert_new_ipintercept(collector_sync_t *sync, ipintercept_t *cept) {

    openli_export_recv_t *expmsg;

    if (cept->vendmirrorid != OPENLI_VENDOR_MIRROR_NONE) {

        /* Don't need to wait for a session to start an ALU intercept.
         * The CIN is contained within the packet and only valid
         * interceptable packets should have the intercept ID we're
         * looking for.
         *
         * TODO allow config that will force us to wait for a session
         * instead, i.e. if the vendor is configured to NOT set the session
         * ID in the shim.
         */
        announce_vendormirror_id(sync, cept);
    } else if (cept->username != NULL) {
        logger(LOG_INFO,
                "OpenLI: received IP intercept for target %s from provisioner (LIID %s, authCC %s, start time %lu, end time %lu)",
                cept->username, cept->common.liid, cept->common.authcc,
                cept->common.tostart_time, cept->common.toend_time);
    }

    if (sync->pubsockcount <= 1) {
        cept->common.seqtrackerid = 0;
    } else {
        cept->common.seqtrackerid = hash_liid(cept->common.liid) % sync->pubsockcount;
    }

    HASH_ADD_KEYPTR(hh_liid, sync->ipintercepts, cept->common.liid,
            cept->common.liid_len, cept);

    add_new_intercept_time_event(&(sync->upcoming_intercept_events), cept,
            &(cept->common));

    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->ipintercepts_added_diff ++;
    sync->glob->stats->ipintercepts_added_total ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);

    expmsg = create_intercept_details_msg(&(cept->common));
    publish_openli_msg(sync->zmq_pubsocks[cept->common.seqtrackerid], expmsg);

    if (cept->username) {
        push_existing_user_sessions(sync, cept);
        add_intercept_to_user_intercept_list(&sync->userintercepts, cept);
    }

    return 1;
}

static inline void remove_vendormirror_id(collector_sync_t *sync,
        ipintercept_t *ipint) {

    sync_sendq_t *sendq, *tmp;
    logger(LOG_INFO,
            "OpenLI: removing IP intercept for Vendor Mirrored ID %u (LIID %s, authCC %s), target was %s",
            ipint->vendmirrorid, ipint->common.liid, ipint->common.authcc,
            ipint->username ? ipint->username : "unknown");

    HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues),
            sendq, tmp) {
        push_single_vendmirrorid(sendq->q, ipint,
                OPENLI_PUSH_HALT_VENDMIRROR_INTERCEPT);
    }
    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->ipsessions_ended_diff ++;
    sync->glob->stats->ipsessions_ended_total ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);
}

static void remove_ip_intercept(collector_sync_t *sync, ipintercept_t *ipint) {

    openli_export_recv_t *expmsg;

    if (!ipint) {
        logger(LOG_INFO,
                "OpenLI: received withdrawal for IP intercept %s but it is not present in the sync intercept list?",
                ipint->common.liid);
        return;
    }

    push_ipintercept_halt_to_threads(sync, ipint);
    HASH_DELETE(hh_liid, sync->ipintercepts, ipint);
    if (ipint->username) {
        remove_intercept_from_user_intercept_list(&sync->userintercepts, ipint);
    }
    remove_intercept_time_event(&(sync->upcoming_intercept_events),
            &(ipint->common));

    expmsg = (openli_export_recv_t *)calloc(1, sizeof(openli_export_recv_t));
    expmsg->type = OPENLI_EXPORT_INTERCEPT_OVER;
    expmsg->data.cept.liid = strdup(ipint->common.liid);
    expmsg->data.cept.authcc = strdup(ipint->common.authcc);
    expmsg->data.cept.delivcc = strdup(ipint->common.delivcc);
    expmsg->data.cept.seqtrackerid = ipint->common.seqtrackerid;

    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->ipintercepts_ended_diff ++;
    sync->glob->stats->ipintercepts_ended_total ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);

    if (ipint->vendmirrorid != OPENLI_VENDOR_MIRROR_NONE) {
        remove_vendormirror_id(sync, ipint);
    }
    publish_openli_msg(sync->zmq_pubsocks[ipint->common.seqtrackerid], expmsg);
    free_single_ipintercept(ipint);
}

static int update_modified_intercept(collector_sync_t *sync,
        ipintercept_t *ipint, ipintercept_t *modified) {

    openli_export_recv_t *expmsg;
    int changed = 0;
    int encodingchanged = 0;

    if (strcmp(ipint->username, modified->username) != 0) {
        push_ipintercept_halt_to_threads(sync, ipint);
        remove_intercept_from_user_intercept_list(&sync->userintercepts, ipint);

        free(ipint->username);
        ipint->username = modified->username;
        add_intercept_to_user_intercept_list(&sync->userintercepts, ipint);

        push_existing_user_sessions(sync, ipint);
        logger(LOG_INFO, "OpenLI: IP intercept %s is now using '%s' as the designated target", ipint->common.liid, ipint->username);
    }

    if (ipint->vendmirrorid != modified->vendmirrorid) {
        if (ipint->vendmirrorid != OPENLI_VENDOR_MIRROR_NONE) {
            remove_vendormirror_id(sync, ipint);
        }

        ipint->vendmirrorid = modified->vendmirrorid;
        if (ipint->vendmirrorid != OPENLI_VENDOR_MIRROR_NONE) {
            announce_vendormirror_id(sync, ipint);
        }
    }

    if (ipint->common.tostart_time != modified->common.tostart_time ||
            ipint->common.toend_time != modified->common.toend_time) {
        logger(LOG_INFO,
                "OpenLI: IP intercept %s has changed start / end times -- now %lu, %lu", ipint->common.liid, modified->common.tostart_time, modified->common.toend_time);
        update_intercept_time_event(&(sync->upcoming_intercept_events),
                ipint, &(ipint->common), &(modified->common));
        changed = 1;
    }

    if (ipint->common.tomediate != modified->common.tomediate) {
        char space[1024];
        intercept_mediation_mode_as_string(modified->common.tomediate, space,
                1024);
        logger(LOG_INFO,
                "OpenLI: IP intercept %s has changed mediation mode to: %s",
                ipint->common.liid, space);
        changed = 1;
    }

    if (ipint->common.encrypt != modified->common.encrypt) {
        char space[1024];
        intercept_encryption_mode_as_string(modified->common.encrypt, space,
                1024);
        logger(LOG_INFO,
                "OpenLI: IP intercept %s has changed encryption mode to: %s",
                ipint->common.liid, space);
        changed = 1;
        encodingchanged = 1;
        goto actonchange;
    }

    if (ipint->common.encryptkey && modified->common.encryptkey) {
        if (strcmp(ipint->common.encryptkey, modified->common.encryptkey) != 0)
        {
            changed = 1;
            encodingchanged = 1;
            goto actonchange;
        }
    } else if (ipint->common.encryptkey == NULL && modified->common.encryptkey)
    {
        changed = 1;
        encodingchanged = 1;
        goto actonchange;
    } else if (ipint->common.encryptkey && modified->common.encryptkey == NULL)
    {
        changed = 1;
        encodingchanged = 1;
        goto actonchange;
    }


    if (strcmp(ipint->common.delivcc, modified->common.delivcc) != 0 ||
            strcmp(ipint->common.authcc, modified->common.authcc) != 0) {
        changed = 1;
        encodingchanged = 1;
        goto actonchange;
    }

actonchange:
    if (encodingchanged) {
        expmsg = create_intercept_details_msg(&(modified->common));
        expmsg->type = OPENLI_EXPORT_INTERCEPT_CHANGED;
        publish_openli_msg(sync->zmq_pubsocks[ipint->common.seqtrackerid],
                expmsg);
    }

    if (changed) {
        /* Note: this will replace the values in 'ipint' with the new ones
         * from 'modified' so don't panic that we haven't changed them
         * earlier in this method...
         */
        push_ipintercept_update_to_threads(sync, ipint, modified);
    }

    free_single_ipintercept(modified);
    return 0;
}

static int modify_ipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    ipintercept_t *ipint, *modified;

    modified = calloc(1, sizeof(ipintercept_t));

    if (decode_ipintercept_modify(intmsg, msglen, modified) == -1) {
        if (sync->instruct_log) {
            logger(LOG_INFO,
                    "OpenLI: received invalid IP intercept modification from provisioner.");
        }
        return -1;
    }

    HASH_FIND(hh_liid, sync->ipintercepts, modified->common.liid,
            modified->common.liid_len, ipint);

    if (!ipint) {
        return insert_new_ipintercept(sync, modified);
    }

    return update_modified_intercept(sync, ipint, modified);
}

static int halt_ipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    ipintercept_t *ipint, *torem;

    torem = calloc(1, sizeof(ipintercept_t));

    if (decode_ipintercept_halt(intmsg, msglen, torem) == -1) {
        if (sync->instruct_log) {
            logger(LOG_INFO,
                    "OpenLI: received invalid IP intercept withdrawal from provisioner.");
        }
        free_single_ipintercept(torem);
        return -1;
    }

    HASH_FIND(hh_liid, sync->ipintercepts, torem->common.liid,
            torem->common.liid_len, ipint);

    if (!ipint) {
        logger(LOG_INFO,
                "OpenLI: tried to halt IP intercept %s but this was not present in the intercept map?", torem->common.liid);
        free_single_ipintercept(torem);
        return -1;
    }

    remove_ip_intercept(sync, ipint);
    free_single_ipintercept(torem);
    return 1;
}

void sync_drop_all_mediators(collector_sync_t *sync) {
    openli_export_recv_t *expmsg;
    int i;

    for (i = 0; i < sync->forwardcount; i++) {
        expmsg = (openli_export_recv_t *)calloc(1,
                sizeof(openli_export_recv_t));

        expmsg->type = OPENLI_EXPORT_DROP_ALL_MEDIATORS;
        expmsg->data.packet = NULL;
        publish_openli_msg(sync->zmq_fwdctrlsocks[i], expmsg);
    }
}

void sync_reconnect_all_mediators(collector_sync_t *sync) {
    openli_export_recv_t *expmsg;
    int i;

    for (i = 0; i < sync->forwardcount; i++) {
        expmsg = (openli_export_recv_t *)calloc(1,
                sizeof(openli_export_recv_t));

        expmsg->type = OPENLI_EXPORT_RECONNECT_ALL_MEDIATORS;
        expmsg->data.packet = NULL;
        publish_openli_msg(sync->zmq_fwdctrlsocks[i], expmsg);
    }
}

static int new_default_radius(collector_sync_t *sync, uint8_t *provmsg,
        uint16_t msglen) {

    default_radius_user_t *defrad, *found;

    defrad = (default_radius_user_t *)calloc(1, sizeof(default_radius_user_t));

    if (decode_default_radius_announcement(provmsg, msglen, defrad) == -1) {
        if (sync->instruct_log) {
            logger(LOG_INFO,
                    "OpenLI: received invalid default RADIUS username from provisioner.");
        }
        free(defrad);
        return -1;
    }

    HASH_FIND(hh, sync->defaultradiususers, defrad->name, defrad->namelen,
            found);

    if (found) {
        found->awaitingconfirm = 0;
        free(defrad->name);
        free(defrad);
        return 0;
    }

    HASH_ADD_KEYPTR(hh, sync->defaultradiususers, defrad->name, defrad->namelen,
            defrad);
    logger(LOG_INFO, "OpenLI: added %s to list of default RADIUS usernames.",
            defrad->name);
    return 1;
}

static inline int remove_default_radius(collector_sync_t *sync,
        default_radius_user_t *defrad) {

    if (!defrad) {
        return 0;
    }

    HASH_DELETE(hh, sync->defaultradiususers, defrad);
    logger(LOG_INFO,
            "OpenLI: removed %s from list of default RADIUS usernames.",
            defrad->name);
    free(defrad->name);
    free(defrad);

    return 1;
}

static int withdraw_default_radius(collector_sync_t *sync, uint8_t *provmsg,
        uint16_t msglen) {

    default_radius_user_t defrad, *found;

    if (decode_default_radius_announcement(provmsg, msglen, &defrad) == -1) {
        if (sync->instruct_log) {
            logger(LOG_INFO,
                    "OpenLI: received invalid default RADIUS username from provisioner.");
        }
        return -1;
    }

    if (!defrad.name) {
        return -1;
    }

    HASH_FIND(hh, sync->defaultradiususers, defrad.name, defrad.namelen,
            found);
    if (found) {
        remove_default_radius(sync, found);
    }
    free(defrad.name);

    return 1;
}

static int new_ipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    ipintercept_t *cept, *x;

    cept = (ipintercept_t *)malloc(sizeof(ipintercept_t));
    if (decode_ipintercept_start(intmsg, msglen, cept) == -1) {
        if (sync->instruct_log) {
            logger(LOG_INFO,
                    "OpenLI: received invalid IP intercept from provisioner.");
        }
        free(cept);
        return -1;
    }

    /* Check if we already have this intercept */
    HASH_FIND(hh_liid, sync->ipintercepts, cept->common.liid,
            cept->common.liid_len, x);

    if (x) {
        /* Duplicate LIID */

        /* OpenLI-internal fields that could change value
         * if the provisioner was restarted.
         */
        if (x->username && cept->username) {
            if (strcmp(x->username, cept->username) != 0) {
                logger(LOG_INFO,
                        "OpenLI: duplicate IP ID %s seen, but targets are different (was %s, now %s).",
                        x->common.liid, x->username, cept->username);
            }
        }

        if (cept->vendmirrorid != x->vendmirrorid) {
            logger(LOG_INFO,
                    "OpenLI: duplicate IP ID %s seen, but Vendor Mirroring intercept IDs are different (was %u, now %u).",
                    x->common.liid, x->vendmirrorid, cept->vendmirrorid);
        }

        if (cept->accesstype != x->accesstype) {
            logger(LOG_INFO,
                "OpenLI: duplicate IP ID %s seen, but access type has changed to %s.", x->common.liid, accesstype_to_string(cept->accesstype));
        /* Only affects IRIs so don't need to modify collector threads */
            x->accesstype = cept->accesstype;
        }
        x->awaitingconfirm = 0;
        return update_modified_intercept(sync, x, cept);
    }

    return insert_new_ipintercept(sync, cept);
}

static void disable_unconfirmed_intercepts(collector_sync_t *sync) {
    coreserver_t *cs, *tmp3;
    ipintercept_t *ipint, *tmp;
    static_ipranges_t *ipr, *tmpr;
    default_radius_user_t *defrad, *tmprad;

    HASH_ITER(hh_liid, sync->ipintercepts, ipint, tmp) {

        if (ipint->awaitingconfirm) {

            /* Tell every collector thread to stop intercepting traffic for
             * the IPs associated with this target. */
            remove_ip_intercept(sync, ipint);
        } else {
            /* Deal with any unconfirmed static IP ranges */
            HASH_ITER(hh, ipint->statics, ipr, tmpr) {
                if (ipr->awaitingconfirm) {
                    remove_staticiprange(sync, ipr);
                }
            }
        }
    }

    /* Also remove any unconfirmed core servers */
    HASH_ITER(hh, sync->coreservers, cs, tmp3) {
        if (cs->awaitingconfirm) {
            push_coreserver_msg(sync, cs, OPENLI_PUSH_REMOVE_CORESERVER);
            logger(LOG_INFO,
                    "OpenLI: collector has removed %s from its %s core server list.",
                    cs->serverkey, coreserver_type_to_string(cs->servertype));
            HASH_DELETE(hh, sync->coreservers, cs);
            free_single_coreserver(cs);
        }
    }

    HASH_ITER(hh, sync->defaultradiususers, defrad, tmprad) {
        if (defrad->awaitingconfirm) {
            remove_default_radius(sync, defrad);
        }
    }
}

static int recv_from_provisioner(collector_sync_t *sync) {
    int ret = 0;
    uint8_t *provmsg;
    uint16_t msglen = 0;
    uint64_t intid = 0;
    static_ipranges_t *ipr;
    openli_proto_msgtype_t msgtype;

    do {
        msgtype = receive_net_buffer(sync->incoming, &provmsg, &msglen, &intid);
        if (msgtype < 0) {
            if (sync->instruct_log) {
                nb_log_receive_error(msgtype);
                logger(LOG_INFO, "OpenLI collector: error receiving message from provisioner.");
            }
            return -1;
        }

        switch(msgtype) {
            case OPENLI_PROTO_DISCONNECT:
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_SSL_REQUIRED:
                logger(LOG_INFO, "OpenLI collector: provisioner requested that we connect using SSL. Disconnecting.");
                return -2;
            case OPENLI_PROTO_DISCONNECT_MEDIATORS:
                sync_drop_all_mediators(sync);
                ret = 1;
                break;
            case OPENLI_PROTO_ANNOUNCE_MEDIATOR:
                ret = new_mediator(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_WITHDRAW_MEDIATOR:
                ret = remove_mediator(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_START_IPINTERCEPT:
                ret = new_ipintercept(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_ADD_STATICIPS:
                ret = new_staticiprange(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_MODIFY_STATICIPS:
                ipr = (static_ipranges_t *)malloc(sizeof(static_ipranges_t));

                if (decode_staticip_modify(provmsg, msglen, ipr) == -1) {
                    if (sync->instruct_log) {
                        logger(LOG_INFO,
                            "OpenLI: received invalid static IP range from provisioner for removal.");
                    }
                    free(ipr);
                    return -1;
                }
                ret = modify_staticiprange(sync, ipr);
                if (ret == -1) {
                    return -1;
                }
                free_single_staticiprange(ipr);
                break;
            case OPENLI_PROTO_REMOVE_STATICIPS:
                ipr = (static_ipranges_t *)malloc(sizeof(static_ipranges_t));

                if (decode_staticip_removal(provmsg, msglen, ipr) == -1) {
                    if (sync->instruct_log) {
                        logger(LOG_INFO,
                            "OpenLI: received invalid static IP range from provisioner for removal.");
                    }
                    free(ipr);
                    return -1;
                }
                ret = remove_staticiprange(sync, ipr);
                if (ret == -1) {
                    return -1;
                }
                free_single_staticiprange(ipr);
                break;
            case OPENLI_PROTO_HALT_IPINTERCEPT:
                ret = halt_ipintercept(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_ANNOUNCE_DEFAULT_RADIUS:
                ret = new_default_radius(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_WITHDRAW_DEFAULT_RADIUS:
                ret = withdraw_default_radius(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_ANNOUNCE_CORESERVER:
                ret = forward_new_coreserver(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_WITHDRAW_CORESERVER:
                ret = forward_remove_coreserver(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
                break;

            case OPENLI_PROTO_MODIFY_IPINTERCEPT:
                ret = modify_ipintercept(sync, provmsg, msglen);
                if (ret < 0) {
                    return -1;
                }
                break;

            case OPENLI_PROTO_START_VOIPINTERCEPT:
            case OPENLI_PROTO_HALT_VOIPINTERCEPT:
            case OPENLI_PROTO_MODIFY_VOIPINTERCEPT:
            case OPENLI_PROTO_ANNOUNCE_SIP_TARGET:
            case OPENLI_PROTO_WITHDRAW_SIP_TARGET:
                ret = forward_provmsg_to_voipsync(sync, provmsg, msglen,
                        msgtype);
                if (ret == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_NOMORE_INTERCEPTS:
                disable_unconfirmed_intercepts(sync);
                ret = forward_provmsg_to_voipsync(sync, provmsg, msglen,
                        msgtype);
                if (ret == -1) {
                    return -1;
                }
                ret = forward_provmsg_to_email_workers(sync, provmsg, msglen,
                        msgtype);
                if (ret == -1) {
                    return -1;
                }
                break;

            case OPENLI_PROTO_START_EMAILINTERCEPT:
            case OPENLI_PROTO_HALT_EMAILINTERCEPT:
            case OPENLI_PROTO_MODIFY_EMAILINTERCEPT:
            case OPENLI_PROTO_ANNOUNCE_EMAIL_TARGET:
            case OPENLI_PROTO_WITHDRAW_EMAIL_TARGET:
            case OPENLI_PROTO_ANNOUNCE_DEFAULT_EMAIL_COMPRESSION:
                ret = forward_provmsg_to_email_workers(sync, provmsg, msglen,
                        msgtype);
                if (ret == -1) {
                    return -1;
                }
                break;

            default:
                if (sync->instruct_log) {
                    logger(LOG_INFO, "Received unexpected message of type %d from provisioner.", msgtype);
                    return -1;
                }
        }

    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    if (ret == 1 && sync->instruct_log == 0) {
        logger(LOG_INFO, "Successfully connected to a legit OpenLI provisioner");
        sync->instruct_log = 1;
    }
    if (ret == 1) {
        sync->instruct_fail = 0;
    }

    return 1;
}

int sync_connect_provisioner(collector_sync_t *sync, SSL_CTX *ctx) {

    int sockfd;

    pthread_rwlock_rdlock(sync->info_mutex);
    sockfd = connect_socket(sync->info->provisionerip,
            sync->info->provisionerport, sync->instruct_fail, 0);
    pthread_rwlock_unlock(sync->info_mutex);

    if (sockfd == -1) {
        sync->instruct_log = 0;
        return 0;
    }

    if (sockfd == 0) {
        sync->instruct_fail = 1;
        return 0;
    }

    if (ctx != NULL){
        fd_set_block(sockfd);
        //collector cannt do anything untill it has instructions from provisioner so blocking is fine

        if (sync->ssl) {
            SSL_free(sync->ssl);
        }
        sync->ssl = SSL_new(ctx);
        SSL_set_fd(sync->ssl, sockfd);
        SSL_set_connect_state(sync->ssl); //set client mode
        int errr = SSL_do_handshake(sync->ssl);

        fd_set_nonblock(sockfd);
        if ((errr) <= 0 ){
            if (sync->instruct_fail == 0) {
                logger(LOG_INFO, "OpenLI: SSL handshake to provisioner failed");
            }
            SSL_free(sync->ssl);
            sync->ssl = NULL;
            sync->instruct_fail = 1;
            /* Our SSL configuration is probably bad, so retrying is not going
             * to help?
             */
            return -1;
        }

        logger(LOG_DEBUG, "OpenLI: SSL Handshake to provisioner finished");
    }
    else {
        sync->ssl = NULL;
    }

    sync->instruct_fd = sockfd;

    assert(sync->outgoing == NULL && sync->incoming == NULL);

    sync->outgoing = create_net_buffer(NETBUF_SEND, sync->instruct_fd, sync->ssl);
    sync->incoming = create_net_buffer(NETBUF_RECV, sync->instruct_fd, sync->ssl);

    /* Put our auth message onto the outgoing buffer */
    if (push_auth_onto_net_buffer(sync->outgoing, OPENLI_PROTO_COLLECTOR_AUTH)
            < 0) {
        if (sync->instruct_fail == 0) {
            logger(LOG_INFO,"OpenLI: collector is unable to queue auth message.");
        }
        sync->instruct_fail = 1;
        sync_disconnect_provisioner(sync, 0);
        return 0;
    }
    sync->instruct_events = ZMQ_POLLIN | ZMQ_POLLOUT;
    return 1;
}

static inline void touch_all_coreservers(coreserver_t *servers) {
    coreserver_t *cs, *tmp;

    HASH_ITER(hh, servers, cs, tmp) {
        cs->awaitingconfirm = 1;
    }
}

static inline void touch_all_defaultradius(default_radius_user_t *radusers) {
    default_radius_user_t *def, *tmp;

    HASH_ITER(hh, radusers, def, tmp) {
        def->awaitingconfirm = 1;
    }
}

static inline void touch_all_intercepts(ipintercept_t *intlist) {
    ipintercept_t *ipint, *tmp;
    static_ipranges_t *ipr, *tmpr;

    /* Set all intercepts to be "awaiting confirmation", i.e. if the
     * provisioner doesn't announce them in its initial batch of
     * intercepts then they are to be halted.
     */
    HASH_ITER(hh_liid, intlist, ipint, tmp) {
        ipint->awaitingconfirm = 1;
        HASH_ITER(hh, ipint->statics, ipr, tmpr) {
            ipr->awaitingconfirm = 1;
        }
    }
}

void sync_disconnect_provisioner(collector_sync_t *sync, uint8_t dropmeds) {

    openli_export_recv_t *expmsg;
    int i;

    destroy_net_buffer(sync->outgoing, NULL);
    destroy_net_buffer(sync->incoming, NULL);

    sync->outgoing = NULL;
    sync->incoming = NULL;

    if (sync->instruct_fd != -1) {
        if (sync->instruct_log) {
            logger(LOG_INFO, "OpenLI: collector is disconnecting from provisioner fd %d", sync->instruct_fd);
        }
        close(sync->instruct_fd);
        sync->instruct_fd = -1;
        sync->instruct_log = 0;
    }

    /* Leave all intercepts running, but require them to be confirmed
     * as active when we reconnect to the provisioner.
     */
    touch_all_intercepts(sync->ipintercepts);
    touch_all_coreservers(sync->coreservers);
    touch_all_defaultradius(sync->defaultradiususers);

    /* Tell other sync thread to flag its intercepts too */
    forward_provmsg_to_voipsync(sync, NULL, 0, OPENLI_PROTO_DISCONNECT);
    forward_provmsg_to_email_workers(sync, NULL, 0, OPENLI_PROTO_DISCONNECT);

    /* Same with mediators -- keep exporting to them, but flag them to be
     * disconnected if they are not announced after we reconnect. */
    if (dropmeds) {
        sync_reconnect_all_mediators(sync);
    } else {
        for ( i = 0; i < sync->forwardcount; i++) {
            expmsg = (openli_export_recv_t *)calloc(1,
                    sizeof(openli_export_recv_t));
            expmsg->type = OPENLI_EXPORT_FLAG_MEDIATORS;
            expmsg->data.packet = NULL;

            publish_openli_msg(sync->zmq_fwdctrlsocks[i], expmsg);
        }
    }

}

static void push_all_active_intercepts(collector_sync_t *sync,
        internet_user_t *allusers,
        ipintercept_t *intlist, libtrace_message_queue_t *q) {

    ipintercept_t *orig, *tmp;
    internet_user_t *user;
    access_session_t *sess, *tmp2;
    static_ipranges_t *ipr, *tmpr;

    HASH_ITER(hh_liid, intlist, orig, tmp) {
        /* Do we have a valid user that matches the target username? */
        if (orig->username != NULL) {
            HASH_FIND(hh, allusers, orig->username, orig->username_len, user);
            if (user) {
                HASH_ITER(hh, user->sessions, sess, tmp2) {
                    push_single_ipintercept(sync, q, orig, sess);
                }
            }
        }
        if (orig->vendmirrorid != OPENLI_VENDOR_MIRROR_NONE) {
            push_single_vendmirrorid(q, orig, OPENLI_PUSH_VENDMIRROR_INTERCEPT);
        }
        HASH_ITER(hh, orig->statics, ipr, tmpr) {
            push_static_iprange_to_collectors(q, orig, ipr);
        }
    }
}

static int remove_ip_to_session_mapping(collector_sync_t *sync,
        access_session_t *sess) {

    ip_to_session_t *mapping;
    char ipstr[128];
    int i, j, errs = 0, nullsess = 0;

    for (i = 0; i < sess->sessipcount; i++) {
        nullsess = 0;

        if (sess->sessionips[i].ipfamily == 0) {
            continue;
        }

        HASH_FIND(hh, sync->activeips, &(sess->sessionips[i]),
                sizeof(internetaccess_ip_t), mapping);

        if (!mapping) {
            logger(LOG_INFO,
                "OpenLI: attempt to remove session mapping for IP %s, but the mapping doesn't exist?",
                sockaddr_to_string(
                    (struct sockaddr *)&(sess->sessionips[i].assignedip),
                    ipstr, 128));
            errs ++;
            continue;
        }

        for (j = 0; j < mapping->sessioncount; j++) {
            if (mapping->session[j] == NULL) {
                nullsess ++;
                continue;
            }

            /* should be ok to compare pointers, right? */
            if (mapping->session[j] == sess) {
                mapping->session[j] = NULL;
                mapping->owner[j] = NULL;
                nullsess ++;
            }
        }

        if (nullsess == mapping->sessioncount) {
            /* all sessions relating to this IP have been removed, so we
             * can free the mapping object */
            HASH_DELETE(hh, sync->activeips, mapping);
            free(mapping->session);
            free(mapping->owner);
            free(mapping);
        }
    }
    if (errs == 0) {
        return 0;
    }
    return -1;
}

static inline int report_silent_logoffs(collector_sync_t *sync,
        ip_to_session_t *prev) {

    user_intercept_list_t *prevuser;
    ipintercept_t *ipint, *tmp;
    int i;
    char ipstr[128];

    for (i = 0; i < prev->sessioncount; i++) {

        /* Check for silent-logoff scenario */
        if (prev->owner[i] == NULL || prev->session[i] == NULL) {
            continue;
        }
        HASH_FIND(hh, sync->userintercepts, prev->owner[i]->userid,
                strlen(prev->owner[i]->userid), prevuser);
        if (prevuser) {

            logger(LOG_INFO,
                    "OpenLI: detected silent owner change for IP %s",
                    sockaddr_to_string(
                        (struct sockaddr *)&(prev->ip.assignedip),
                        ipstr, 128));
            HASH_ITER(hh_user, prevuser->intlist, ipint, tmp) {
                create_iri_from_session(sync,
                        prev->session[i],
                        ipint, OPENLI_IPIRI_SILENTLOGOFF);
                push_session_update_to_threads(sync->glob->collector_queues,
                        prev->session[i], ipint, OPENLI_PUSH_HALT_IPINTERCEPT);
            }
        }

        if (remove_session_ip(prev->session[i], &(prev->ip)) == 1) {
            free_single_session(prev->owner[i], prev->session[i]);
        }
    }
    HASH_DELETE(hh, sync->activeips, prev);
    free(prev->session);
    free(prev->owner);
    free(prev);
    return 1;
}

static int add_ip_to_session_mapping(collector_sync_t *sync,
        access_session_t *sess, internet_user_t *iuser) {

    int i, replaced = 0;
    ip_to_session_t *prev;

    prev = NULL;
    ip_to_session_t *newmap;

    if (sess->sessipcount == 0) {
        logger(LOG_INFO, "OpenLI: called add_ip_to_session_mapping() but no IP has been assigned for this session.");
        return -1;
    }

    for (i = 0; i < sess->sessipcount; i++) {
        HASH_FIND(hh, sync->activeips, &(sess->sessionips[i]),
                sizeof(internetaccess_ip_t), prev);

        if (prev && prev->cin == sess->cin) {
            prev->session = realloc(prev->session,
                    (prev->sessioncount + 1) * sizeof(access_session_t *));
            prev->owner = realloc(prev->owner,
                    (prev->sessioncount + 1) * sizeof(internet_user_t *));
            prev->session[prev->sessioncount] = sess;
            prev->owner[prev->sessioncount] = iuser;
            prev->sessioncount ++;
            continue;
        } else if (prev) {
            replaced += report_silent_logoffs(sync, prev);
            /* fall through to replace prev with a new entry */
        }

        newmap = (ip_to_session_t *)malloc(sizeof(ip_to_session_t));
        newmap->ip = sess->sessionips[i];
        newmap->sessioncount = 1;
        newmap->session = calloc(1, sizeof(access_session_t *));
        newmap->owner = calloc(1, sizeof(internet_user_t *));
        newmap->cin = sess->cin;

        newmap->session[0] = sess;
        newmap->owner[0] = iuser;

        HASH_ADD_KEYPTR(hh, sync->activeips, &newmap->ip,
                sizeof(internetaccess_ip_t), newmap);

    }
    return replaced;
}

static inline internet_user_t *lookup_userid(collector_sync_t *sync,
        user_identity_t *userid) {

    internet_user_t *iuser;

    HASH_FIND(hh, sync->allusers, userid->idstr, userid->idlength, iuser);
    if (iuser == NULL) {
        iuser = (internet_user_t *)malloc(sizeof(internet_user_t));

        if (!iuser) {
            logger(LOG_INFO, "OpenLI: unable to allocate memory for new Internet user");
            return NULL;
        }
        iuser->userid = userid->idstr;
        userid->idstr = NULL;
        iuser->sessions = NULL;

        HASH_ADD_KEYPTR(hh, sync->allusers, iuser->userid,
                userid->idlength, iuser);
    }
    return iuser;
}

static inline int identity_match_intercept(ipintercept_t *ipint,
        user_identity_t *uid) {

    /* If the user has specifically said that the intercept target can
     * not be identified using the username, then matching against the
     * username is not allowed */

    if (uid->method == USER_IDENT_RADIUS_USERNAME &&
            ((ipint->options & (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_USER))\
            == 0)) {
        return 0;
    }

    if (uid->method == USER_IDENT_RADIUS_CSID &&
            ((ipint->options & (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_CSID)) == 0)) {
        return 0;
    }

    return 1;
}

static int newly_active_session(collector_sync_t *sync,
        user_intercept_list_t *userint, internet_user_t *iuser,
        access_session_t *sess, user_identity_t *uid) {

    int mapret = 0;
    sync_sendq_t *sendq, *tmpq;
    ipintercept_t *ipint, *tmp;

    if (sess->sessipcount > 0) {
        mapret = add_ip_to_session_mapping(sync, sess, iuser);
        if (mapret < 0) {
            logger(LOG_INFO,
                "OpenLI: error while updating IP->session map in sync thread.");
            return -1;
        }
    }

    if (!userint) {
        return 0;
    }

    /* Session has been confirmed for a target; time to start intercepting
     * packets involving the session IP.
     */
    HASH_ITER(hh_user, userint->intlist, ipint, tmp) {
        if (!identity_match_intercept(ipint, uid)) {
            continue;
        }
        HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues),
                sendq, tmpq) {
            push_single_ipintercept(sync, sendq->q, ipint, sess);
        }
    }
    pthread_mutex_lock(sync->glob->stats_mutex);
    sync->glob->stats->ipsessions_added_diff ++;
    sync->glob->stats->ipsessions_added_total ++;
    pthread_mutex_unlock(sync->glob->stats_mutex);
    return 0;


}

static inline int is_default_radius_username(collector_sync_t *sync,
        user_identity_t *uid) {

    default_radius_user_t *found;

    if (uid->method != USER_IDENT_RADIUS_USERNAME) {
        return 0;
    }

    HASH_FIND(hh, sync->defaultradiususers, uid->idstr, uid->idlength,
            found);

    if (found) {
        return 1;
    }

    return 0;
}

static int update_user_sessions(collector_sync_t *sync, libtrace_packet_t *pkt,
        uint8_t accesstype) {

    access_plugin_t *p = NULL;
    user_identity_t *identities = NULL;
    internet_user_t *iuser;
    access_session_t *sess;
    access_action_t accessaction;
    session_state_t oldstate, newstate;
    user_intercept_list_t *userint;
    ipintercept_t *ipint, *tmp;
    int expcount = 0;
    void *parseddata = NULL;
    int i, ret, useridcnt = 0;

    if (accesstype == ACCESS_RADIUS) {
        p = sync->radiusplugin;
    } else if (accesstype == ACCESS_GTP) {
        p = sync->gtpplugin;
    }

    if (!p) {
        logger(LOG_INFO, "OpenLI: tried to update user sessions using an unsupported access type: %u", accesstype);
        return -1;
    }

    parseddata = p->process_packet(p, pkt);

    if (parseddata == NULL) {
        logger(LOG_INFO, "OpenLI: unable to parse %s packet", p->name);
        pthread_mutex_lock(sync->glob->stats_mutex);
        sync->glob->stats->bad_ip_session_packets ++;
        pthread_mutex_unlock(sync->glob->stats_mutex);
        return -1;
    }

    ret = 0;
    identities = p->get_userid(p, parseddata, &useridcnt);
    if (identities == NULL) {
        /* Probably an orphaned response packet */
        goto endupdate;
    }

    for (i = 0; i < useridcnt; i++) {
        /* If id type is RADIUS username and idstr is in the list of
         * default usernames, then ignore it */

        if (is_default_radius_username(sync, &(identities[i]))) {
            continue;
        }

        iuser = lookup_userid(sync, &identities[i]);
        if (!iuser) {
            ret = -1;
            break;
        }

        sess = p->update_session_state(p, parseddata, identities[i].plugindata,
                &(iuser->sessions), &oldstate, &newstate, &accessaction);
        if (!sess) {
            /* Unable to assign packet to a session, just quietly ignore it */
            continue;
        }

        HASH_FIND(hh, sync->userintercepts, iuser->userid,
                identities[i].idlength, userint);

        if (oldstate != newstate) {
            if (newstate == SESSION_STATE_ACTIVE) {
                ret = newly_active_session(sync, userint, iuser, sess,
                        &(identities[i]));
                if (ret < 0) {
                    logger(LOG_INFO, "OpenLI: error while processing new active IP session in sync thread.");
                    break;
                }

            } else if (newstate == SESSION_STATE_OVER) {
                /* If this was an active intercept, tell our threads to
                 * stop intercepting traffic for this session */
                if (userint) {
                    HASH_ITER(hh_user, userint->intlist, ipint, tmp) {
                        if (identity_match_intercept(ipint, &(identities[i]))) {
                            push_session_update_to_threads(
                                    sync->glob->collector_queues,
                                    sess, ipint, OPENLI_PUSH_HALT_IPINTERCEPT);
                        }
                    }
                    pthread_mutex_lock(sync->glob->stats_mutex);
                    sync->glob->stats->ipsessions_ended_diff ++;
                    sync->glob->stats->ipsessions_ended_total ++;
                    pthread_mutex_unlock(sync->glob->stats_mutex);
                }

                if (remove_ip_to_session_mapping(sync, sess) < 0) {
                    logger(LOG_INFO, "OpenLI: error while removing IP->session mapping in sync thread.");
                }
            }
        }

        if (userint) {
            HASH_ITER(hh_user, userint->intlist, ipint, tmp) {
                if (!identity_match_intercept(ipint, &(identities[i]))) {
                    continue;
                }

                if (ipint->common.targetagency == NULL ||
                        strcmp(ipint->common.targetagency,"pcapdisk") == 0) {
                    uint32_t seqno;

                    seqno = p->get_packet_sequence(p, parseddata);
                    if (export_raw_sync_packet_content(p, sync, ipint,
                            parseddata, seqno, sess->cin) > 0) {
                        expcount ++;
                    }
                } else if (accessaction != ACCESS_ACTION_NONE) {
                    create_iri_from_packet_event(sync, sess, ipint, p,
                            parseddata);
                    expcount ++;
                }
            }
        }

        if (oldstate != newstate && newstate == SESSION_STATE_OVER) {
            free_single_session(iuser, sess);
        }
    }

endupdate:
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

    if (ret < 0) {
        return -1;
    }

    if (expcount == 0) {
        return 0;
    }

    return 1;
}

static int set_upcoming_timer(collector_sync_t *sync) {
    struct itimerspec its;
    sync->upcomingtimerfd = timerfd_create(CLOCK_MONOTONIC, 0);

    if (sync->upcomingtimerfd == -1) {
        return -1;
    }

    if (fcntl(sync->upcomingtimerfd, F_SETFL, fcntl(sync->upcomingtimerfd,
            F_GETFL, 0) | O_NONBLOCK) < 0) {
        return -1;
    }

    its.it_interval.tv_sec = 1;
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = 1;
    its.it_value.tv_nsec = 0;

    timerfd_settime(sync->upcomingtimerfd, 0, &its, NULL);
    return 0;
}

int sync_thread_main(collector_sync_t *sync) {
    zmq_pollitem_t items[3];
    openli_state_update_t recvd;
    int rc;

    items[0].socket = sync->zmq_colsock;
    items[0].events = ZMQ_POLLIN;

    items[1].socket = NULL;
    items[1].fd = sync->instruct_fd;
    items[1].events = sync->instruct_events;

    if (sync->upcomingtimerfd == -1) {
        set_upcoming_timer(sync);
    }

    if (sync->upcomingtimerfd != -1) {
        items[2].socket = NULL;
        items[2].fd = sync->upcomingtimerfd;
        items[2].events = ZMQ_POLLIN;
    }

    if (zmq_poll(items, 3, 50) < 0) {
        return -1;
    }

    if (items[2].revents & ZMQ_POLLIN) {
        struct timeval tv;
        char readbuf[16];
        ipintercept_t *ipint_v;

        if (read(sync->upcomingtimerfd, readbuf, 16) > 0) {
            gettimeofday(&tv, NULL);

            do {
                ipint_v = (ipintercept_t *)check_intercept_time_event(
                        &(sync->upcoming_intercept_events), tv.tv_sec);
                if (ipint_v) {
                    generate_startend_ipiris(sync, ipint_v, tv.tv_sec);
                }
            } while (ipint_v);

        }
    }

    if (items[1].revents & ZMQ_POLLOUT) {
        if (send_to_provisioner(sync) <= 0) {
            sync_disconnect_provisioner(sync, 0);
            return 0;
        }
    }

    /* Don't process any incoming messages from the provisioner until
     * all of our processing threads have started up. This helps avoid
     * concurrency issues where we end up doing duplicate announcements
     * of "active" intercepts because we announce them both as soon as
     * we get the message from the provisioner and then again when the
     * HELLO message comes in from the processing threads.
     *
     * NOTE: we should consider just removing HELLO messages entirely,
     * as they communicate no useful information and we should be able
     * to push messages onto the queue for a processing thread, even if
     * the thread itself is still in the process of starting up.
     */
    if ((items[1].revents & ZMQ_POLLIN) &&
            sync->hellosreceived >= sync->glob->total_col_threads) {
        if ((rc = recv_from_provisioner(sync)) <= 0) {
            sync_disconnect_provisioner(sync, 0);
            if (rc == 0 || rc == -1) {
                return 0;
            } else {
                return -1;
            }
        }
    }

    if (items[0].revents & ZMQ_POLLIN) {
        do {
            rc = zmq_recv(sync->zmq_colsock, &recvd, sizeof(recvd),
                    ZMQ_DONTWAIT);
            if (rc < 0) {
                if (errno == EAGAIN) {
                    return 0;
                }
                logger(LOG_INFO, "openli-collector: IP sync thread had an error receiving message from collector threads: %s", strerror(errno));
                return -1;
            }

            /* If a hello from a thread, push all active intercepts back */
            if (recvd.type == OPENLI_UPDATE_HELLO) {
                push_all_active_intercepts(sync, sync->allusers,
                        sync->ipintercepts, recvd.data.replyq);
                push_all_coreservers(sync->coreservers, recvd.data.replyq);
                sync->hellosreceived ++;

                if (sync->hellosreceived == sync->glob->total_col_threads) {
                    logger(LOG_INFO, "openli-collector: all processing threads have reported for duty");
                }
            }


            /* If an update from a thread, update appropriate internal state */

            /* If this resolves an unknown mapping or changes an existing one,
             * push II update messages to processing threads */

            /* If this relates to an active intercept, create IRI and export */
            if (recvd.type == OPENLI_UPDATE_RADIUS ||
                    recvd.type == OPENLI_UPDATE_GTP) {
                int ret;
                int accesstype;

                if (recvd.type == OPENLI_UPDATE_RADIUS) {
                    accesstype = ACCESS_RADIUS;
                } else if (recvd.type == OPENLI_UPDATE_GTP) {
                    accesstype = ACCESS_GTP;
                }

                if ((ret = update_user_sessions(sync, recvd.data.pkt,
                            accesstype)) < 0) {
                    /* If a user has screwed up their RADIUS config and we
                     * see non-RADIUS packets here, we probably want to limit the
                     * number of times we complain about this... FIXME */
                    logger(LOG_INFO,
                            "OpenLI: sync thread received an invalid packet");
                }
                trace_destroy_packet(recvd.data.pkt);
            }

        } while (rc > 0);
    }

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
