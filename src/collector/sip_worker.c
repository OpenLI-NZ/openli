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

#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/timerfd.h>
#include <math.h>
#include <libtrace.h>

#include "logger.h"
#include "util.h"
#include "sip_worker.h"
#include "collector.h"
#include "collector_publish.h"
#include "ipmmiri.h"
#include "intercept.h"
#include "location.h"

static void destroy_sip_worker_thread(openli_sip_worker_t *sipworker) {
    sync_epoll_t *syncev, *tmp;

    if (sipworker->sipparser) {
        release_sip_parser(sipworker->sipparser);
    }

    free_voip_cinmap(sipworker->knowncallids);
    HASH_ITER(hh, sipworker->timeouts, syncev, tmp) {
        HASH_DELETE(hh, sipworker->timeouts, syncev);
    }

    if (sipworker->voipintercepts) {
        free_all_voipintercepts(&(sipworker->voipintercepts));
    }

    if (sipworker->worker_threadname) {
        free((void *)sipworker->worker_threadname);
    }


    if (sipworker->debug.sipdebugupdate) {
        trace_destroy_output(sipworker->debug.sipdebugupdate);
    }

    if (sipworker->debug.sipdebugout) {
        trace_destroy_output(sipworker->debug.sipdebugout);
    }

    if (sipworker->zmq_colthread_recvsock) {
        zmq_close(sipworker->zmq_colthread_recvsock);
    }

    if (sipworker->zmq_ii_sock) {
        zmq_close(sipworker->zmq_ii_sock);
    }

    if (sipworker->zmq_redirect_insock) {
        zmq_close(sipworker->zmq_redirect_insock);
    }

    clear_zmq_socket_array(sipworker->zmq_pubsocks, sipworker->tracker_threads);
    clear_zmq_socket_array(sipworker->zmq_fwdsocks,
            sipworker->forwarding_threads);
    clear_zmq_socket_array(sipworker->zmq_redirect_outsocks,
            sipworker->sipworker_threads);

    if (sipworker->haltinfo) {
        pthread_mutex_lock(&(sipworker->haltinfo->mutex));
        sipworker->haltinfo->halted ++;
        pthread_cond_signal(&(sipworker->haltinfo->cond));
        pthread_mutex_unlock(&(sipworker->haltinfo->mutex));
    }

    clear_redirection_map(&(sipworker->redir_data.redirections));
    clear_redirection_map(&(sipworker->redir_data.recvd_redirections));

    /* Don't destroy the col_queue_mutex here -- let the main collector thread
     * handle that.
     */
}

static int setup_zmq_sockets(openli_sip_worker_t *sipworker) {
    int zero = 0;
    char sockname[256];

    sipworker->zmq_pubsocks = calloc(sipworker->tracker_threads,
            sizeof(void *));
    sipworker->zmq_fwdsocks = calloc(sipworker->forwarding_threads,
            sizeof(void *));
    sipworker->zmq_redirect_outsocks = calloc(sipworker->sipworker_threads,
            sizeof(void *));

    init_zmq_socket_array(sipworker->zmq_pubsocks, sipworker->tracker_threads,
            "inproc://openlipub", sipworker->zmq_ctxt, -1);
    init_zmq_socket_array(sipworker->zmq_redirect_outsocks,
            sipworker->sipworker_threads,
            "inproc://openlisipredirect", sipworker->zmq_ctxt, 1000);
    init_zmq_socket_array(sipworker->zmq_fwdsocks,
            sipworker->forwarding_threads,
            "inproc://openliforwardercontrol_sync", sipworker->zmq_ctxt, -1);

    /* don't need to redirect to ourselves... */
    if (sipworker->zmq_redirect_outsocks[sipworker->workerid]) {
        zmq_close(sipworker->zmq_redirect_outsocks[sipworker->workerid]);
        sipworker->zmq_redirect_outsocks[sipworker->workerid] = NULL;
    }

    sipworker->zmq_redirect_insock = zmq_socket(sipworker->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openlisipredirect-%d",
            sipworker->workerid);
    if (zmq_bind(sipworker->zmq_redirect_insock, sockname) < 0) {
        logger(LOG_INFO,
                "OpenLI: SIP processing thread %d failed to bind to redirect recv ZMQ: %s",
                sipworker->workerid, strerror(errno));
        return -1;
    }

    if (zmq_setsockopt(sipworker->zmq_redirect_insock, ZMQ_LINGER, &zero,
                sizeof(zero)) != 0) {
        logger(LOG_INFO,
                "OpenLI: SIP processing thread %d failed to configure redirect recv ZMQ: %s",
                sipworker->workerid, strerror(errno));
        return -1;
    }


    sipworker->zmq_ii_sock = zmq_socket(sipworker->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openlisipcontrol_sync-%d",
            sipworker->workerid);
    if (zmq_bind(sipworker->zmq_ii_sock, sockname) < 0) {
        logger(LOG_INFO,
                "OpenLI: SIP processing thread %d failed to bind to II ZMQ: %s",
                sipworker->workerid, strerror(errno));
        return -1;
    }

    if (zmq_setsockopt(sipworker->zmq_ii_sock, ZMQ_LINGER, &zero, sizeof(zero))
            != 0) {
        logger(LOG_INFO,
                "OpenLI: SIP processing thread %d failed to configure II ZMQ: %s",
                sipworker->workerid, strerror(errno));
        return -1;
    }

    sipworker->zmq_colthread_recvsock = zmq_socket(sipworker->zmq_ctxt,
            ZMQ_PULL);
    snprintf(sockname, 256, "inproc://openlisipworker-colrecv-%d",
            sipworker->workerid);
    if (zmq_bind(sipworker->zmq_colthread_recvsock, sockname) < 0) {
        logger(LOG_INFO,
                "OpenLI: SIP processing thread %d failed to bind to packet ZMQ: %s",
                sipworker->workerid, strerror(errno));
        return -1;
    }

    if (zmq_setsockopt(sipworker->zmq_colthread_recvsock, ZMQ_LINGER, &zero,
                sizeof(zero)) != 0) {
        logger(LOG_INFO,
                "OpenLI: SIP processing thread %d failed to configure packet ZMQ: %s",
                sipworker->workerid, strerror(errno));
        return -1;
    }
    return 0;
}

static size_t setup_pollset(openli_sip_worker_t *sipworker,
        zmq_pollitem_t **topoll, size_t *topoll_size, int timerfd,
        struct rtpstreaminf ***expiring) {

    size_t topoll_req, i;
    sync_epoll_t *syncev, *tmp;

    topoll_req = 4 + HASH_CNT(hh, sipworker->timeouts);
    if (topoll_req > *topoll_size) {
        free(*topoll);
        free(*expiring);
        *topoll = calloc(topoll_req + 32, sizeof(zmq_pollitem_t));
        *expiring = calloc(topoll_req + 32,
                sizeof(struct rtpstreaminf *));
        *topoll_size = topoll_req + 32;
    }

    (*topoll)[0].socket = sipworker->zmq_ii_sock;
    (*topoll)[0].events = ZMQ_POLLIN;

    (*topoll)[1].socket = sipworker->zmq_colthread_recvsock;
    (*topoll)[1].events = ZMQ_POLLIN;

    (*topoll)[2].socket = NULL;
    (*topoll)[2].fd = timerfd;
    (*topoll)[2].events = ZMQ_POLLIN;

    (*topoll)[3].socket = sipworker->zmq_redirect_insock;
    (*topoll)[3].events = ZMQ_POLLIN;

    i = 4;
    HASH_ITER(hh, sipworker->timeouts, syncev, tmp) {
        (*topoll)[i].socket = NULL;
        (*topoll)[i].fd = syncev->fd;
        (*topoll)[i].events = ZMQ_POLLIN;
        (*expiring)[i] = (struct rtpstreaminf *)(syncev->ptr);
        i++;
    }

    return i;
}

static void purge_old_sms_sessions(openli_sip_worker_t *sipworker) {
    struct timeval tv;
    voipcinmap_t *cid, *tmp;

    gettimeofday(&tv, NULL);
    HASH_ITER(hh_callid, sipworker->knowncallids, cid, tmp) {
        if (!cid->smsonly) {
            continue;
        }
        if (cid->lastsip != 0 && tv.tv_sec - cid->lastsip >
                SMS_SESSION_EXPIRY) {
            HASH_DELETE(hh_callid, sipworker->knowncallids, cid);
            free_single_voip_cinmap_entry(cid);
        }
    }
}

static int halt_expired_rtpstream(openli_sip_worker_t *sipworker,
        rtpstreaminf_t *rtp) {
    voipintercept_t *vint;
    voipcinmap_t *cin_callid, *tmpcin;
    voipsdpmap_t *cin_sdp, *tmpsdp;
    uint8_t stop;

    if (!rtp) {
        return 0;
    }

    vint = rtp->parent;

    if (rtp->timeout_ev) {
        sync_epoll_t *timerev = (sync_epoll_t *)(rtp->timeout_ev);
        sync_epoll_t *syncev;

        HASH_FIND(hh, sipworker->timeouts, &(timerev->fd), sizeof(int),
                syncev);
        if (syncev) {
            HASH_DELETE(hh, sipworker->timeouts, syncev);
        }
        close(timerev->fd);
        free(timerev);
        rtp->timeout_ev = NULL;
    }

    if (rtp->active) {
        sync_sendq_t *sendq, *tmpq;
        openli_pushed_t msg;
        /* tell all of the packet processing threads to stop intercepting
         * this RTP stream */
        pthread_mutex_lock(&(sipworker->col_queue_mutex));
        HASH_ITER(hh, (sync_sendq_t *)(sipworker->collector_queues), sendq,
                tmpq) {
            memset(&msg, 0, sizeof(openli_pushed_t));
            msg.type = OPENLI_PUSH_HALT_IPMMINTERCEPT;
            msg.data.rtpstreamkey = strdup(rtp->streamkey);
            libtrace_message_queue_put(sendq->q, (void *)(&msg));
        }

        pthread_mutex_unlock(&(sipworker->col_queue_mutex));
    }

    if (!vint) {
        return 0;
    }

    HASH_DEL(vint->active_cins, rtp);

    /* Iterating through the corresponding voipintercept's call maps seems
     * a bit clunky at first glance, but there shouldn't be too many
     * entries in these maps at any given time so it isn't really worth
     * the effort of trying to maintain reverse references to the map
     * entries in the RTP stream info structure
     */

    HASH_ITER(hh_callid, vint->cin_callid_map, cin_callid, tmpcin) {
        stop = 0;
        if (cin_callid->shared->cin == rtp->cin) {
            HASH_DELETE(hh_callid, vint->cin_callid_map, cin_callid);
            free(cin_callid->callid);
            cin_callid->shared->refs --;
            if (cin_callid->shared->refs == 0) {
                free(cin_callid->shared);
                stop = 1;
            }
            if (cin_callid->username) {
                free(cin_callid->username);
            }
            if (cin_callid->realm) {
                free(cin_callid->realm);
            }
            free(cin_callid);
            if (stop) {
                break;
            }
        }
    }

    HASH_ITER(hh_sdp, vint->cin_sdp_map, cin_sdp, tmpsdp) {
        stop = 0;
        if (cin_sdp->shared->cin == rtp->cin) {
            HASH_DELETE(hh_sdp, vint->cin_sdp_map, cin_sdp);
            cin_sdp->shared->refs --;
            if (cin_sdp->shared->refs == 0) {
                free(cin_sdp->shared);
                stop = 1;
            }
            if (cin_sdp->username) {
                free(cin_sdp->username);
            }
            if (cin_sdp->realm) {
                free(cin_sdp->realm);
            }
            free(cin_sdp);
            if (stop) {
                break;
            }
        }
    }
    free_single_rtpstream(rtp);
    return 0;
}

void sip_worker_conclude_sip_call(openli_sip_worker_t *sipworker,
        rtpstreaminf_t *thisrtp) {

    sync_epoll_t *timeout = (sync_epoll_t *)calloc(1, sizeof(sync_epoll_t));
    struct itimerspec its;

    thisrtp->byematched = 1;
    its.it_value.tv_sec = 30;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    /* Call for this session should be over */
    thisrtp->timeout_ev = (void *)timeout;
    timeout->fdtype = SYNC_EVENT_SIP_TIMEOUT;
    timeout->fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timeout->ptr = thisrtp;

    if (timeout->fd > 0) {
    	timerfd_settime(timeout->fd, 0, &its, NULL);
        HASH_ADD_KEYPTR(hh, sipworker->timeouts, &(timeout->fd), sizeof(int),
                timeout);
    } else {
        /* if we can't get a valid file descriptor for a timer, we
         * have to just purge the call right away... */
        free(timeout);
        thisrtp->timeout_ev = NULL;
        halt_expired_rtpstream(sipworker, thisrtp);
    }

}

static libtrace_out_t *open_debug_output(char *basename, size_t workerid,
        char *ext) {
    libtrace_out_t *out = NULL;
    char fname[1024];
    int compressmethod = TRACE_OPTION_COMPRESSTYPE_ZLIB;
    int compresslevel = 1;

    snprintf(fname, 1024, "pcapfile:%s-%s-%zu.pcap.gz", basename, ext,
            workerid);
    out = trace_create_output(fname);
    if (trace_is_err_output(out)) {
        trace_perror_output(out, "trace_create_output");
        goto debugfail;
    }

    if (trace_config_output(out, TRACE_OPTION_OUTPUT_COMPRESSTYPE,
            &compressmethod) == -1) {
        trace_perror_output(out, "config compress type");
        goto debugfail;
    }

    if (trace_config_output(out, TRACE_OPTION_OUTPUT_COMPRESS,
                    &compresslevel) == -1) {
        trace_perror_output(out, "config compress level");
        goto debugfail;
    }

    if (trace_start_output(out) == -1) {
        trace_perror_output(out, "trace_start_output");
        goto debugfail;
    }

    return out;

debugfail:
    if (out) {
        trace_destroy_output(out);
    }
    return NULL;
}

static void handle_bad_sip_update(openli_sip_worker_t *sipworker,
        libtrace_packet_t **packets, int pkt_cnt, uint8_t during) {

    int i;

    if (sipworker->debug.log_bad_sip) {
        if (during == SIP_PROCESSING_PARSING) {
            logger(LOG_INFO,
                    "OpenLI: SIP worker thread %d saw an invalid SIP packet?",
                    sipworker->workerid);
        } else if (during == SIP_PROCESSING_UPDATING_STATE) {
            logger(LOG_INFO,
                    "OpenLI: error while updating SIP state in worker thread %d.",
                    sipworker->workerid);
        } else if (during == SIP_PROCESSING_EXTRACTING_IPS) {
            logger(LOG_INFO,
                    "OpenLI: error while extracting IP addresses from SIP packet in worker thread %d", sipworker->workerid);
        } else if (during == SIP_PROCESSING_ADD_PARSER) {
            logger(LOG_INFO,
                    "OpenLI: SIP worker thread %d received an invalid SIP packet?",
                    sipworker->workerid);
        } else {
            logger(LOG_INFO,
                    "OpenLI: unexpected error when processing SIP packet in worker thread %d", sipworker->workerid);

        }
        logger(LOG_INFO,
                "OpenLI: SIP worker thread %d will not log any further invalid SIP instances.", sipworker->workerid);
        sipworker->debug.log_bad_sip = 0;
    }
    pthread_mutex_lock(sipworker->stats_mutex);
    sipworker->stats->bad_sip_packets ++;
    pthread_mutex_unlock(sipworker->stats_mutex);

    if (!packets) {
        return;
    }

    if (!sipworker->debug.sipdebugout) {
        pthread_rwlock_rdlock(sipworker->shared_mutex);
        if (sipworker->shared->sipdebugfile == NULL) {
            pthread_rwlock_unlock(sipworker->shared_mutex);
            return;
        }

        sipworker->debug.sipdebugout = open_debug_output(
                    sipworker->shared->sipdebugfile,
                    sipworker->workerid, "invalid");
        pthread_rwlock_unlock(sipworker->shared_mutex);
    }

    if (sipworker->debug.sipdebugout) {
        for (i = 0; i < pkt_cnt; i++) {
            if (packets[i] == NULL) {
                continue;
            }
            trace_write_packet(sipworker->debug.sipdebugout, packets[i]);
        }
    }
}


static void sip_update_fast_path(openli_sip_worker_t *sipworker,
        libtrace_packet_t *packet) {

    int ret;
    openli_export_recv_t baseirimsg;

    /* The provided packet contains an entire SIP message, so we
     * don't need to worry about segmentation or multiple
     * messages within the same packet.
     */

    memset(&baseirimsg, 0, sizeof(openli_export_recv_t));

    baseirimsg.type = OPENLI_EXPORT_IPMMIRI;
    baseirimsg.data.ipmmiri.ipmmiri_style = OPENLI_IPMMIRI_SIP;
    baseirimsg.ts = trace_get_timeval(packet);

    if (extract_ip_addresses(packet, baseirimsg.data.ipmmiri.ipsrc,
            baseirimsg.data.ipmmiri.ipdest,
            &(baseirimsg.data.ipmmiri.ipfamily)) != 0) {
        handle_bad_sip_update(sipworker, &packet, 1,
                SIP_PROCESSING_EXTRACTING_IPS);
        return;
    }

    baseirimsg.data.ipmmiri.srcport = trace_get_source_port(packet);
    baseirimsg.data.ipmmiri.dstport = trace_get_destination_port(packet);

    ret = parse_next_sip_message(sipworker->sipparser, NULL, NULL);
    if (ret == 0) {
        return;
    }
    if (ret < 0) {
        handle_bad_sip_update(sipworker, &packet, 1, SIP_PROCESSING_PARSING);
        return;

    }
    baseirimsg.data.ipmmiri.content = (uint8_t *)get_sip_contents(
            sipworker->sipparser, &(baseirimsg.data.ipmmiri.contentlen));

    if (sipworker_update_sip_state(sipworker, &packet, 1, &baseirimsg) < 0) {
        handle_bad_sip_update(sipworker, &packet, 1,
                SIP_PROCESSING_UPDATING_STATE);
    }

}

static void sip_update_slow_path(openli_sip_worker_t *sipworker,
        libtrace_packet_t *packet, uint8_t doonce) {

    int ret, i;
    openli_export_recv_t baseirimsg;
    libtrace_packet_t **packets = NULL;
    int pkt_cnt = 0;

    memset(&baseirimsg, 0, sizeof(openli_export_recv_t));

    baseirimsg.type = OPENLI_EXPORT_IPMMIRI;
    baseirimsg.data.ipmmiri.ipmmiri_style = OPENLI_IPMMIRI_SIP;
    baseirimsg.ts = trace_get_timeval(packet);

    if (extract_ip_addresses(packet, baseirimsg.data.ipmmiri.ipsrc,
            baseirimsg.data.ipmmiri.ipdest,
            &(baseirimsg.data.ipmmiri.ipfamily)) != 0) {
        handle_bad_sip_update(sipworker, &packet, 1,
                SIP_PROCESSING_EXTRACTING_IPS);
        return;
    }
    baseirimsg.data.ipmmiri.srcport = trace_get_source_port(packet);
    baseirimsg.data.ipmmiri.dstport = trace_get_destination_port(packet);

    do {
        if (packets != NULL) {
            for (i = 0; i < pkt_cnt; i++) {
                if (packets[i]) {
                    trace_destroy_packet(packets[i]);
                }
            }
            free(packets);
            pkt_cnt = 0;
            packets = NULL;
        }

        ret = parse_next_sip_message(sipworker->sipparser, &packets, &pkt_cnt);
        if (ret == 0) {
            return;
        }
        if (ret < 0) {
            handle_bad_sip_update(sipworker, packets, pkt_cnt,
                    SIP_PROCESSING_PARSING);
            continue;
        }
        baseirimsg.data.ipmmiri.content = (uint8_t *)get_sip_contents(
                sipworker->sipparser, &(baseirimsg.data.ipmmiri.contentlen));
        if (sipworker_update_sip_state(sipworker, packets, pkt_cnt,
                    &baseirimsg) < 0) {
            handle_bad_sip_update(sipworker, packets, pkt_cnt,
                    SIP_PROCESSING_UPDATING_STATE);
            continue;
        }

    } while (!doonce);

    if (packets) {
        for (i = 0; i < pkt_cnt; i++) {
            if (packets[i]) {
                trace_destroy_packet(packets[i]);
            }
        }
        free(packets);
    }

}

static void process_received_sip_packet(openli_sip_worker_t *sipworker,
        libtrace_packet_t *packet) {

    int ret;

    ret = add_sip_packet_to_parser(&(sipworker->sipparser), packet,
            sipworker->debug.log_bad_sip);

    if (ret == SIP_ACTION_ERROR) {
        handle_bad_sip_update(sipworker, &packet, 1,
                SIP_PROCESSING_ADD_PARSER);
    } else if (ret == SIP_ACTION_USE_PACKET) {
        sip_update_fast_path(sipworker, packet);
    } else if (ret == SIP_ACTION_REASSEMBLE_TCP) {
        sip_update_slow_path(sipworker, packet, 0);
        packet = NULL;        // consumed by the reassembler
    } else if (ret == SIP_ACTION_REASSEMBLE_IPFRAG) {
        sip_update_slow_path(sipworker, packet, 1);
    }

    if (packet) {
        trace_destroy_packet(packet);
    }
}


static inline voipintercept_t *lookup_sip_target_intercept(
        openli_sip_worker_t *sipworker, provisioner_msg_t *provmsg,
        openli_sip_identity_t *sipid) {

    voipintercept_t *found = NULL;
    char liidspace[1024];

    sipid->username = NULL;
    sipid->realm = NULL;

    if (decode_sip_target_announcement(provmsg->msgbody,
            provmsg->msglen, sipid, liidspace, 1024) < 0) {
        logger(LOG_INFO,
                "OpenLI: SIP worker thread %d received invalid SIP target",
                sipworker->workerid);
        return NULL;
    }

    HASH_FIND(hh_liid, sipworker->voipintercepts, liidspace, strlen(liidspace),
            found);
    if (!found) {
        logger(LOG_INFO,
                "OpenLI: SIP worker thread %d received SIP target for unknown VoIP LIID %s.",
                liidspace);
    }
    return found;
}


static inline void sip_worker_push_single_voipstreamintercept(
        openli_sip_worker_t *sipworker, libtrace_message_queue_t *q,
        rtpstreaminf_t *orig) {

    rtpstreaminf_t *copy;
    openli_pushed_t msg;

    copy = deep_copy_rtpstream(orig);
    if (!copy) {
        logger(LOG_INFO,
                "OpenLI: unable to copy RTP stream in SIP worker thread due to lack of memory.");
        logger(LOG_INFO,
                "OpenLI: forcing collector instance to halt.");
        exit(-2);
    }

    memset(&msg, 0, sizeof(openli_pushed_t));
    msg.type = OPENLI_PUSH_IPMMINTERCEPT;
    msg.data.ipmmint = copy;

    if (orig->announced == 0) {
        pthread_mutex_lock(sipworker->stats_mutex);
        sipworker->stats->voipsessions_added_diff ++;
        sipworker->stats->voipsessions_added_total ++;
        pthread_mutex_unlock(sipworker->stats_mutex);

        orig->announced = 1;
    }
    libtrace_message_queue_put(q, (void *)(&msg));
}

int sip_worker_announce_rtp_streams(openli_sip_worker_t *sipworker,
        rtpstreaminf_t *rtp) {

    sync_sendq_t *sendq, *tmp;

    if (!rtp->targetaddr || !rtp->otheraddr) {
        return 0;
    }

    if (rtp->active == 1 && rtp->changed == 0) {
        return 0;
    }

    pthread_mutex_lock(&(sipworker->col_queue_mutex));
    HASH_ITER(hh, (sync_sendq_t *)(sipworker->collector_queues), sendq, tmp) {
        sip_worker_push_single_voipstreamintercept(sipworker, sendq->q, rtp);
    }
    pthread_mutex_unlock(&(sipworker->col_queue_mutex));
    rtp->active = 1;
    rtp->changed = 0;
    return 1;
}

static void sip_worker_push_all_active_voipstreams(
        openli_sip_worker_t *sipworker, libtrace_message_queue_t *q,
        voipintercept_t *vint) {

    rtpstreaminf_t *cin = NULL;

    if (vint->active_cins == NULL) {
        return;
    }

    for (cin = vint->active_cins; cin != NULL; cin=cin->hh.next) {
        if (cin->active == 0) {
            continue;
        }

        sip_worker_push_single_voipstreamintercept(sipworker, q, cin);
    }

}

static void sip_worker_send_intercept_update_to_seqtracker(
        openli_sip_worker_t *sipworker, voipintercept_t *vint, uint8_t type) {

    openli_export_recv_t *expmsg;

    if (sipworker->workerid != 0) {
        // we don't need all of our workers to send the same update
        return;
    }

    expmsg = create_intercept_details_msg(&(vint->common),
            OPENLI_INTERCEPT_TYPE_VOIP);
    expmsg->type = type;
    publish_openli_msg(sipworker->zmq_pubsocks[vint->common.seqtrackerid],
            expmsg);

}

static void sip_worker_push_intercept_halt(openli_sip_worker_t *sipworker,
        voipintercept_t *vint) {

    /* Need to do this inside every SIP worker, because we don't know
     * which one actually has the RTP streams for the intercept (if any)
     */
    sync_sendq_t *sendq, *tmp;
    rtpstreaminf_t *cin = NULL;
    char *streamdup;
    openli_pushed_t msg;

    if (vint->active_cins == NULL) {
        return;
    }

    pthread_mutex_lock(&(sipworker->col_queue_mutex));
    HASH_ITER(hh, (sync_sendq_t *)(sipworker->collector_queues), sendq, tmp) {
        for (cin = vint->active_cins; cin != NULL; cin=cin->hh.next) {
            if (cin->active == 0) {
                continue;
            }
            streamdup = strdup(cin->streamkey);
            memset(&msg, 0, sizeof(openli_pushed_t));
            msg.type = OPENLI_PUSH_HALT_IPMMINTERCEPT;
            msg.data.rtpstreamkey = streamdup;

            pthread_mutex_lock(sipworker->stats_mutex);
            sipworker->stats->voipsessions_ended_diff ++;
            sipworker->stats->voipsessions_ended_total ++;
            pthread_mutex_unlock(sipworker->stats_mutex);

            libtrace_message_queue_put(sendq->q, (void *)(&msg));

            /* If we were already about to time this intercept out, make sure
             * we kill the timer.
             */
            if (cin->timeout_ev) {
                sync_epoll_t *timerev = (sync_epoll_t *)(cin->timeout_ev);
                sync_epoll_t *syncev;

                HASH_FIND(hh, sipworker->timeouts, &(timerev->fd),
                        sizeof(int), syncev);
                if (syncev) {
                    HASH_DELETE(hh, sipworker->timeouts, syncev);
                }

                close(timerev->fd);
                free(timerev);
                cin->timeout_ev = NULL;
            }
        }
    }
    pthread_mutex_unlock(&(sipworker->col_queue_mutex));
}



static void sip_worker_push_active_voipstream_update(
        openli_sip_worker_t *sipworker UNUSED, libtrace_message_queue_t *q,
        voipintercept_t *vint) {

    openli_pushed_t msg;
    rtpstreaminf_t *cin = NULL;

    for (cin = vint->active_cins; cin != NULL; cin=cin->hh.next) {
        if (cin->active == 0) {
            continue;
        }
        memset(&msg, 0, sizeof(openli_pushed_t));
        msg.type = OPENLI_PUSH_UPDATE_VOIPINTERCEPT;
        msg.data.ipmmint = create_rtpstream(vint, cin->cin);

        libtrace_message_queue_put(q, (void *)(&msg));
    }

}

static int sip_worker_update_modified_voip_intercept(
        openli_sip_worker_t *sipworker, voipintercept_t *found,
        voipintercept_t *decoded) {
    int r = 0, changed = 0, encodingchanged = 0;

    encodingchanged = update_modified_intercept_common(&(found->common),
            &(decoded->common), OPENLI_INTERCEPT_TYPE_VOIP, &changed);

    if (encodingchanged < 0) {
        r = -1;
        goto endupdatevint;
    }

    if (found->options != decoded->options) {
        if (decoded->options & (1UL << OPENLI_VOIPINT_OPTION_IGNORE_COMFORT)) {
            if (sipworker->workerid == 0) {
                logger(LOG_INFO,
                        "OpenLI: VOIP intercept %s is now ignoring RTP comfort noise",
                        decoded->common.liid);
            }
        } else {
            if (sipworker->workerid == 0) {
                logger(LOG_INFO,
                        "OpenLI: VOIP intercept %s is now intercepting RTP comfort noise",
                        decoded->common.liid);
            }
        }
        found->options = decoded->options;
        changed = 1;
    }

    if (encodingchanged || changed) {
        sip_worker_send_intercept_update_to_seqtracker(sipworker, found,
                OPENLI_EXPORT_INTERCEPT_CHANGED);
    }

    if (changed) {
        sync_sendq_t *sendq, *tmp;
        pthread_mutex_lock(&(sipworker->col_queue_mutex));
        HASH_ITER(hh, (sync_sendq_t *)(sipworker->collector_queues), sendq,
                    tmp) {
            sip_worker_push_active_voipstream_update(sipworker, sendq->q,
                    found);
        }
        pthread_mutex_unlock(&(sipworker->col_queue_mutex));
    }

endupdatevint:
    free_single_voipintercept(decoded);
    return r;
}

static void remove_cin_callids_for_target(voipcinmap_t **cinmap,
        char *username, char *realm) {

    voipcinmap_t *c, *tmp;
    openli_sip_identity_t a, b;

    a.username = username;
    a.realm = realm;
    HASH_ITER(hh_callid, *cinmap, c, tmp) {
        b.username = c->username;
        b.realm = c->realm;

        if (!are_sip_identities_same(&a, &b)) {
            continue;
        }

        HASH_DELETE(hh_callid, *cinmap, c);
        if (c->shared) {
            c->shared->refs --;
            if (c->shared->refs == 0) {
                free(c->shared);
            }
        }
        if (c->username) {
            free(c->username);
        }
        if (c->realm) {
            free(c->realm);
        }
        free(c->callid);
        free(c);
    }

}

static void remove_cin_sdpkeys_for_target(voipsdpmap_t **sdpmap,
        char *username, char *realm) {

    voipsdpmap_t *s, *tmp;
    openli_sip_identity_t a, b;

    a.username = username;
    a.realm = realm;
    HASH_ITER(hh_sdp, *sdpmap, s, tmp) {
        b.username = s->username;
        b.realm = s->realm;

        if (!are_sip_identities_same(&a, &b)) {
            continue;
        }

        HASH_DELETE(hh_sdp, *sdpmap, s);
        if (s->shared) {
            s->shared->refs --;
            if (s->shared->refs == 0) {
                free(s->shared);
            }
        }
        if (s->username) {
            free(s->username);
        }
        if (s->realm) {
            free(s->realm);
        }
        free(s);
    }
}

static void post_disable_unconfirmed_voip_intercept(voipintercept_t *vint,
        void *arg) {
    openli_sip_worker_t *sipworker = (openli_sip_worker_t *)arg;
    if (sipworker && vint) {
        sip_worker_push_intercept_halt(sipworker, vint);
    }
}

static void post_disable_unconfirmed_voip_target(openli_sip_identity_t *sipid,
        voipintercept_t *v, void *arg) {

    openli_sip_worker_t *sipworker = (openli_sip_worker_t *)arg;
    if (sipworker == NULL || v == NULL || sipid == NULL) {
        return;
    }

    remove_cin_callids_for_target(&(v->cin_callid_map), sipid->username,
            sipid->realm);
    remove_cin_sdpkeys_for_target(&(v->cin_sdp_map), sipid->username,
            sipid->realm);
    remove_cin_callids_for_target(&(sipworker->knowncallids), sipid->username,
            sipid->realm);
}

static void sip_worker_init_voip_intercept(openli_sip_worker_t *sipworker,
        voipintercept_t *vint) {

    if (sipworker->tracker_threads <= 1) {
        vint->common.seqtrackerid = 0;
    } else {
        vint->common.seqtrackerid = hash_liid(vint->common.liid) %
                sipworker->tracker_threads;
    }

    HASH_ADD_KEYPTR(hh_liid, sipworker->voipintercepts, vint->common.liid,
            vint->common.liid_len, vint);
    vint->awaitingconfirm = 0;

    sip_worker_send_intercept_update_to_seqtracker(sipworker, vint,
            OPENLI_EXPORT_INTERCEPT_DETAILS);
}

static int sip_worker_add_new_voip_intercept(openli_sip_worker_t *sipworker,
        provisioner_msg_t *msg) {

    voipintercept_t *vint, *found;
    sync_sendq_t *sendq, *tmp;
    int ret = 0;

    vint = calloc(1, sizeof(voipintercept_t));
    if (decode_voipintercept_start(msg->msgbody, msg->msglen, vint) < 0) {
        logger(LOG_INFO, "OpenLI: SIP worker failed to decode VoIP intercept start message from provisioner");
        free(vint);
        return -1;
    }

    HASH_FIND(hh_liid, sipworker->voipintercepts, vint->common.liid,
            vint->common.liid_len, found);
    if (found) {
        openli_sip_identity_t *tgt;
        libtrace_list_node_t *n;

        /* We already know about this intercept, but don't overwrite
         * anything just yet because hopefully our (updated) targets
         * will be announced to us shortly.
         */
        n = found->targets->head;
        while (n) {
            tgt = *((openli_sip_identity_t **)(n->data));
            tgt->awaitingconfirm = 1;
            n = n->next;
        }
        sip_worker_update_modified_voip_intercept(sipworker, found, vint);
        found->awaitingconfirm = 0;
        found->active = 1;
        ret = 0;
    } else {
        sip_worker_init_voip_intercept(sipworker, vint);
        found = vint;
        ret = 1;
    }


    /* Forward any active RTP streams to the packet processing threads */

    pthread_mutex_lock(&(sipworker->col_queue_mutex));
    HASH_ITER(hh, (sync_sendq_t *)(sipworker->collector_queues), sendq, tmp) {
        sip_worker_push_all_active_voipstreams(sipworker, sendq->q, found);
    }
    pthread_mutex_unlock(&(sipworker->col_queue_mutex));

    if (sipworker->workerid == 0 && ret == 1) {
        logger(LOG_INFO,
            "OpenLI: adding new VOIP intercept %s (start time %lu, end time %lu)", found->common.liid, found->common.tostart_time, found->common.toend_time);
    }

    return ret;
}

static int sip_worker_halt_voip_intercept(openli_sip_worker_t *sipworker,
        provisioner_msg_t *provmsg) {

    voipintercept_t *decode, *found;
    decode = calloc(1, sizeof(voipintercept_t));

    if (decode_voipintercept_halt(provmsg->msgbody, provmsg->msglen,
                decode) < 0) {
        logger(LOG_INFO,
                "OpenLI: SIP worker thread %d received an invalid VoIP intercept withdrawal", sipworker->workerid);
        return -1;
    }

    HASH_FIND(hh_liid, sipworker->voipintercepts, decode->common.liid,
            decode->common.liid_len, found);
    if (!found) {
        if (sipworker->workerid == 0) {
            logger(LOG_INFO,
                    "OpenLI: tried to halt VoIP intercept %s within SIP worker but it was not present in the intercept map?",
                    decode->common.liid);
        }
        free_single_voipintercept(decode);
        return -1;
    }

    if (sipworker->workerid == 0) {
        logger(LOG_INFO,
                "OpenLI: SIP worker threads are withdrawing VOIP intercept: %s",
                found->common.liid);
    }

    sip_worker_push_intercept_halt(sipworker, found);
    sip_worker_send_intercept_update_to_seqtracker(sipworker, found,
            OPENLI_EXPORT_INTERCEPT_OVER);
    HASH_DELETE(hh_liid, sipworker->voipintercepts, found);
    free_single_voipintercept(found);
    free_single_voipintercept(decode);
    return 0;
}

static int sip_worker_modify_voip_intercept(openli_sip_worker_t *sipworker,
        provisioner_msg_t *provmsg) {

    voipintercept_t *vint, *found;

    vint = calloc(1, sizeof(voipintercept_t));
    if (decode_voipintercept_modify(provmsg->msgbody, provmsg->msglen,
                vint) < 0) {
        logger(LOG_INFO, "OpenLI: SIP worker failed to decode VOIP intercept modify message from provisioner");
        return -1;
    }

    HASH_FIND(hh_liid, sipworker->voipintercepts, vint->common.liid,
            vint->common.liid_len, found);
    if (!found) {
        sip_worker_init_voip_intercept(sipworker, vint);
    } else {
        sip_worker_update_modified_voip_intercept(sipworker, found, vint);
    }
    return 0;

}

static int sip_worker_add_sip_target(openli_sip_worker_t *sipworker,
        provisioner_msg_t *provmsg) {

    voipintercept_t *found;
    openli_sip_identity_t sipid;
    int r;

    found = lookup_sip_target_intercept(sipworker, provmsg, &sipid);
    if (!found) {
        if (sipid.username) {
            free(sipid.username);
        }
        if (sipid.realm) {
            free(sipid.realm);
        }
        return -1;
    }
    r = add_new_sip_target_to_list(found, &sipid);
    if (sipworker->workerid == 0 && r == 1) {
        logger(LOG_INFO,
                "OpenLI: collector received new SIP target for LIID %s.",
                found->common.liid);
    }

    return r;
}

static int sip_worker_remove_sip_target(openli_sip_worker_t *sipworker,
        provisioner_msg_t *provmsg) {

    voipintercept_t *found;
    openli_sip_identity_t sipid;
    int ret = 0;

    found = lookup_sip_target_intercept(sipworker, provmsg, &sipid);
    if (!found) {
        ret = -1;
        goto removesiptargetend;
    }
    disable_sip_target_from_list(found, &sipid);
    if (sipworker->workerid == 0) {
        logger(LOG_INFO,
                "OpenLI: collector has withdrawn a SIP target for LIID %s.",
                found->common.liid);
    }

removesiptargetend:
    if (sipid.username) {
        free(sipid.username);
    }
    if (sipid.realm) {
        free(sipid.realm);
    }

    return ret;
}

static int sip_worker_handle_provisioner_message(openli_sip_worker_t *sipworker,
        openli_export_recv_t *msg) {

    int ret = 0;
    switch(msg->data.provmsg.msgtype) {
        case OPENLI_PROTO_START_VOIPINTERCEPT:
            ret = sip_worker_add_new_voip_intercept(sipworker,
                    &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_HALT_VOIPINTERCEPT:
            ret = sip_worker_halt_voip_intercept(sipworker,
                    &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_MODIFY_VOIPINTERCEPT:
            ret = sip_worker_modify_voip_intercept(sipworker,
                    &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_ANNOUNCE_SIP_TARGET:
            ret = sip_worker_add_sip_target(sipworker, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_WITHDRAW_SIP_TARGET:
            ret = sip_worker_remove_sip_target(sipworker, &(msg->data.provmsg));
            break;
        case OPENLI_PROTO_NOMORE_INTERCEPTS:
            disable_unconfirmed_voip_intercepts(&(sipworker->voipintercepts),
                    post_disable_unconfirmed_voip_intercept, sipworker,
                    post_disable_unconfirmed_voip_target, sipworker);
            break;
        case OPENLI_PROTO_DISCONNECT:
            flag_voip_intercepts_as_unconfirmed(&(sipworker->voipintercepts));
            break;
        default:
            logger(LOG_INFO, "OpenLI: SIP worker thread %d received unexpected message type from provisioner: %u",
                    sipworker->workerid, msg->data.provmsg.msgtype);
            ret = -1;
    }
    if (msg->data.provmsg.msgbody) {
        free(msg->data.provmsg.msgbody);
    }

    return ret;
}


static int sip_worker_process_sync_thread_message(
        openli_sip_worker_t *sipworker) {

    openli_export_recv_t *msg;
    int x;

    do {
        x = zmq_recv(sipworker->zmq_ii_sock, &msg, sizeof(msg), ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error receiving II in SIP worker thread %d: %s",
                    sipworker->workerid, strerror(errno));
            return -1;
        }

        if (x <= 0) {
            break;
        }

        if (msg->type == OPENLI_EXPORT_HALT) {
	        sipworker->haltinfo = (halt_info_t *)(msg->data.haltinfo);
            free(msg);
            return -1;
        }

        if (msg->type == OPENLI_EXPORT_PROVISIONER_MESSAGE) {
            if (sip_worker_handle_provisioner_message(sipworker, msg) < 0) {
                free(msg);
                return -1;
            }
        }

        free(msg);
    } while (x > 0);

    return 1;
}

static int sip_worker_process_packets(openli_sip_worker_t *sipworker) {
    openli_state_update_t recvd;
    int rc;

    do {
        rc = zmq_recv(sipworker->zmq_colthread_recvsock, &recvd, sizeof(recvd),
                ZMQ_DONTWAIT);
        if (rc < 0) {
            if (errno == EAGAIN) {
                return 0;
            }
            logger(LOG_INFO,
                    "OpenLI: error while receiving packet in SIP worker thread %d: %s",
                    sipworker->workerid, strerror(errno));
            return -1;
        }

        if (recvd.type == OPENLI_UPDATE_HELLO) {
            /* Push all interceptable RTP streams back to the sender */
            voipintercept_t *v;
            for (v = sipworker->voipintercepts; v != NULL;
                    v = v->hh_liid.next) {
                sip_worker_push_all_active_voipstreams(sipworker,
                        recvd.data.replyq, v);
            }
        } else if (recvd.type == OPENLI_UPDATE_SIP) {
            process_received_sip_packet(sipworker, recvd.data.pkt);
        } else {
            logger(LOG_INFO,
                    "OpenLI: SIP worker thread %d received unexpected update type %u",
                    sipworker->workerid, recvd.type);
        }

    } while (rc > 0);
    return 0;
}

static int sip_worker_receive_redirect(openli_sip_worker_t *sipworker) {
    redirected_sip_message_t msg;
    int rc, r;

    do {
        rc = zmq_recv(sipworker->zmq_redirect_insock, &msg, sizeof(msg),
                ZMQ_DONTWAIT);
        if (rc < 0) {
            if (errno == EAGAIN) {
                return 0;
            }
            logger(LOG_INFO,
                    "OpenLI: error while receiving redirection message in SIP worker thread %d: %s",
                    sipworker->workerid, strerror(errno));
            return -1;
        }

        switch (msg.message_type) {
            case REDIRECTED_SIP_PACKET:
                if ((r = handle_sip_redirection_packet(sipworker, &msg)) < 0) {
                    return -1;
                }
                if (r != 0) {
                    uint32_t i;
                    for (i = 0; i < msg.pkt_cnt; i++) {
                        process_received_sip_packet(sipworker, msg.packets[i]);
                        msg.packets[i] = NULL;
                    }
                }

                break;
            case REDIRECTED_SIP_CLAIM:
                if (handle_sip_redirection_claim(sipworker, msg.callid,
                            msg.sender) < 0) {
                    return -1;
                }
                break;
            case REDIRECTED_SIP_REJECTED:
                if (handle_sip_redirection_reject(sipworker, msg.callid,
                            msg.sender) < 0) {
                    return -1;
                }
                break;
            case REDIRECTED_SIP_OVER:
                if (handle_sip_redirection_over(sipworker, msg.callid) < 0) {
                    return -1;
                }
                break;
            case REDIRECTED_SIP_PURGE:
                if (handle_sip_redirection_purge(sipworker, msg.callid) < 0) {
                    return -1;
                }
                break;
        }
        destroy_redirected_message(&msg);

    } while (rc > 0);

    return 0;
}

static void sip_worker_main(openli_sip_worker_t *sipworker) {

    sync_epoll_t purgetimer;
    zmq_pollitem_t *topoll;
    size_t topoll_size, topoll_cnt, i;
    struct itimerspec its;
    struct rtpstreaminf **expiringstreams;
    int x, rc;

    topoll = calloc(128, sizeof(zmq_pollitem_t));
    expiringstreams = calloc(128, sizeof(struct rtpstreaminf *));
    topoll_size = 128;

    its.it_value.tv_sec = 60;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;

    purgetimer.fdtype = 0;
    purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(purgetimer.fd, 0, &its, NULL);

    while (1) {
        topoll_cnt = setup_pollset(sipworker, &topoll, &topoll_size,
                purgetimer.fd, &expiringstreams);

        if (topoll_cnt < 1) {
            break;
        }
        rc = zmq_poll(topoll, topoll_cnt, 50);
        if (rc < 0) {
            logger(LOG_INFO,
                    "OpenLI: error in zmq_poll in SIP worker %d: %s",
                    sipworker->workerid, strerror(errno));
            break;
        }

        /* halt RTP streams for calls that have been over long enough --
         * topoll[3 .. N]
         */
        for (i = 4; i < topoll_cnt; i++) {
            if (topoll[i].revents & ZMQ_POLLIN) {
                halt_expired_rtpstream(sipworker, expiringstreams[i]);
            }
        }

        /* handle any messages from the sync thread -- topoll[0] */
        if (topoll[0].revents & ZMQ_POLLIN) {
            x = sip_worker_process_sync_thread_message(sipworker);
            if (x < 0) {
                break;
            }
            topoll[0].revents = 0;
        }

        /* process SIP packets received from the packet processing threads --
         * topoll[1]
         */
        if (topoll[1].revents & ZMQ_POLLIN) {
            x = sip_worker_process_packets(sipworker);
            if (x < 0) {
                break;
            }
            topoll[1].revents = 0;
        }

        /* purge any SMS-only sessions that have been idle for a while --
         * topoll[2] timer
         */
        if (topoll[2].revents & ZMQ_POLLIN) {
            topoll[2].revents = 0;
            close(topoll[2].fd);

            purge_old_sms_sessions(sipworker);

            /* also purge any "redirected to other worker" calls that have
             * not been claimed and have been idle for some time
             */
            purge_redirected_sip_calls(sipworker);

            /* reset the timer */
            purgetimer.fdtype = 0;
            purgetimer.fd = timerfd_create(CLOCK_MONOTONIC, 0);
            timerfd_settime(purgetimer.fd, 0, &its, NULL);
            topoll[2].fd = purgetimer.fd;
        }

        if (topoll[3].revents & ZMQ_POLLIN) {
            x = sip_worker_receive_redirect(sipworker);
            if (x < 0) {
                break;
            }

            topoll[3].revents = 0;
        }

    }
    free(topoll);
    free(expiringstreams);
}

void create_sip_ipmmiri(openli_sip_worker_t *sipworker,
        voipintercept_t *vint, openli_export_recv_t *irimsg,
        etsili_iri_type_t iritype, int64_t cin, openli_location_t *loc,
        int loc_count, libtrace_packet_t **pkts, int pkt_cnt) {

    openli_export_recv_t *copy;

    if (vint->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_CCONLY) {
        return;
    }

    if (vint->common.tostart_time > irimsg->ts.tv_sec) {
        return;
    }

    if (vint->common.toend_time > 0 &&
            vint->common.toend_time <= irimsg->ts.tv_sec) {
        return;
    }

    if (vint->common.targetagency == NULL ||
            strcmp(vint->common.targetagency, "pcapdisk") == 0) {
        int i;
        if (pkts == NULL) {
            return;
        }
        for (i = 0; i < pkt_cnt; i++) {
            if (pkts[i] == NULL) {
                continue;
            }
            copy = create_rawip_iri_job(vint->common.liid, vint->common.destid,
                pkts[i]);
            publish_openli_msg(
                    sipworker->zmq_pubsocks[vint->common.seqtrackerid],
                    copy);
        }
        return;
    }
    /* TODO consider recycling IRI messages like we do with IPCCs */

    /* Wrap this packet up in an IRI and forward it on to the exporter.
     * irimsg may be used multiple times, so make a copy and forward
     * that instead. */
    copy = calloc(1, sizeof(openli_export_recv_t));
    memcpy(copy, irimsg, sizeof(openli_export_recv_t));

    copy->data.ipmmiri.liid = strdup(vint->common.liid);
    copy->destid = vint->common.destid;
    copy->data.ipmmiri.iritype = iritype;
    copy->data.ipmmiri.cin = cin;

    copy->data.ipmmiri.content = malloc(copy->data.ipmmiri.contentlen);
    memcpy(copy->data.ipmmiri.content, irimsg->data.ipmmiri.content,
            irimsg->data.ipmmiri.contentlen);
    copy_location_into_ipmmiri_job(copy, loc, loc_count);

    pthread_mutex_lock(sipworker->stats_mutex);
    sipworker->stats->ipmmiri_created ++;
    pthread_mutex_unlock(sipworker->stats_mutex);
    publish_openli_msg(sipworker->zmq_pubsocks[vint->common.seqtrackerid],
            copy);
}


void *start_sip_worker_thread(void *arg) {
    openli_sip_worker_t *sipworker = (openli_sip_worker_t *)arg;
    int x;
    openli_state_update_t recvd;
    struct timeval tv;

    sipworker->redir_data.redirections = NULL;
    sipworker->redir_data.recvd_redirections = NULL;

    logger(LOG_INFO, "OpenLI: starting SIP processing thread %d",
            sipworker->workerid);
    if (setup_zmq_sockets(sipworker) < 0) {
        goto haltsipworker;
    }

    gettimeofday(&tv, NULL);
    sipworker->started = tv.tv_sec;
    sip_worker_main(sipworker);

    do {
        /* drain any remaining captured packets in the receive queue */
        x = zmq_recv(sipworker->zmq_colthread_recvsock, &recvd,
                sizeof(recvd), ZMQ_DONTWAIT);
        if (x > 0) {
            trace_destroy_packet(recvd.data.pkt);
        }
    } while (x > 0);

haltsipworker:
    logger(LOG_INFO, "OpenLI: halting SIP processing thread %d",
            sipworker->workerid);
    destroy_sip_worker_thread(sipworker);
    pthread_exit(NULL);
}
