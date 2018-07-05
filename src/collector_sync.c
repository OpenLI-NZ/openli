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

#include "etsili_core.h"
#include "collector.h"
#include "collector_sync.h"
#include "collector_sync_voip.h"
#include "collector_export.h"
#include "configparser.h"
#include "logger.h"
#include "intercept.h"
#include "netcomms.h"
#include "util.h"
#include "ipmmiri.h"

collector_sync_t *init_sync_data(collector_global_t *glob) {

	collector_sync_t *sync = (collector_sync_t *)
			malloc(sizeof(collector_sync_t));

    sync->glob = &(glob->syncip);
    sync->intersyncq = &(glob->intersyncq);
    sync->allusers = NULL;
    sync->ipintercepts = NULL;
    sync->userintercepts = NULL;
    sync->coreservers = NULL;
    sync->instruct_fd = -1;
    sync->instruct_fail = 0;
    sync->ii_ev = (sync_epoll_t *)malloc(sizeof(sync_epoll_t));
    sync->exportqueues = create_export_queue_set(glob->exportthreads);
    sync->export_used = (uint8_t *)malloc(sizeof(uint8_t) * glob->exportthreads);

    sync->outgoing = NULL;
    sync->incoming = NULL;
    sync->info = &(glob->sharedinfo);

    sync->radiusplugin = init_access_plugin(ACCESS_RADIUS);
    sync->freegenerics = NULL;
    return sync;

}

void clean_sync_data(collector_sync_t *sync) {

    int i = 0;

	if (sync->instruct_fd != -1) {
		close(sync->instruct_fd);
        sync->instruct_fd = -1;
	}

    if (sync->export_used) {
        free(sync->export_used);
    }

    free_export_queue_set(sync->exportqueues);
    free_all_users(sync->allusers);
    clear_user_intercept_list(sync->userintercepts);
    free_all_ipintercepts(&(sync->ipintercepts));
    free_coreserver_list(sync->coreservers);

    if (sync->outgoing) {
        destroy_net_buffer(sync->outgoing);
    }

    if (sync->incoming) {
        destroy_net_buffer(sync->incoming);
    }

    if (sync->ii_ev) {
        free(sync->ii_ev);
    }

    if (sync->radiusplugin) {
        destroy_access_plugin(sync->radiusplugin);
    }

    if (sync->freegenerics) {
        free_etsili_generics(sync->freegenerics);
    }

    sync->allusers = NULL;
    sync->ipintercepts = NULL;
    sync->userintercepts = NULL;
    sync->outgoing = NULL;
    sync->incoming = NULL;
    sync->ii_ev = NULL;
    sync->radiusplugin = NULL;

}

static int forward_provmsg_to_voipsync(collector_sync_t *sync,
        uint8_t *provmsg, uint16_t msglen, openli_proto_msgtype_t msgtype) {

    openli_intersync_msg_t topush;

    topush.msgtype = msgtype;
    topush.msgbody = (uint8_t *)malloc(msglen);
    memcpy(topush.msgbody, provmsg, msglen);
    topush.msglen = msglen;

    libtrace_message_queue_put(sync->intersyncq, &topush);
    return 0;

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

static inline void push_static_iprange_to_collectors(
        libtrace_message_queue_t *q, ipintercept_t *ipint,
        static_ipranges_t *ipr) {

    openli_pushed_t msg;
    staticipsession_t *staticsess = NULL;

    if (ipr->liid == NULL || ipr->rangestr == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: attempted to send invalid static IP range to collectors");
        return;
    }

    staticsess = create_staticipsession(ipint, ipr->rangestr, ipr->cin);

    memset(&msg, 0, sizeof(openli_pushed_t));
    msg.type = OPENLI_PUSH_IPRANGE;
    msg.data.iprange = staticsess;

    libtrace_message_queue_put(q, (void *)(&msg));

}

static inline void push_static_iprange_remove_to_collectors(
        libtrace_message_queue_t *q, ipintercept_t *ipint,
        static_ipranges_t *ipr) {

    openli_pushed_t msg;
    staticipsession_t *staticsess = NULL;

    if (ipr->liid == NULL || ipr->rangestr == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: attempted to send invalid static IP range to collectors");
        return;
    }

    staticsess = create_staticipsession(ipint, ipr->rangestr, ipr->cin);
    memset(&msg, 0, sizeof(openli_pushed_t));
    msg.type = OPENLI_PUSH_REMOVE_IPRANGE;
    msg.data.iprange = staticsess;

    libtrace_message_queue_put(q, (void *)(&msg));

}

static inline void push_single_ipintercept(libtrace_message_queue_t *q,
        ipintercept_t *ipint, access_session_t *session) {

    ipsession_t *ipsess;
    openli_pushed_t msg;

    /* No assigned IP, session is not fully active yet. Don't push yet */
    if (session->assignedip == NULL) {
        return;
    }

    ipsess = create_ipsession(ipint, session->cin, session->ipfamily,
            session->assignedip);

    if (!ipsess) {
        logger(LOG_DAEMON,
                "OpenLI: ran out of memory while creating IP session message.");
        return;
    }
    memset(&msg, 0, sizeof(openli_pushed_t));
    msg.type = OPENLI_PUSH_IPINTERCEPT;
    msg.data.ipsess = ipsess;

    libtrace_message_queue_put(q, (void *)(&msg));
}

static inline void push_single_alushimid(libtrace_message_queue_t *q,
        ipintercept_t *ipint, uint32_t sesscin) {

    aluintercept_t *alu;
    openli_pushed_t msg;

    if (ipint->alushimid == OPENLI_ALUSHIM_NONE) {
        return;
    }

    alu = create_aluintercept(ipint);
    if (!alu) {
        logger(LOG_DAEMON,
                "OpenLI: ran out of memory while creating ALU intercept message.");
        return;
    }
    alu->cin = sesscin;

    memset(&msg, 0, sizeof(openli_pushed_t));
    msg.type = OPENLI_PUSH_ALUINTERCEPT;
    msg.data.aluint = alu;

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
    struct epoll_event ev;

    ret = transmit_net_buffer(sync->outgoing);
    if (ret == -1) {
        /* Something went wrong */
        logger(LOG_DAEMON,
                "OpenLI: error sending message from collector to provisioner.");
        return -1;
    }

    if (ret == 0) {
        /* Everything has been sent successfully, no more to send right now. */
        ev.data.ptr = sync->ii_ev;
        ev.events = EPOLLIN | EPOLLRDHUP;

        if (epoll_ctl(sync->glob->epoll_fd, EPOLL_CTL_MOD,
                    sync->instruct_fd, &ev) == -1) {
            logger(LOG_DAEMON,
                    "OpenLI: error disabling EPOLLOUT on provisioner fd: %s.",
                    strerror(errno));
            return -1;
        }
    }

    return 1;
}

static int new_staticiprange(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    static_ipranges_t *ipr, *found;
    ipintercept_t *ipint;
    sync_sendq_t *tmp, *sendq;

    ipr = (static_ipranges_t *)malloc(sizeof(static_ipranges_t));

    if (decode_staticip_announcement(intmsg, msglen, ipr) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: received invalid static IP range from provisioner.");
        free(ipr);
        return -1;
    }

    HASH_FIND(hh_liid, sync->ipintercepts, ipr->liid, strlen(ipr->liid), ipint);
    if (!ipint) {
        logger(LOG_DAEMON,
                "OpenLI: received static IP range for LIID %s, but this LIID is unknown?",
                ipr->liid);
        free(ipr);
        return -1;
    }

    HASH_FIND(hh, ipint->statics, ipr->rangestr, strlen(ipr->rangestr), found);
    if (found) {
        found->awaitingconfirm = 0;
        free(ipr->liid);
        free(ipr->rangestr);
        free(ipr);
        return 0;
    }

    HASH_ADD_KEYPTR(hh, ipint->statics, ipr->rangestr,
            strlen(ipr->rangestr), ipr);

    HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues),
            sendq, tmp) {
        push_static_iprange_to_collectors(sendq->q, ipint, ipr);
    }

    return 1;
}

static int remove_staticiprange(collector_sync_t *sync, static_ipranges_t *ipr)
{

    static_ipranges_t *found;
    ipintercept_t *ipint;
    sync_sendq_t *tmp, *sendq;


    HASH_FIND(hh_liid, sync->ipintercepts, ipr->liid, strlen(ipr->liid), ipint);
    if (!ipint) {
        logger(LOG_DAEMON,
                "OpenLI: received static IP range to remove for LIID %s, but this LIID is unknown?",
                ipr->liid);
        free(ipr);
        return -1;
    }

    HASH_FIND(hh, ipint->statics, ipr->rangestr, strlen(ipr->rangestr), found);
    if (found) {
        HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues),
                sendq, tmp) {
            push_static_iprange_remove_to_collectors(sendq->q, ipint, ipr);
        }

        HASH_DELETE(hh, ipint->statics, found);
        free(found->liid);
        free(found->rangestr);
        free(found);
    }

    return 0;
}

static inline void push_session_halt_to_threads(void *sendqs,
        access_session_t *sess, ipintercept_t *ipint) {

    sync_sendq_t *sendq, *tmp;
    char ipstr[128];

    if (sess->assignedip == NULL) {
        return;
    }

    /* XXX no error checking because this logging should not reach
     * the production version... */
    getnameinfo((struct sockaddr *)(sess->assignedip),
            (sess->ipfamily == AF_INET) ? sizeof(struct sockaddr_in) :
                sizeof(struct sockaddr_in6),
                ipstr, sizeof(ipstr), 0, 0, NI_NUMERICHOST);

    HASH_ITER(hh, (sync_sendq_t *)sendqs, sendq, tmp) {
        openli_pushed_t pmsg;
        ipsession_t *sessdup;

        memset(&pmsg, 0, sizeof(openli_pushed_t));
        pmsg.type = OPENLI_PUSH_HALT_IPINTERCEPT;
        sessdup = create_ipsession(ipint, sess->cin, sess->ipfamily,
                sess->assignedip);

        pmsg.data.ipsess = sessdup;

        libtrace_message_queue_put(sendq->q, &pmsg);

    }
}

static inline void push_ipintercept_halt_to_threads(collector_sync_t *sync,
        ipintercept_t *ipint) {

    sync_sendq_t *sendq, *tmp;
    internet_user_t *user;
    access_session_t *sess, *tmp2;
    static_ipranges_t *ipr, *tmpr;

    logger(LOG_DAEMON, "OpenLI: collector will stop intercepting traffic for LIID %s", ipint->common.liid);

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

        push_session_halt_to_threads(sync->glob->collector_queues, sess,
                ipint);
    }

}

static void disable_unconfirmed_intercepts(collector_sync_t *sync) {
    voipintercept_t *v, *tmp2;
    coreserver_t *cs, *tmp3;
    ipintercept_t *ipint, *tmp;
    internet_user_t *user;
    static_ipranges_t *ipr, *tmpr;

    HASH_ITER(hh_liid, sync->ipintercepts, ipint, tmp) {

        if (ipint->awaitingconfirm) {

            /* Tell every collector thread to stop intercepting traffic for
             * the IPs associated with this target. */
            push_ipintercept_halt_to_threads(sync, ipint);
            HASH_DELETE(hh_liid, sync->ipintercepts, ipint);
            if (ipint->username) {
                remove_intercept_from_user_intercept_list(&sync->userintercepts,
                        ipint);
            }
            free_single_ipintercept(ipint);
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
            logger(LOG_DAEMON,
                    "OpenLI: collector has removed %s from its %s core server list.",
                    cs->serverkey, coreserver_type_to_string(cs->servertype));
            HASH_DELETE(hh, sync->coreservers, cs);
            free_single_coreserver(cs);
        }
    }
}

static int new_mediator(collector_sync_t *sync, uint8_t *provmsg,
        uint16_t msglen) {

    int i;
    openli_mediator_t med;
    openli_export_recv_t expmsg;

    if (decode_mediator_announcement(provmsg, msglen, &med) == -1) {
        logger(LOG_DAEMON, "OpenLI: received invalid mediator announcement from provisioner.");
        return -1;
    }

    for (i = 0; i < sync->exportqueues->numqueues; i++) {
        memset(&expmsg, 0, sizeof(openli_export_recv_t));
        expmsg.type = OPENLI_EXPORT_MEDIATOR;
        expmsg.data.med.ipstr = strdup(med.ipstr);
        expmsg.data.med.portstr = strdup(med.portstr);
        expmsg.data.med.mediatorid = med.mediatorid;
        export_queue_put_by_queueid(sync->exportqueues, &expmsg, i);
    }
    free(med.ipstr);
    free(med.portstr);
    return 0;
}

static int remove_mediator(collector_sync_t *sync, uint8_t *provmsg,
        uint16_t msglen) {

    int i;
    openli_mediator_t med;
    openli_export_recv_t expmsg;

    if (decode_mediator_withdraw(provmsg, msglen, &med) == -1) {
        logger(LOG_DAEMON, "OpenLI: received invalid mediator withdrawal from provisioner.");
        return -1;
    }

    for (i = 0; i < sync->exportqueues->numqueues; i++) {
        memset(&expmsg, 0, sizeof(openli_export_recv_t));
        expmsg.type = OPENLI_EXPORT_DROP_SINGLE_MEDIATOR;
        expmsg.data.med.mediatorid = med.mediatorid;
        expmsg.data.med.ipstr = NULL;
        expmsg.data.med.portstr = NULL;

        export_queue_put_by_queueid(sync->exportqueues, &expmsg, i);
    }
    free(med.ipstr);
    free(med.portstr);
    return 0;
}


static int forward_new_coreserver(collector_sync_t *sync, uint8_t *provmsg,
        uint16_t msglen) {
    coreserver_t *cs, *found;

    cs = (coreserver_t *)calloc(1, sizeof(coreserver_t));

    if (decode_coreserver_announcement(provmsg, msglen, cs) == -1) {
        logger(LOG_DAEMON, "OpenLI: received invalid core server announcement from provisioner.");
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
        logger(LOG_DAEMON,
                "OpenLI: collector has added %s to its %s core server list.",
                cs->serverkey, coreserver_type_to_string(cs->servertype));
    }
    return 0;
}

static int forward_remove_coreserver(collector_sync_t *sync, uint8_t *provmsg,
        uint16_t msglen) {

    coreserver_t *cs, *found;

    cs = (coreserver_t *)calloc(1, sizeof(coreserver_t));
    if (decode_coreserver_withdraw(provmsg, msglen, cs) == -1) {
        logger(LOG_DAEMON, "OpenLI: received invalid core server withdrawal from provisioner.");
        free_single_coreserver(cs);
        return -1;
    }

    HASH_FIND(hh, sync->coreservers, cs->serverkey, strlen(cs->serverkey),
            found);
    if (!found) {
        logger(LOG_DAEMON, "OpenLI sync: asked to remove %s server %s, but we don't have any record of it?",
                coreserver_type_to_string(cs->servertype), cs->serverkey);
    } else {
        push_coreserver_msg(sync, cs, OPENLI_PUSH_REMOVE_CORESERVER);
        logger(LOG_DAEMON,
                "OpenLI: collector has removed %s from its %s core server list.",
                cs->serverkey, coreserver_type_to_string(cs->servertype));
        HASH_DELETE(hh, sync->coreservers, found);
        free_single_coreserver(found);
    }
    free_single_coreserver(cs);
    return 0;
}

static void remove_ip_intercept(collector_sync_t *sync, ipintercept_t *ipint) {

    if (!ipint) {
        logger(LOG_DAEMON,
                "OpenLI: received withdrawal for IP intercept %s but it is not present in the sync intercept list?",
                ipint->common.liid);
        return;
    }

    push_ipintercept_halt_to_threads(sync, ipint);
    HASH_DELETE(hh_liid, sync->ipintercepts, ipint);
    if (ipint->username) {
        remove_intercept_from_user_intercept_list(&sync->userintercepts, ipint);
    }
    free_single_ipintercept(ipint);

}

static int halt_ipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    ipintercept_t *ipint, torem;
    sync_sendq_t *sendq, *tmp;
    int i;
    openli_export_recv_t expmsg;

    memset(&expmsg, 0, sizeof(openli_export_recv_t));

    if (decode_ipintercept_halt(intmsg, msglen, &torem) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: received invalid IP intercept withdrawal from provisioner.");
        return -1;
    }

    HASH_FIND(hh_liid, sync->ipintercepts, torem.common.liid,
            torem.common.liid_len, ipint);

    for (i = 0; i < sync->exportqueues->numqueues; i++) {
        expmsg.type = OPENLI_EXPORT_INTERCEPT_OVER;
        expmsg.data.cept = (exporter_intercept_msg_t *)malloc(
                sizeof(exporter_intercept_msg_t));
        expmsg.data.cept->liid = strdup(ipint->common.liid);
        expmsg.data.cept->authcc = strdup(ipint->common.authcc);
        expmsg.data.cept->delivcc = strdup(ipint->common.delivcc);
        expmsg.data.cept->liid_len = ipint->common.liid_len;
        expmsg.data.cept->authcc_len = ipint->common.authcc_len;
        expmsg.data.cept->delivcc_len = ipint->common.delivcc_len;

        export_queue_put_by_queueid(sync->exportqueues, &expmsg, i);
    }
    remove_ip_intercept(sync, ipint);

    return 0;
}

static inline void drop_all_mediators(collector_sync_t *sync) {
    openli_export_recv_t expmsg;

    memset(&expmsg, 0, sizeof(openli_export_recv_t));
    expmsg.type = OPENLI_EXPORT_DROP_ALL_MEDIATORS;
    expmsg.data.packet = NULL;
    export_queue_put_all(sync->exportqueues, &expmsg);
}

static int new_ipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    ipintercept_t *cept, *x;
    sync_sendq_t *tmp, *sendq;
    internet_user_t *user;
    openli_export_recv_t expmsg;
    int i;

    memset(&expmsg, 0, sizeof(openli_export_recv_t));

    cept = (ipintercept_t *)malloc(sizeof(ipintercept_t));
    if (decode_ipintercept_start(intmsg, msglen, cept) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: received invalid IP intercept from provisioner.");
        free(cept);
        return -1;
    }

    /* Check if we already have this intercept */
    HASH_FIND(hh_liid, sync->ipintercepts, cept->common.liid,
            cept->common.liid_len, x);

    /* TODO change alushimid and username to not be mutually exclusive.
     * Ideally, username would be mandatory even for ALU intercepts as we
     * still will need to produce IRIs for those targets from AAA traffic.
     * We can also use the AAA stream to assign CINs for the CCs created from
     * the ALU intercepted packets, so really this still needs a lot of proper
     * sync work.
     *
     * Therefore, we'll want to only announce ALU Shim IDs once we have a
     * valid session for the user and withdraw them once the session is over.
     */

    if (x) {
        /* Duplicate LIID */

        /* OpenLI-internal fields that could change value
         * if the provisioner was restarted.
         */
        if (x->username && cept->username) {
            if (strcmp(x->username, cept->username) != 0) {
                logger(LOG_DAEMON,
                        "OpenLI: duplicate IP ID %s seen, but targets are different (was %s, now %s).",
                        x->common.liid, x->username, cept->username);
                free(cept);
                return -1;
            }
        } else if (cept->alushimid != x->alushimid) {
            logger(LOG_DAEMON,
                    "OpenLI: duplicate IP ID %s seen, but ALU intercept IDs are different (was %u, now %u).",
                    x->common.liid, x->alushimid, cept->alushimid);
            free(cept);
            return -1;
        }

        if (cept->accesstype != x->accesstype) {
            logger(LOG_DAEMON,
                    "OpenLI: duplicate IP ID %s seen, but access type has changed to %s.", x->common.liid, accesstype_to_string(cept->accesstype));
            /* Only affects IRIs so don't need to modify collector threads */
            x->accesstype = cept->accesstype;
        }
        x->awaitingconfirm = 0;
        free(cept);
        /* our collector threads should already know about this intercept */
        return 0;
    }

    if (cept->username) {
        HASH_FIND(hh, sync->allusers, cept->username, cept->username_len, user);

        if (user) {
            access_session_t *sess, *tmp2;
            HASH_ITER(hh, user->sessions, sess, tmp2) {
                HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues),
                        sendq, tmp) {
                    push_single_ipintercept(sendq->q, cept, sess);
                }
            }
        }
        add_intercept_to_user_intercept_list(&sync->userintercepts, cept);
    }

    if (cept->alushimid != OPENLI_ALUSHIM_NONE) {
        logger(LOG_DAEMON,
                "OpenLI: received IP intercept from provisioner for ALU shim ID %u (LIID %s, authCC %s)",
                cept->alushimid, cept->common.liid, cept->common.authcc);

        /* Don't need to wait for a session to start an ALU intercept.
         * The CIN is contained within the packet and only valid
         * interceptable packets should have the intercept ID we're
         * looking for.
         *
         * TODO allow config that will force us to wait for a session
         * instead, i.e. if the ALU is configured to NOT set the session
         * ID in the shim.
         */
        HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues),
                sendq, tmp) {
            push_single_alushimid(sendq->q, cept, 0);
        }
    } else {
        logger(LOG_DAEMON,
                "OpenLI: received IP intercept from provisioner (LIID %s, authCC %s)",
                cept->common.liid, cept->common.authcc);
    }

    HASH_ADD_KEYPTR(hh_liid, sync->ipintercepts, cept->common.liid,
            cept->common.liid_len, cept);

    for (i = 0; i < sync->exportqueues->numqueues; i++) {
        expmsg.type = OPENLI_EXPORT_INTERCEPT_DETAILS;
        expmsg.data.cept = (exporter_intercept_msg_t *)malloc(
                sizeof(exporter_intercept_msg_t));
        expmsg.data.cept->liid = strdup(cept->common.liid);
        expmsg.data.cept->authcc = strdup(cept->common.authcc);
        expmsg.data.cept->delivcc = strdup(cept->common.delivcc);
        expmsg.data.cept->liid_len = cept->common.liid_len;
        expmsg.data.cept->authcc_len = cept->common.authcc_len;
        expmsg.data.cept->delivcc_len = cept->common.delivcc_len;

        export_queue_put_by_queueid(sync->exportqueues, &expmsg, i);
    }

    return 0;

}

static int recv_from_provisioner(collector_sync_t *sync) {
    struct epoll_event ev;
    int ret = 0;
    uint8_t *provmsg;
    uint16_t msglen = 0;
    uint64_t intid = 0;
    static_ipranges_t *ipr;
    openli_proto_msgtype_t msgtype;

    do {
        msgtype = receive_net_buffer(sync->incoming, &provmsg, &msglen, &intid);
        switch(msgtype) {
            case OPENLI_PROTO_DISCONNECT:
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_DISCONNECT_MEDIATORS:
                drop_all_mediators(sync);
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
            case OPENLI_PROTO_REMOVE_STATICIPS:
                ipr = (static_ipranges_t *)malloc(sizeof(static_ipranges_t));

                if (decode_staticip_removal(provmsg, msglen, ipr) == -1) {
                    logger(LOG_DAEMON,
                            "OpenLI: received invalid static IP range from provisioner for removal.");
                    free(ipr);
                    return -1;
                }
                ret = remove_staticiprange(sync, ipr);
                if (ret == -1) {
                    return -1;
                }
                free(ipr->liid);
                free(ipr->rangestr);
                free(ipr);
                break;
            case OPENLI_PROTO_HALT_IPINTERCEPT:
                ret = halt_ipintercept(sync, provmsg, msglen);
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
            case OPENLI_PROTO_START_VOIPINTERCEPT:
            case OPENLI_PROTO_HALT_VOIPINTERCEPT:
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
                forward_provmsg_to_voipsync(sync, provmsg, msglen, msgtype);
                break;
        }

    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    return 1;
}

int sync_connect_provisioner(collector_sync_t *sync) {

    struct epoll_event ev;
    int sockfd;


    sockfd = connect_socket(sync->info->provisionerip,
            sync->info->provisionerport, sync->instruct_fail);

    if (sockfd == -1) {
        return -1;
    }

    if (sockfd == 0) {
        sync->instruct_fail = 1;
        return 0;
    }

    sync->instruct_fail = 0;
    sync->instruct_fd = sockfd;

    assert(sync->outgoing == NULL && sync->incoming == NULL);

    sync->outgoing = create_net_buffer(NETBUF_SEND, sync->instruct_fd);
    sync->incoming = create_net_buffer(NETBUF_RECV, sync->instruct_fd);

    /* Put our auth message onto the outgoing buffer */
    if (push_auth_onto_net_buffer(sync->outgoing, OPENLI_PROTO_COLLECTOR_AUTH)
            < 0) {
        logger(LOG_DAEMON,"OpenLI: collector is unable to queue auth message.");
        return -1;
    }

    /* Add instruct_fd to epoll for both reading and writing */
    sync->ii_ev->fdtype = SYNC_EVENT_PROVISIONER;
    sync->ii_ev->fd = sync->instruct_fd;
    sync->ii_ev->ptr = NULL;

    ev.data.ptr = (void *)(sync->ii_ev);
    ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;

    if (epoll_ctl(sync->glob->epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        /* TODO Do something? */
        logger(LOG_DAEMON, "OpenLI: failed to register provisioner fd: %s",
                strerror(errno));
        return -1;
    }

    return 1;

}

static inline void touch_all_coreservers(coreserver_t *servers) {
    coreserver_t *cs, *tmp;

    HASH_ITER(hh, servers, cs, tmp) {
        cs->awaitingconfirm = 1;
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

void sync_disconnect_provisioner(collector_sync_t *sync) {

    struct epoll_event ev;
    openli_export_recv_t expmsg;

    destroy_net_buffer(sync->outgoing);
    destroy_net_buffer(sync->incoming);

    sync->outgoing = NULL;
    sync->incoming = NULL;

    if (sync->instruct_fd != -1) {
        if (epoll_ctl(sync->glob->epoll_fd, EPOLL_CTL_DEL,
                sync->instruct_fd, &ev) == -1) {
            logger(LOG_DAEMON,
                    "OpenLI: error de-registering provisioner fd: %s.",
                    strerror(errno));
        }
        close(sync->instruct_fd);
        sync->instruct_fd = -1;
    }

    /* Leave all intercepts running, but require them to be confirmed
     * as active when we reconnect to the provisioner.
     */
    touch_all_intercepts(sync->ipintercepts);
    touch_all_coreservers(sync->coreservers);

    /* Tell other sync thread to flag its intercepts too */
    forward_provmsg_to_voipsync(sync, NULL, 0, OPENLI_PROTO_DISCONNECT);

    /* Same with mediators -- keep exporting to them, but flag them to be
     * disconnected if they are not announced after we reconnect. */
    memset(&expmsg, 0, sizeof(openli_export_recv_t));
    expmsg.type = OPENLI_EXPORT_FLAG_MEDIATORS;
    expmsg.data.packet = NULL;

    export_queue_put_all(sync->exportqueues, &expmsg);


}

static void push_all_active_intercepts(internet_user_t *allusers,
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
                    push_single_ipintercept(q, orig, sess);
                }
            }
        }
        if (orig->alushimid != OPENLI_ALUSHIM_NONE) {
            push_single_alushimid(q, orig, 0);
        }
        HASH_ITER(hh, orig->statics, ipr, tmpr) {
            push_static_iprange_to_collectors(q, orig, ipr);
        }
    }
}


static int update_user_sessions(collector_sync_t *sync, libtrace_packet_t *pkt,
        uint8_t accesstype) {

    access_plugin_t *p = NULL;
    char *userid;
    internet_user_t *iuser;
    access_session_t *sess;
    access_action_t accessaction;
    session_state_t oldstate, newstate;
    user_intercept_list_t *userint;
    ipintercept_t *ipint, *tmp;
    openli_export_recv_t msg;
    sync_sendq_t *sendq, *tmpq;
    int expcount = 0;
    void *parseddata = NULL;
    int i;

    if (accesstype == ACCESS_RADIUS) {
        p = sync->radiusplugin;
    }

    if (!p) {
        logger(LOG_DAEMON, "OpenLI: tried to update user sessions using an unsupported access type: %u", accesstype);
        return -1;
    }

    parseddata = p->process_packet(p, pkt);

    if (parseddata == NULL) {
        logger(LOG_DAEMON, "OpenLI: unable to parse %s packet", p->name);
        return -1;
    }

    userid = p->get_userid(p, parseddata);
    if (userid == NULL) {
        /* Probably an orphaned response packet */
        goto endupdate;
    }

    HASH_FIND(hh, sync->allusers, userid, strlen(userid), iuser);
    if (iuser == NULL) {
        iuser = (internet_user_t *)malloc(sizeof(internet_user_t));

        if (!iuser) {
            logger(LOG_DAEMON, "OpenLI: unable to allocate memory for new Internet user");
            p->destroy_parsed_data(p, parseddata);
            return -1;
        }
        iuser->userid = strdup(userid);
        iuser->sessions = NULL;

        HASH_ADD_KEYPTR(hh, sync->allusers, iuser->userid,
                strlen(iuser->userid), iuser);
    }

    sess = p->update_session_state(p, parseddata, &(iuser->sessions), &oldstate,
            &newstate, &accessaction);
    if (!sess) {
        logger(LOG_DAEMON, "OpenLI: error while assigning packet to a Internet access session");
        p->destroy_parsed_data(p, parseddata);
        return -1;
    }

    /* TODO keep track of ip->user mappings so that we can recognise when
     * an IP has been re-assigned silently.
     *
     * In this case, we want to find and withdraw any intercepts for the
     * old owner.
     */

    HASH_FIND(hh, sync->userintercepts, userid, strlen(userid), userint);

    if (oldstate != newstate) {
        if (userint && newstate == SESSION_STATE_ACTIVE) {
            /* Session has been confirmed, time to start intercepting
             * packets involving the session IP.
             */
            HASH_ITER(hh_user, userint->intlist, ipint, tmp) {
                HASH_ITER(hh, (sync_sendq_t *)(sync->glob->collector_queues),
                        sendq, tmpq) {
                    push_single_ipintercept(sendq->q, ipint, sess);
                }
            }

        } else if (newstate == SESSION_STATE_OVER) {
            /* If this was an active intercept, tell our threads to
             * stop intercepting traffic for this session */
            if (userint) {
                HASH_ITER(hh_user, userint->intlist, ipint, tmp) {
                    push_session_halt_to_threads(sync->glob->collector_queues,
                            sess, ipint);
                }
            }
        }
    }

    memset(sync->export_used, 0, sizeof(uint8_t) *
            sync->exportqueues->numqueues);

    if (userint && accessaction != ACCESS_ACTION_NONE) {
        HASH_ITER(hh_user, userint->intlist, ipint, tmp) {
            openli_export_recv_t irimsg;
            int queueused = 0;

            memset(&irimsg, 0, sizeof(irimsg));
            irimsg.type = OPENLI_EXPORT_IPIRI;
            irimsg.destid = ipint->common.destid;
            irimsg.data.ipiri.liid = strdup(ipint->common.liid);
            irimsg.data.ipiri.plugin = p;
            irimsg.data.ipiri.plugin_data = parseddata;
            irimsg.data.ipiri.access_tech = ipint->accesstype;
            irimsg.data.ipiri.cin = sess->cin;
            irimsg.data.ipiri.colinfo = sync->info;
            irimsg.data.ipiri.username = strdup(ipint->username);
            if (irimsg.data.ipiri.ipfamily) {
                irimsg.data.ipiri.sessionstartts = sess->started;
                irimsg.data.ipiri.ipfamily = sess->ipfamily;
                memcpy(&(irimsg.data.ipiri.assignedip), sess->assignedip,
                        (sess->ipfamily == AF_INET) ?
                                sizeof(struct sockaddr_in) :
                                sizeof(struct sockaddr_in6));
            } else {
                irimsg.data.ipiri.ipfamily = 0;
                irimsg.data.ipiri.sessionstartts.tv_sec = 0;
                irimsg.data.ipiri.sessionstartts.tv_usec = 0;
                memset(&(irimsg.data.ipiri.assignedip), 0,
                        sizeof(struct sockaddr_storage));
            }


            queueused = export_queue_put_by_liid(sync->exportqueues, &irimsg,
                    ipint->common.liid);
            sync->export_used[queueused] = 1;
            expcount ++;
        }
        p->uncouple_parsed_data(p);
        parseddata = NULL;
    }

    if (oldstate != newstate && newstate == SESSION_STATE_OVER) {
        free_single_session(iuser, sess);
    }

endupdate:
    if (parseddata) {
        p->destroy_parsed_data(p, parseddata);
    }

    if (expcount == 0) {
        return 0;
    }

    memset(&msg, 0, sizeof(openli_export_recv_t));
    msg.type = OPENLI_EXPORT_PACKET_FIN;
    msg.data.packet = pkt;
    
    trace_increment_packet_refcount(pkt);
    for (i = 0; i < sync->exportqueues->numqueues; i++) {
        if (sync->export_used[i] == 0) {
            continue;
        }

        /* Increment ref count for the packet and send a packet fin message
         * so the exporter knows when to decrease the ref count */
        trace_increment_packet_refcount(pkt);
        export_queue_put_by_queueid(sync->exportqueues, (&msg), i);
    }
    trace_decrement_packet_refcount(pkt);
    return 1;
}

int sync_thread_main(collector_sync_t *sync) {

    int i, nfds;
    struct epoll_event evs[64];
    openli_state_update_t recvd;
    libtrace_message_queue_t *srcq = NULL;
    sync_epoll_t *syncev;

    nfds = epoll_wait(sync->glob->epoll_fd, evs, 64, 50);

    if (nfds <= 0) {
        return nfds;
    }

    for (i = 0; i < nfds; i++) {
        syncev = (sync_epoll_t *)(evs[i].data.ptr);

	    /* Check for incoming messages from processing threads and II fd */
        if ((evs[i].events & EPOLLERR) || (evs[i].events & EPOLLHUP) ||
                (evs[i].events & EPOLLRDHUP)) {
            /* Some error detection / handling? */

            /* Don't close any fds on error -- they should get closed when
             * their parent structures are tidied up */


            if (syncev->fd == sync->instruct_fd) {
                logger(LOG_DAEMON, "OpenLI: collector lost connection to central provisioner");
                sync_disconnect_provisioner(sync);
                return 0;

            } else {
                logger(LOG_DAEMON, "OpenLI: processor->sync message queue pipe has broken down.");
                epoll_ctl(sync->glob->epoll_fd, EPOLL_CTL_DEL,
                        syncev->fd, NULL);
            }

            continue;
        }

        if (syncev->fd == sync->instruct_fd) {
            /* Provisioner fd */
            if (evs[i].events & EPOLLOUT) {
                if (send_to_provisioner(sync) <= 0) {
                    sync_disconnect_provisioner(sync);
                    return 0;
                }
            } else {
                if (recv_from_provisioner(sync) <= 0) {
                    sync_disconnect_provisioner(sync);
                    return 0;
                }
            }
            continue;
        }

        /* Must be from a processing thread queue, figure out which one */
        if (libtrace_message_queue_count(
                (libtrace_message_queue_t *)(syncev->ptr)) <= 0) {

            /* Processing thread queue was empty but we thought we had a
             * message available? I think this is just a consequence of
             * libtrace MQ's "fast" path that tries to avoid locking for
             * simple operations. */
            continue;
        }

        libtrace_message_queue_get((libtrace_message_queue_t *)(syncev->ptr),
                (void *)(&recvd));

        /* If a hello from a thread, push all active intercepts back */
        if (recvd.type == OPENLI_UPDATE_HELLO) {
            push_all_active_intercepts(sync->allusers, sync->ipintercepts,
                    recvd.data.replyq);
            push_all_coreservers(sync->coreservers, recvd.data.replyq);
        }


        /* If an update from a thread, update appropriate internal state */

        /* If this resolves an unknown mapping or changes an existing one,
         * push II update messages to processing threads */

        /* If this relates to an active intercept, create IRI and export */
        if (recvd.type == OPENLI_UPDATE_RADIUS) {
            int ret;
            if ((ret = update_user_sessions(sync, recvd.data.pkt,
                        ACCESS_RADIUS)) < 0) {
                logger(LOG_DAEMON,
                        "OpenLI: sync thread received an invalid RADIUS packet");
            }

            trace_decrement_packet_refcount(recvd.data.pkt);
        }

    }

    return nfds;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
