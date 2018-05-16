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

    sync->glob = glob;
    sync->allusers = NULL;
    sync->ipintercepts = NULL;
    sync->userintercepts = NULL;
    sync->voipintercepts = NULL;
    sync->coreservers = NULL;
    sync->instruct_fd = -1;
    sync->instruct_fail = 0;
    sync->ii_ev = (sync_epoll_t *)malloc(sizeof(sync_epoll_t));

    libtrace_message_queue_init(&(sync->exportq), sizeof(openli_exportmsg_t));

    sync->outgoing = NULL;
    sync->incoming = NULL;
    sync->sipparser = NULL;
    sync->encoder = NULL;

    return sync;

}

void clean_sync_data(collector_sync_t *sync) {

    int i = 0;

	if (sync->instruct_fd != -1) {
		close(sync->instruct_fd);
        sync->instruct_fd = -1;
	}

    free_all_users(sync->allusers);
    clear_user_intercept_list(sync->userintercepts);
    free_all_ipintercepts(sync->ipintercepts);
    if (sync->voipintercepts) {
        free_all_voipintercepts(sync->voipintercepts);
    }

	libtrace_message_queue_destroy(&(sync->exportq));

    if (sync->outgoing) {
        destroy_net_buffer(sync->outgoing);
    }

    if (sync->incoming) {
        destroy_net_buffer(sync->incoming);
    }

    if (sync->ii_ev) {
        free(sync->ii_ev);
    }

    if (sync->sipparser) {
        release_sip_parser(sync->sipparser);
    }

    if (sync->encoder) {
        free_wandder_encoder(sync->encoder);
    }

    sync->allusers = NULL;
    sync->ipintercepts = NULL;
    sync->userintercepts = NULL;
    sync->voipintercepts = NULL;
    sync->outgoing = NULL;
    sync->incoming = NULL;
    sync->sipparser = NULL;
    sync->encoder = NULL;
    sync->ii_ev = NULL;
}

static inline void push_coreserver_msg(collector_sync_t *sync,
        coreserver_t *cs, uint8_t msgtype) {

    sync_sendq_t *sendq, *tmp;
    HASH_ITER(hh, (sync_sendq_t *)(sync->glob->syncsendqs), sendq, tmp) {
        openli_pushed_t msg;

        msg.type = msgtype;
        msg.data.coreserver = deep_copy_coreserver(cs);
        libtrace_message_queue_put(sendq->q, (void *)(&msg));
    }
}

static inline void push_single_ipintercept(libtrace_message_queue_t *q,
        ipintercept_t *ipint, access_session_t *session) {

    ipsession_t *sess;
    openli_pushed_t msg;

    /* No assigned IP, session is not fully active yet. Don't push yet */
    if (session->assignedip == NULL) {
        return;
    }

    sess = create_ipsession(ipint, session);

    if (!sess) {
        logger(LOG_DAEMON,
                "OpenLI: ran out of memory while creating IP session message.");
        return;
    }
    msg.type = OPENLI_PUSH_IPINTERCEPT;
    msg.data.ipsess = sess;

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

    msg.type = OPENLI_PUSH_ALUINTERCEPT;
    msg.data.aluint = alu;

    libtrace_message_queue_put(q, (void *)(&msg));
}

static inline void push_single_voipstreamintercept(libtrace_message_queue_t *q,
        rtpstreaminf_t *orig) {

    rtpstreaminf_t *copy;
    openli_pushed_t msg;

    copy = deep_copy_rtpstream(orig);
    if (!copy) {
        logger(LOG_DAEMON,
                "OpenLI: unable to copy RTP stream in sync thread.");
        return;
    }

    msg.type = OPENLI_PUSH_IPMMINTERCEPT;
    msg.data.ipmmint = copy;

    libtrace_message_queue_put(q, (void *)(&msg));
}

static void push_all_coreservers(coreserver_t *servers,
        libtrace_message_queue_t *q) {

    coreserver_t *cs, *tmp;
    HASH_ITER(hh, servers, cs, tmp) {
        openli_pushed_t msg;

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

        if (epoll_ctl(sync->glob->sync_epollfd, EPOLL_CTL_MOD,
                    sync->instruct_fd, &ev) == -1) {
            logger(LOG_DAEMON,
                    "OpenLI: error disabling EPOLLOUT on provisioner fd: %s.",
                    strerror(errno));
            return -1;
        }
    }

    return 1;
}

static void push_halt_active_voipstreams(libtrace_message_queue_t *q,
        voipintercept_t *vint, int epollfd) {

    rtpstreaminf_t *cin = NULL;
    char *streamdup;
    openli_pushed_t msg;

    if (vint->active_cins == NULL) {
        return;
    }

    for (cin = vint->active_cins; cin != NULL; cin=cin->hh.next) {
        if (cin->active == 0) {
            continue;
        }
        streamdup = strdup(cin->streamkey);
        msg.type = OPENLI_PUSH_HALT_IPMMINTERCEPT;
        msg.data.rtpstreamkey = streamdup;

        libtrace_message_queue_put(q, (void *)(&msg));

        /* If we were already about to time this intercept out, make sure
         * we kill the timer.
         */
        if (cin->timeout_ev) {
            struct epoll_event ev;
            sync_epoll_t *timerev = (sync_epoll_t *)(cin->timeout_ev);
            if (epoll_ctl(epollfd, EPOLL_CTL_DEL, timerev->fd, &ev) == -1) {
                logger(LOG_DAEMON, "OpenLI: unable to remove RTP stream timeout event for %s from epoll: %s",
                        cin->streamkey, strerror(errno));
            }
            close(timerev->fd);
            free(timerev);
            cin->timeout_ev = NULL;

        }
    }
}

static void push_sip_uri_halt(libtrace_message_queue_t *q, char *uri) {
    openli_pushed_t msg;

    msg.type = OPENLI_PUSH_HALT_SIPURI;
    msg.data.sipuri = strdup(uri);

    libtrace_message_queue_put(q, (void *)(&msg));
}

static inline void push_voipintercept_halt_to_threads(collector_sync_t *sync,
        voipintercept_t *vint) {

    sync_sendq_t *sendq, *tmp;

    HASH_ITER(hh, (sync_sendq_t *)(sync->glob->syncsendqs), sendq, tmp) {
        push_sip_uri_halt(sendq->q, vint->sipuri);
        push_halt_active_voipstreams(sendq->q, vint,
                sync->glob->sync_epollfd);
    }
}

static inline void push_session_halt_to_threads(void *sendqs,
        access_session_t *sess, ipintercept_t *ipint) {

    sync_sendq_t *sendq, *tmp;

    HASH_ITER(hh, (sync_sendq_t *)sendqs, sendq, tmp) {
        openli_pushed_t pmsg;
        ipsession_t *sessdup;
        char ipstr[128];

        pmsg.type = OPENLI_PUSH_HALT_IPINTERCEPT;
        sessdup = create_ipsession(ipint, sess);

        /* misnomer, but whatever. */
        pmsg.data.ipsess = sessdup;

        /* XXX no error checking because this logging should not reach
         * the production version... */
        getnameinfo((struct sockaddr *)(&sess->assignedip),
                (sess->ipfamily == AF_INET) ? sizeof(struct sockaddr_in) :
                    sizeof(struct sockaddr_in6),
                    ipstr, sizeof(ipstr), 0, 0, NI_NUMERICHOST);
        logger(LOG_DAEMON, "OpenLI: telling threads to cease intercepting traffic for IP %s", ipstr);
        libtrace_message_queue_put(sendq->q, &pmsg);
    }
}

static inline void push_ipintercept_halt_to_threads(collector_sync_t *sync,
        ipintercept_t *ipint) {

    sync_sendq_t *sendq, *tmp;
    internet_user_t *user;
    access_session_t *sess, *tmp2;

    logger(LOG_DAEMON, "OpenLI: collector will stop intercepting traffic for user %s", ipint->username);

    HASH_FIND(hh, sync->allusers, ipint->username, ipint->username_len,
            user);

    if (user == NULL) {
        return;
    }

    /* Cancel all IP sessions for the target */
    HASH_ITER(hh, user->sessions, sess, tmp2) {
        /* TODO skip sessions that were never active */

        push_session_halt_to_threads(sync->glob->syncsendqs, sess,
                ipint);
    }
}

static void disable_unconfirmed_intercepts(collector_sync_t *sync) {
    voipintercept_t *v, *tmp2;
    coreserver_t *cs, *tmp3;
    ipintercept_t *ipint, *tmp;
    internet_user_t *user;

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
        }
    }

    HASH_ITER(hh_liid, sync->voipintercepts, v, tmp2) {
        if (v->awaitingconfirm && v->active) {
            v->active = 0;

            if (v->active_cins == NULL) {
                continue;
            }

            push_voipintercept_halt_to_threads(sync, v);
            HASH_DELETE(hh_liid, sync->voipintercepts, v);
            free_single_voipintercept(v);
        }
    }

    /* Also remove any unconfirmed core servers */
    HASH_ITER(hh, sync->coreservers, cs, tmp3) {
        if (cs->awaitingconfirm) {
            push_coreserver_msg(sync, cs, OPENLI_PUSH_REMOVE_CORESERVER);
            HASH_DELETE(hh, sync->coreservers, cs);
            free_single_coreserver(cs);
        }
    }
}

static int new_mediator(collector_sync_t *sync, uint8_t *provmsg,
        uint16_t msglen) {

    openli_mediator_t med;
    openli_export_recv_t expmsg;

    if (decode_mediator_announcement(provmsg, msglen, &med) == -1) {
        logger(LOG_DAEMON, "OpenLI: received invalid mediator announcement from provisioner.");
        return -1;
    }

    expmsg.type = OPENLI_EXPORT_MEDIATOR;
    expmsg.data.med = med;

    libtrace_message_queue_put(&(sync->exportq), &expmsg);
    return 0;
}

static int remove_mediator(collector_sync_t *sync, uint8_t *provmsg,
        uint16_t msglen) {

    openli_mediator_t med;
    openli_export_recv_t expmsg;

    if (decode_mediator_withdraw(provmsg, msglen, &med) == -1) {
        logger(LOG_DAEMON, "OpenLI: received invalid mediator withdrawal from provisioner.");
        return -1;
    }

    expmsg.type = OPENLI_EXPORT_DROP_SINGLE_MEDIATOR;
    expmsg.data.med = med;

    libtrace_message_queue_put(&(sync->exportq), &expmsg);
    return 0;
}

static inline void convert_ipstr_to_sockaddr(char *knownip,
        struct sockaddr_storage **saddr, int *family) {

    struct addrinfo *res = NULL;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(knownip, NULL, &hints, &res) != 0) {
        logger(LOG_DAEMON, "OpenLI: getaddrinfo cannot parse IP address %s: %s",
                knownip, gai_strerror(errno));
    }

    *family = res->ai_family;
    *saddr = (struct sockaddr_storage *)malloc(
            sizeof(struct sockaddr_storage));
    memcpy(*saddr, res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res);
}


static void push_sip_uri(libtrace_message_queue_t *q, char *uri) {
    openli_pushed_t msg;

    msg.type = OPENLI_PUSH_SIPURI;
    msg.data.sipuri = strdup(uri);

    libtrace_message_queue_put(q, (void *)(&msg));
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
        HASH_DELETE(hh, sync->coreservers, found);
        free_single_coreserver(found);
    }
    free_single_coreserver(cs);
    return 0;
}

static void push_all_active_voipstreams(libtrace_message_queue_t *q,
        voipintercept_t *vint) {

    rtpstreaminf_t *cin = NULL;

    if (vint->active_cins == NULL) {
        return;
    }

    for (cin = vint->active_cins; cin != NULL; cin=cin->hh.next) {
        if (cin->active == 0) {
            continue;
        }

        push_single_voipstreamintercept(q, cin);
    }

}

static int update_rtp_stream(collector_sync_t *sync, rtpstreaminf_t *rtp,
        voipintercept_t *vint, char *ipstr, char *portstr, uint8_t dir) {

    uint32_t port;
    struct sockaddr_storage *saddr;
    int family, i;
    int updaterequired = 1;
    sync_sendq_t *sendq, *tmp;

    errno = 0;
    port = strtoul(portstr, NULL, 0);

    if (errno != 0 || port > 65535) {
        logger(LOG_DAEMON, "OpenLI: invalid RTP port number: %s", portstr);
        return -1;
    }

    convert_ipstr_to_sockaddr(ipstr, &(saddr), &(family));

    /* If we get here, the RTP stream is not in our list. */
    if (dir == ETSI_DIR_FROM_TARGET) {
        if (rtp->targetaddr) {
            /* has the address or port changed? should we warn? */
            free(rtp->targetaddr);
        }
        rtp->ai_family = family;
        rtp->targetaddr = saddr;
        rtp->targetport = (uint16_t)port;

    } else {
        if (rtp->otheraddr) {
            /* has the address or port changed? should we warn? */
            free(rtp->otheraddr);
        }
        rtp->ai_family = family;
        rtp->otheraddr = saddr;
        rtp->otherport = (uint16_t)port;
    }

    /* Not got the full 5-tuple for the RTP stream yet */
    if (!rtp->targetaddr || !rtp->otheraddr) {
        return 0;
    }

    if (!updaterequired) {
        return 0;
    }

    /* If we get here, we need to push the RTP stream details to the
     * processing threads. */
    HASH_ITER(hh, (sync_sendq_t *)(sync->glob->syncsendqs), sendq, tmp) {
        if (rtp->active == 0) {
            push_single_voipstreamintercept(sendq->q, rtp);
        }
    }
    rtp->active = 1;
    return 0;
}

static inline voipcinmap_t *update_cin_callid_map(voipintercept_t *vint,
        char *callid, voipintshared_t *vshared) {

    voipcinmap_t *newcinmap;

    newcinmap = (voipcinmap_t *)malloc(sizeof(voipcinmap_t));
    if (!newcinmap) {
        logger(LOG_DAEMON,
                "OpenLI: out of memory in collector_sync thread.");
        return NULL;
    }
    newcinmap->callid = strdup(callid);
    newcinmap->shared = vshared;
    newcinmap->shared->refs ++;

    HASH_ADD_KEYPTR(hh_callid, vint->cin_callid_map, newcinmap->callid,
            strlen(newcinmap->callid), newcinmap);
    return newcinmap;
}

static inline voipsdpmap_t *update_cin_sdp_map(voipintercept_t *vint,
        sip_sdp_identifier_t *sdpo, voipintshared_t *vshared) {

    voipsdpmap_t *newsdpmap;

    newsdpmap = (voipsdpmap_t *)malloc(sizeof(voipsdpmap_t));
    if (!newsdpmap) {
        logger(LOG_DAEMON,
                "OpenLI: out of memory in collector_sync thread.");
        return NULL;
    }
    newsdpmap->sdpkey.sessionid = sdpo->sessionid;
    newsdpmap->sdpkey.version = sdpo->version;
    newsdpmap->shared = vshared;
    newsdpmap->shared->refs ++;

    HASH_ADD_KEYPTR(hh_sdp, vint->cin_sdp_map, &(newsdpmap->sdpkey),
            sizeof(sip_sdp_identifier_t), newsdpmap);

    return newsdpmap;
}

static int create_new_voipcin(rtpstreaminf_t **activecins, uint32_t cin_id,
        voipintercept_t *vint) {

    rtpstreaminf_t *newcin;

    newcin = create_rtpstream(vint, cin_id);

    if (!newcin) {
        logger(LOG_DAEMON,
                "OpenLI: out of memory while creating new RTP stream");
        return -1;
    }
    HASH_ADD_KEYPTR(hh, *activecins, newcin->streamkey,
            strlen(newcin->streamkey), newcin);
    return 0;

}

static int lookup_voip_calls(collector_sync_t *sync, char *uri,
        char *callid, char *sessid, char *sessversion, uint8_t fromorto,
        libtrace_packet_t *pkt) {

    voipcinmap_t *cin = NULL;
    rtpstreaminf_t *thisrtp = NULL;
    sip_sdp_identifier_t sdpo;
    voipintercept_t *vint, *tmp;
    char *ipstr, *portstr, *cseqstr;
    char rtpkey[256];
    int exportcount = 0;
    int ret;

    if (sessid != NULL) {
        errno = 0;
        sdpo.sessionid = strtoul(sessid, NULL, 0);
        if (errno != 0) {
            logger(LOG_DAEMON, "OpenLI: invalid session ID in SIP packet %s",
                    sessid);
            sessid = NULL;
        }
    }

    if (sessversion != NULL) {
        errno = 0;
        sdpo.version = strtoul(sessversion, NULL, 0);
        if (errno != 0) {
            logger(LOG_DAEMON, "OpenLI: invalid version in SIP packet %s",
                    sessid);
            sessversion = NULL;
        }
    }

    HASH_ITER(hh_liid, sync->voipintercepts, vint, tmp) {
        uint32_t cin_id;
        voipcinmap_t *newcin, *findcin;
        voipsdpmap_t *findsdp = NULL;
        voipintshared_t *vshared = NULL;
        etsili_iri_type_t iritype = ETSILI_IRI_REPORT;

        findcin = NULL;
        findsdp = NULL;

        if (strcmp(vint->sipuri, uri) != 0) {
            continue;
        }

        HASH_FIND(hh_callid, vint->cin_callid_map, callid, strlen(callid),
                findcin);
        if (sessid != NULL && sessversion != NULL) {
            HASH_FIND(hh_sdp, vint->cin_sdp_map, &sdpo, sizeof(sdpo),
                    findsdp);
        }

        if (findcin == NULL && findsdp == NULL) {
            /* Never seen this call ID or session before */
            cin_id = hashlittle(callid, strlen(callid), 0xbeefface);
            if (create_new_voipcin(&(vint->active_cins), cin_id,
                        vint) == -1) {
                ret = -1;
                goto endvoiplookup;
            }
            vshared = (voipintshared_t *)malloc(sizeof(voipintshared_t));
            vshared->cin = cin_id;
            vshared->iriseqno = 0;
            vshared->refs = 0;

            newcin = update_cin_callid_map(vint, callid, vshared);
            if (newcin == NULL) {
                ret = -1;
                goto endvoiplookup;
            }

            if (sessid != NULL && sessversion != NULL) {
                if (update_cin_sdp_map(vint, &sdpo, vshared) == NULL) {
                    ret = -1;
                    goto endvoiplookup;
                }
            }
            iritype = ETSILI_IRI_BEGIN;
        } else if (findcin == NULL && findsdp != NULL) {
            /* New call ID but already seen this session */
            vshared = findsdp->shared;
            newcin = update_cin_callid_map(vint, callid, vshared);
            if (newcin == NULL) {
                ret = -1;
                goto endvoiplookup;
            }

            iritype = ETSILI_IRI_CONTINUE;

        } else if (findsdp == NULL && findcin != NULL && sessid != NULL &&
                sessversion != NULL) {
            /* New session ID for a known call ID */
            vshared = findcin->shared;
            if (update_cin_sdp_map(vint, &sdpo, vshared) == NULL) {
                ret = -1;
                goto endvoiplookup;
            }
            iritype = ETSILI_IRI_CONTINUE;
        } else {
            if (findsdp) {
                assert(findsdp->shared->cin == findcin->shared->cin); // XXX
            }
            vshared = findcin->shared;
            iritype = ETSILI_IRI_CONTINUE;
        }

        snprintf(rtpkey, 256, "%s-%u", vint->common.liid, vshared->cin);
        HASH_FIND(hh, vint->active_cins, rtpkey, strlen(rtpkey), thisrtp);
        if (thisrtp == NULL) {
            logger(LOG_DAEMON,
                    "OpenLI: unable to find %u in the active call list for %s, %s",
                    vshared->cin, vint->common.liid, vint->sipuri);
            continue;
        }

        /* Check for a new RTP stream announcement in an INVITE */
        if (sip_is_invite(sync->sipparser)) {
            ipstr = get_sip_media_ipaddr(sync->sipparser);
            portstr = get_sip_media_port(sync->sipparser);

            if (ipstr && portstr) {
                if (update_rtp_stream(sync, thisrtp, vint, ipstr, portstr,
                            0) == -1) {
                    logger(LOG_DAEMON,
                            "OpenLI: error adding new RTP stream for LIID %s (%s:%s)",
                            vint->common.liid, ipstr, portstr);
                    continue;
                }
            }

            if (thisrtp->invitecseq != NULL) {
                free(thisrtp->invitecseq);
            }
            thisrtp->invitecseq = get_sip_cseq(sync->sipparser);
        }

        /* Check for a new RTP stream announcement in a 200 OK */
        if (sip_is_200ok(sync->sipparser)) {
            cseqstr = get_sip_cseq(sync->sipparser);

            if (thisrtp->invitecseq && strcmp(thisrtp->invitecseq,
                    cseqstr) == 0) {

                ipstr = get_sip_media_ipaddr(sync->sipparser);
                portstr = get_sip_media_port(sync->sipparser);

                if (ipstr && portstr) {
                    if (update_rtp_stream(sync, thisrtp, vint, ipstr,
                                portstr, 1) == -1) {
                        logger(LOG_DAEMON,
                                "OpenLI: error adding new RTP stream for LIID %s (%s:%s)",
                                vint->common.liid, ipstr, portstr);
                        free(cseqstr);
                        continue;
                    }
                    free(thisrtp->invitecseq);
                    thisrtp->invitecseq = NULL;
                }
            } else if (thisrtp->byecseq && strcmp(thisrtp->byecseq,
                    cseqstr) == 0 && thisrtp->byematched == 0) {
                sync_epoll_t *timeout = (sync_epoll_t *)calloc(1,
                        sizeof(sync_epoll_t));

                /* Call for this session should be over */
                thisrtp->timeout_ev = (void *)timeout;
                timeout->fdtype = SYNC_EVENT_SIP_TIMEOUT;
                timeout->fd = epoll_add_timer(sync->glob->sync_epollfd,
                        30, timeout);
                timeout->ptr = thisrtp;

                thisrtp->byematched = 1;
                iritype = ETSILI_IRI_END;
            }
            free(cseqstr);
        }

        /* Check for 183 Session Progress, as this can contain RTP info */
        if (sip_is_183sessprog(sync->sipparser)) {
            cseqstr = get_sip_cseq(sync->sipparser);

            if (thisrtp->invitecseq && strcmp(thisrtp->invitecseq,
                    cseqstr) == 0) {

                ipstr = get_sip_media_ipaddr(sync->sipparser);
                portstr = get_sip_media_port(sync->sipparser);

                if (ipstr && portstr) {
                    if (update_rtp_stream(sync, thisrtp, vint, ipstr,
                                portstr, 1) == -1) {
                        logger(LOG_DAEMON,
                                "OpenLI: error adding new RTP stream for LIID %s (%s:%s)",
                                vint->common.liid, ipstr, portstr);
                        free(cseqstr);
                        continue;
                    }
                    free(thisrtp->invitecseq);
                    thisrtp->invitecseq = NULL;
                }
            }
            free(cseqstr);
        }


        /* Check for a BYE */
        if (sip_is_bye(sync->sipparser) && !thisrtp->byematched) {
            if (thisrtp->byecseq) {
                free(thisrtp->byecseq);
            }
            thisrtp->byecseq = get_sip_cseq(sync->sipparser);
        }

        if (thisrtp->byematched && iritype != ETSILI_IRI_END) {
            /* All post-END IRIs must be REPORTs */
            iritype = ETSILI_IRI_REPORT;
        }

        /* Wrap this packet up in an IRI and forward it on to the exporter */
        ret = ipmm_iri(pkt, sync->glob, &(sync->encoder), &(sync->exportq),
                vint, vshared, iritype);
        if (ret == -1) {
            logger(LOG_DAEMON,
                    "OpenLI: error while trying to export IRI containing SIP packet.");
            goto endvoiplookup;
        }
        exportcount += ret;
    }


endvoiplookup:
    if (exportcount > 0) {
        /* Increment ref count for the packet and send a packet fin message
         * so the exporter knows when to decrease the ref count */
        openli_export_recv_t msg;
        trace_increment_packet_refcount(pkt);
        msg.type = OPENLI_EXPORT_PACKET_FIN;
        msg.data.packet = pkt;
        libtrace_message_queue_put(&(sync->exportq), (void *)(&msg));
        return 1;
    }
    return 0;
}

static int update_sip_state(collector_sync_t *sync, libtrace_packet_t *pkt) {

    char *fromuri, *touri, *callid, *sessid, *sessversion;
    int iserr = 0;

    callid = get_sip_callid(sync->sipparser);
    sessid = get_sip_session_id(sync->sipparser);
    sessversion = get_sip_session_version(sync->sipparser);

    if (callid == NULL) {
        iserr = 1;
        goto sipgiveup;
    }


    fromuri = get_sip_from_uri(sync->sipparser);
    if (fromuri != NULL) {
        if (lookup_voip_calls(sync, fromuri, callid, sessid,
                sessversion, SIP_MATCH_FROMURI, pkt) < 0) {
            iserr = 1;
        }

    }

    touri = get_sip_to_uri(sync->sipparser);
    if (touri != NULL) {
        /* If the "from" and "to" URIs are the same (which can happen
         * with REGISTER requests), don't repeat the lookup and processing
         * we just did -- otherwise we'll end up sending duplicate IRIs.
         */
        if (fromuri == NULL || strcmp(fromuri, touri) != 0) {
            if (lookup_voip_calls(sync, touri, callid, sessid,
                    sessversion, SIP_MATCH_TOURI, pkt) < 0) {
                iserr = 1;
            }
        }
    }

    if (!fromuri && !touri) {
        iserr = 1;
    }

    if (fromuri) {
        free(fromuri);
    }
    if (touri) {
        free(touri);
    }

sipgiveup:

    if (iserr) {
        return -1;
    }
    return 0;

}

static int halt_voipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    voipintercept_t *vint, torem;
    sync_sendq_t *sendq, *tmp;
    int i;

    if (decode_voipintercept_halt(intmsg, msglen, &torem) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: received invalid VOIP intercept withdrawal from provisioner.");
        return -1;
    }

    HASH_FIND(hh_liid, sync->voipintercepts, torem.common.liid,
            torem.common.liid_len, vint);
    if (!vint) {
        logger(LOG_DAEMON,
                "OpenLI: received withdrawal for VOIP intercept %s but it is not present in the sync intercept list?",
                torem.common.liid);
        return 0;
    }

    logger(LOG_DAEMON, "OpenLI: sync thread withdrawing VOIP intercept %s",
            torem.common.liid);

    push_voipintercept_halt_to_threads(sync, vint);
    HASH_DELETE(hh_liid, sync->voipintercepts, vint);
    free_single_voipintercept(vint);
    return 0;
}

static int halt_ipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    ipintercept_t *ipint, torem;
    sync_sendq_t *sendq, *tmp;
    int i;

    if (decode_ipintercept_halt(intmsg, msglen, &torem) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: received invalid IP intercept withdrawal from provisioner.");
        return -1;
    }

    HASH_FIND(hh_liid, sync->ipintercepts, torem.common.liid,
            torem.common.liid_len, ipint);
    if (!ipint) {
        logger(LOG_DAEMON,
                "OpenLI: received withdrawal for IP intercept %s but it is not present in the sync intercept list?",
                torem.common.liid);
        return 0;
    }

    logger(LOG_DAEMON, "OpenLI: sync thread withdrawing IP intercept %s",
            torem.common.liid);

    push_ipintercept_halt_to_threads(sync, ipint);
    HASH_DELETE(hh_liid, sync->ipintercepts, ipint);
    if (ipint->username) {
        remove_intercept_from_user_intercept_list(&sync->userintercepts, ipint);
    }
    free_single_ipintercept(ipint);
    return 0;
}

static int halt_single_rtpstream(collector_sync_t *sync, rtpstreaminf_t *rtp) {
    int i;

    struct epoll_event ev;
    voipcinmap_t *cin_callid, *tmp;
    voipsdpmap_t *cin_sdp, *tmp2;
    sync_sendq_t *sendq, *tmp3;

    if (rtp->timeout_ev) {
        sync_epoll_t *timerev = (sync_epoll_t *)(rtp->timeout_ev);
        if (epoll_ctl(sync->glob->sync_epollfd, EPOLL_CTL_DEL, timerev->fd,
                &ev) == -1) {
            logger(LOG_DAEMON, "OpenLI: unable to remove RTP stream timeout event for %s from epoll: %s",
                    rtp->streamkey, strerror(errno));
        }
        close(timerev->fd);
        free(timerev);
        rtp->timeout_ev = NULL;
    }


    if (rtp->active) {
        HASH_ITER(hh, (sync_sendq_t *)(sync->glob->syncsendqs), sendq, tmp3) {
           openli_pushed_t msg;
           msg.type = OPENLI_PUSH_HALT_IPMMINTERCEPT;
           msg.data.rtpstreamkey = strdup(rtp->streamkey);
           libtrace_message_queue_put(sendq->q, (void *)(&msg));
        }
    }

    HASH_DEL(rtp->parent->active_cins, rtp);

    /* TODO this is painful, maybe include reverse references in the shared
     * data structure?
     */
    HASH_ITER(hh_callid, rtp->parent->cin_callid_map, cin_callid, tmp) {
        if (cin_callid->shared->cin == rtp->cin) {
            HASH_DELETE(hh_callid, rtp->parent->cin_callid_map, cin_callid);
            free(cin_callid->callid);
            cin_callid->shared->refs --;
            if (cin_callid->shared->refs == 0) {
                free(cin_callid->shared);
                break;
            }
            free(cin_callid);
        }
    }

    HASH_ITER(hh_sdp, rtp->parent->cin_sdp_map, cin_sdp, tmp2) {
        int stop = 0;
        if (cin_sdp->shared->cin == rtp->cin) {
            HASH_DELETE(hh_sdp, rtp->parent->cin_sdp_map, cin_sdp);
            cin_sdp->shared->refs --;
            if (cin_sdp->shared->refs == 0) {
                free(cin_sdp->shared);
                stop = 1;
            }
            free(cin_sdp);
            if (stop) {
                break;
            }
        }
    }

    free_single_voip_cin(rtp);

    return 0;
}

static inline void drop_all_mediators(collector_sync_t *sync) {
    openli_export_recv_t expmsg;

    expmsg.type = OPENLI_EXPORT_DROP_ALL_MEDIATORS;
    expmsg.data.packet = NULL;
    libtrace_message_queue_put(&(sync->exportq), &expmsg);
}


static int new_voipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    voipintercept_t *vint, toadd;
    sync_sendq_t *sendq, *tmp;
    int i;

    if (decode_voipintercept_start(intmsg, msglen, &toadd) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: received invalid VOIP intercept from provisioner.");
        return -1;
    }

    HASH_FIND(hh_liid, sync->voipintercepts, toadd.common.liid,
            toadd.common.liid_len, vint);
    if (vint) {
        /* Duplicate LIID */
        if (strcmp(toadd.sipuri, vint->sipuri) != 0) {
            logger(LOG_DAEMON,
                    "OpenLI: duplicate VOIP intercept ID %s seen, but targets are different (was %s, now %s).",
                    vint->common.liid, vint->sipuri, toadd.sipuri);
            return -1;
        }
        vint->internalid = toadd.internalid;
        vint->awaitingconfirm = 0;
        vint->active = 1;
        return 0;
    }

    vint = (voipintercept_t *)malloc(sizeof(voipintercept_t));
    memcpy(vint, &toadd, sizeof(voipintercept_t));
    HASH_ADD_KEYPTR(hh_liid, sync->voipintercepts, vint->common.liid,
            vint->common.liid_len, vint);

    HASH_ITER(hh, (sync_sendq_t *)(sync->glob->syncsendqs), sendq, tmp) {
        push_sip_uri(sendq->q, vint->sipuri);

        /* Forward all active CINs to our collector threads */
        push_all_active_voipstreams(sendq->q, vint);

    }
    return 0;
}

static int new_ipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    ipintercept_t *cept, *x;
    sync_sendq_t *tmp, *sendq;
    internet_user_t *user;

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

        x->awaitingconfirm = 0;
        free(cept);
        /* our collector threads should already know about this intercept? */
        return 0;
    }

    if (cept->username) {
        HASH_FIND(hh, sync->allusers, cept->username, cept->username_len, user);

        if (user) {
            access_session_t *sess, *tmp2;
            HASH_ITER(hh, user->sessions, sess, tmp2) {
                HASH_ITER(hh, (sync_sendq_t *)(sync->glob->syncsendqs),
                        sendq, tmp) {
                    if (cept->alushimid != OPENLI_ALUSHIM_NONE) {
                        push_single_alushimid(sendq->q, cept, sess->cin);
                    } else {
                        push_single_ipintercept(sendq->q, cept, sess);
                    }
                }
            }
        }
        add_intercept_to_user_intercept_list(&sync->userintercepts, cept);
        logger(LOG_DAEMON,
                "OpenLI: received IP intercept from provisioner for user %s (LIID %s, authCC %s)",
                cept->username, cept->common.liid, cept->common.authcc);
    }

    if (cept->alushimid != OPENLI_ALUSHIM_NONE) {
        logger(LOG_DAEMON,
                "OpenLI: received IP intercept from provisioner for ALU shim ID %u (LIID %s, authCC %s)",
                cept->alushimid, cept->common.liid, cept->common.authcc);
    }

    HASH_ADD_KEYPTR(hh_liid, sync->ipintercepts, cept->common.liid,
            cept->common.liid_len, cept);

    return 0;

}

static int recv_from_provisioner(collector_sync_t *sync) {
    struct epoll_event ev;
    int ret = 0;
    uint8_t *provmsg;
    uint16_t msglen = 0;
    uint64_t intid = 0;

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
            case OPENLI_PROTO_START_VOIPINTERCEPT:
                ret = new_voipintercept(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_HALT_VOIPINTERCEPT:
                ret = halt_voipintercept(sync, provmsg, msglen);
                if (ret == -1) {
                    return -1;
                }
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
            case OPENLI_PROTO_NOMORE_INTERCEPTS:
                disable_unconfirmed_intercepts(sync);
                break;
        }

    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    return 1;
}

int sync_connect_provisioner(collector_sync_t *sync) {

    struct epoll_event ev;
    int sockfd;


    sockfd = connect_socket(sync->glob->provisionerip,
            sync->glob->provisionerport, sync->instruct_fail);

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

    if (epoll_ctl(sync->glob->sync_epollfd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
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

    /* Set all intercepts to be "awaiting confirmation", i.e. if the
     * provisioner doesn't announce them in its initial batch of
     * intercepts then they are to be halted.
     */
    HASH_ITER(hh_liid, intlist, ipint, tmp) {
        ipint->awaitingconfirm = 1;
    }
}

static inline void touch_all_voipintercepts(voipintercept_t *vints) {
    voipintercept_t *v;

    for (v = vints; v != NULL; v = v->hh_liid.next) {
        v->awaitingconfirm = 1;
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
        if (epoll_ctl(sync->glob->sync_epollfd, EPOLL_CTL_DEL,
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
    touch_all_voipintercepts(sync->voipintercepts);

    touch_all_coreservers(sync->coreservers);

    /* Same with mediators -- keep exporting to them, but flag them to be
     * disconnected if they are not announced after we reconnect. */
    expmsg.type = OPENLI_EXPORT_FLAG_MEDIATORS;
    expmsg.data.packet = NULL;

    libtrace_message_queue_put(&(sync->exportq), &expmsg);


}

static void push_all_active_intercepts(internet_user_t *allusers,
        ipintercept_t *intlist, libtrace_message_queue_t *q) {

    ipintercept_t *orig, *tmp;
    internet_user_t *user;
    access_session_t *sess, *tmp2;

    HASH_ITER(hh_liid, intlist, orig, tmp) {
        /* Do we have a valid user that matches the target username? */
        if (orig->username != NULL) {
            HASH_FIND(hh, allusers, orig->username, orig->username_len, user);
            if (!user) {
                continue;
            }

            HASH_ITER(hh, user->sessions, sess, tmp2) {
                if (orig->alushimid != OPENLI_ALUSHIM_NONE) {
                    push_single_alushimid(q, orig, sess->cin);
                } else {
                    push_single_ipintercept(q, orig, sess);
                }
            }
        }
    }
}

int sync_thread_main(collector_sync_t *sync) {

    int i, nfds;
    struct epoll_event evs[64];
    openli_state_update_t recvd;
    libtrace_message_queue_t *srcq = NULL;
    sync_epoll_t *syncev;

    nfds = epoll_wait(sync->glob->sync_epollfd, evs, 64, 50);

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
                epoll_ctl(sync->glob->sync_epollfd, EPOLL_CTL_DEL,
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

        if (syncev->fdtype == SYNC_EVENT_SIP_TIMEOUT) {
            struct rtpstreaminf *thisrtp;
            thisrtp = (struct rtpstreaminf *)(syncev->ptr);
            halt_single_rtpstream(sync, thisrtp);
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
            voipintercept_t *v;

            push_all_active_intercepts(sync->allusers, sync->ipintercepts,
                    recvd.data.replyq);
            for (v = sync->voipintercepts; v != NULL; v = v->hh_liid.next) {
                push_sip_uri(recvd.data.replyq, v->sipuri);
                push_all_active_voipstreams(recvd.data.replyq, v);
            }
            push_all_coreservers(sync->coreservers, recvd.data.replyq);
        }


        /* If an update from a thread, update appropriate internal state */

        /* If this resolves an unknown mapping or changes an existing one,
         * push II update messages to processing threads */

        /* If this relates to an active intercept, create IRI and export */

        if (recvd.type == OPENLI_UPDATE_SIP) {

            /* The error checking / reporting in here is a bit meaningless,
             * as I'm not really sure what action I can take here if something
             * goes wrong aside from just ignoring the SIP update.
             */
            int ret;
            if ((ret = parse_sip_packet(&(sync->sipparser),
                        recvd.data.pkt)) > 0) {
                if (update_sip_state(sync, recvd.data.pkt) < 0) {
                    logger(LOG_DAEMON,
                            "OpenLI: error while updating SIP state in collector.");
                }
            } else if (ret < 0) {
                logger(LOG_DAEMON,
                        "OpenLI: sync thread received an invalid SIP packet?");
            }

            trace_decrement_packet_refcount(recvd.data.pkt);
        }

    }

    return nfds;
}

static inline void push_hello_message(libtrace_message_queue_t *atob,
        libtrace_message_queue_t *btoa) {

    openli_state_update_t hello;

    hello.type = OPENLI_UPDATE_HELLO;
    hello.data.replyq = btoa;

    libtrace_message_queue_put(atob, (void *)(&hello));
}

int register_sync_queues(collector_global_t *glob,
        libtrace_message_queue_t *recvq, libtrace_message_queue_t *sendq,
        libtrace_thread_t *parent) {

    struct epoll_event ev;
    sync_epoll_t *syncev, *syncev_hash;
    sync_sendq_t *syncq, *sendq_hash, *a, *b;
    int ind;

    syncq = (sync_sendq_t *)malloc(sizeof(sync_sendq_t));
    syncq->q = sendq;
    syncq->parent = parent;

    syncev = (sync_epoll_t *)malloc(sizeof(sync_epoll_t));
    syncev->fdtype = SYNC_EVENT_PROC_QUEUE;
    syncev->fd = libtrace_message_queue_get_fd(recvq);
    syncev->ptr = recvq;
    syncev->parent = parent;

    ev.data.ptr = (void *)syncev;
    ev.events = EPOLLIN;

    pthread_mutex_lock(&(glob->syncq_mutex));
    if (epoll_ctl(glob->sync_epollfd, EPOLL_CTL_ADD, syncev->fd, &ev) == -1) {
        /* TODO Do something? */
        logger(LOG_DAEMON, "OpenLI: failed to register processor->sync queue: %s",
                strerror(errno));
        pthread_mutex_unlock(&(glob->syncq_mutex));
        return -1;
    }

    sendq_hash = (sync_sendq_t *)(glob->syncsendqs);
    HASH_ADD_PTR(sendq_hash, parent, syncq);
    glob->syncsendqs = (void *)sendq_hash;

    syncev_hash = (sync_epoll_t *)(glob->syncepollevs);
    HASH_ADD_PTR(syncev_hash, parent, syncev);
    glob->syncepollevs = (void *)syncev_hash;

    pthread_mutex_unlock(&(glob->syncq_mutex));

    push_hello_message(recvq, sendq);
    return 0;
}

void deregister_sync_queues(collector_global_t *glob, libtrace_thread_t *t) {

    sync_epoll_t *syncev, *syncev_hash;
    sync_sendq_t *syncq, *sendq_hash;
    struct epoll_event ev;

    pthread_mutex_lock(&(glob->syncq_mutex));
    sendq_hash = (sync_sendq_t *)(glob->syncsendqs);

    HASH_FIND_PTR(sendq_hash, &t, syncq);
    /* Caller will free the queue itself */
    if (syncq) {
        HASH_DELETE(hh, sendq_hash, syncq);
        free(syncq);
        glob->syncsendqs = (void *)sendq_hash;
    }

    syncev_hash = (sync_epoll_t *)(glob->syncepollevs);
    HASH_FIND_PTR(syncev_hash, &t, syncev);
    if (syncev) {
        if (glob->sync_epollfd != -1 && epoll_ctl(glob->sync_epollfd,
                    EPOLL_CTL_DEL, syncev->fd, &ev) == -1) {
            logger(LOG_DAEMON, "OpenLI: failed to de-register processor->sync queue %d: %s", syncev->fd, strerror(errno));
        }
        HASH_DELETE(hh, syncev_hash, syncev);
        free(syncev);
        glob->syncepollevs = (void *)syncev_hash;
    }

    pthread_mutex_unlock(&(glob->syncq_mutex));
}

void halt_processing_threads(collector_global_t *glob) {
    colinput_t *inp, *tmp;
    HASH_ITER(hh, glob->inputs, inp, tmp) {
        trace_pstop(inp->trace);
    }
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
