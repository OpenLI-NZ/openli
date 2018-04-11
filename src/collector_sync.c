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
    sync->ipintercepts = libtrace_list_init(sizeof(ipintercept_t));
    sync->voipintercepts = NULL;
    sync->instruct_fd = -1;
    sync->instruct_fail = 0;
    sync->ii_ev = (sync_epoll_t *)malloc(sizeof(sync_epoll_t));
    sync->glob->sync_epollfd = epoll_create1(0);

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
	}

	if (sync->glob->sync_epollfd != -1) {
		close(sync->glob->sync_epollfd);
	}

    /* XXX possibly need to lock this? */
    for (i = 0; i < sync->glob->registered_syncqs; i++) {
        free(sync->glob->syncepollevs[i]);
    }

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

	free(sync);

}

static inline void push_single_intercept(libtrace_message_queue_t *q,
        ipintercept_t *orig) {

    ipintercept_t *copy;
    openli_pushed_t msg;

    copy = (ipintercept_t *)malloc(sizeof(ipintercept_t));

    copy->internalid = orig->internalid;
    copy->liid = strdup(orig->liid);
    copy->liid_len = strlen(copy->liid);
    copy->authcc = strdup(orig->authcc);
    copy->authcc_len = strlen(copy->authcc);
    copy->delivcc = strdup(orig->delivcc);
    copy->delivcc_len = strlen(copy->delivcc);
    copy->cin = orig->cin;
    copy->ai_family = orig->ai_family;
    copy->destid = orig->destid;

    if (orig->targetagency) {
        copy->targetagency = strdup(orig->targetagency);
    } else {
        copy->targetagency = NULL;
    }

    if (orig->ipaddr) {
        copy->ipaddr = (struct sockaddr_storage *)malloc(
                sizeof(struct sockaddr_storage));
        memcpy(copy->ipaddr, orig->ipaddr, sizeof(struct sockaddr_storage));
    } else {
        copy->ipaddr = NULL;
    }

    if (orig->username) {
        copy->username = strdup(orig->username);
        copy->username_len = strlen(copy->username);
    } else {
        copy->username = NULL;
        copy->username_len = 0;
    }

    copy->active = 1;
    copy->nextseqno = 0;
    copy->awaitingconfirm = 0;

    msg.type = OPENLI_PUSH_IPINTERCEPT;
    msg.data.ipint = copy;

    libtrace_message_queue_put(q, (void *)(&msg));
}

static inline void push_single_voipstreamintercept(libtrace_message_queue_t *q,
        rtpstreaminf_t *orig) {

    rtpstreaminf_t *copy;
    openli_pushed_t msg;

    copy = (rtpstreaminf_t *)malloc(sizeof(rtpstreaminf_t));
    copy->streamkey = strdup(orig->streamkey);
    copy->cin = orig->cin;
    copy->parent = orig->parent;
    copy->ai_family = orig->ai_family;
    copy->targetaddr = (struct sockaddr_storage *)malloc(
            sizeof(struct sockaddr_storage));
    memcpy(copy->targetaddr, orig->targetaddr, sizeof(struct sockaddr_storage));
    copy->otheraddr = (struct sockaddr_storage *)malloc(
            sizeof(struct sockaddr_storage));
    memcpy(copy->otheraddr, orig->otheraddr, sizeof(struct sockaddr_storage));
    copy->targetport = orig->targetport;
    copy->otherport = orig->otherport;
    copy->seqno = 0;
    copy->active = orig->active;
    copy->invitecseq = NULL;
    copy->byecseq = NULL;
    copy->timeout_ev = NULL;
    copy->byematched = 0;

    msg.type = OPENLI_PUSH_IPMMINTERCEPT;
    msg.data.ipmmint = copy;

    libtrace_message_queue_put(q, (void *)(&msg));
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

static void disable_unconfirmed_intercepts(collector_sync_t *sync) {
    libtrace_list_node_t *n;
    voipintercept_t *v;
    int i;

    n = sync->ipintercepts->head;

    /* TODO count total inactive as we go and reconstruct the list
     * if the inactive count is relatively high?
     */

    while (n) {
        ipintercept_t *cept = (ipintercept_t *)(n->data);

        if (cept->awaitingconfirm && cept->active) {
            cept->active = 0;

            for (i = 0; i < sync->glob->registered_syncqs; i++) {
                openli_pushed_t pmsg;

                /* strdup because we might end up freeing this intercept
                 * shortly.
                 */
                pmsg.type = OPENLI_PUSH_HALT_IPINTERCEPT;
                pmsg.data.interceptid.liid = strdup(cept->liid);
                pmsg.data.interceptid.authcc = strdup(cept->authcc);
                libtrace_message_queue_put(sync->glob->syncsendqs[i], &pmsg);
            }
        }
        n = n->next;
    }

    for (v = sync->voipintercepts; v != NULL; v = v->hh_liid.next) {
        if (v->awaitingconfirm && v->active) {
            v->active = 0;

            if (v->active_cins == NULL) {
                continue;
            }

            for (i = 0; i < sync->glob->registered_syncqs; i++) {
                openli_pushed_t pmsg;

                /* strdup because we might end up freeing this intercept
                 * shortly.
                 */
                pmsg.type = OPENLI_PUSH_HALT_IPMMINTERCEPT;
                pmsg.data.interceptid.liid = strdup(v->liid);
                pmsg.data.interceptid.authcc = strdup(v->authcc);
                libtrace_message_queue_put(sync->glob->syncsendqs[i], &pmsg);
            }
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

static void finish_init_mediators(collector_sync_t *sync) {
    openli_export_recv_t expmsg;

    expmsg.type = OPENLI_EXPORT_INIT_MEDIATORS_OVER;
    expmsg.data.packet = NULL;

    libtrace_message_queue_put(&(sync->exportq), &expmsg);
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

static void temporary_map_user_to_address(ipintercept_t *cept) {

    char *knownip;
    if (strcmp(cept->username, "RogerMegently") == 0) {
        knownip = "10.0.0.2";
    } else if (strcmp(cept->username, "Everything") == 0) {
        knownip = "10.0.0.1";
    } else {
        return;
    }

    convert_ipstr_to_sockaddr(knownip, &(cept->ipaddr), &(cept->ai_family));
}

static void push_sip_uri(libtrace_message_queue_t *q, char *uri) {
    openli_pushed_t msg;

    msg.type = OPENLI_PUSH_SIPURI;
    msg.data.sipuri = strdup(uri);

    libtrace_message_queue_put(q, (void *)(&msg));
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
    libtrace_list_node_t *n;
    int updaterequired = 1;

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
            /* TODO */
            /* has the address or port changed? */
        }
        rtp->ai_family = family;
        rtp->targetaddr = saddr;
        rtp->targetport = (uint16_t)port;

    } else {
        if (rtp->otheraddr) {
            /* TODO */
            /* has the address or port changed? */

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
    for (i = 0; i < sync->glob->registered_syncqs; i++) {
        if (rtp->active == 0) {
            rtp->active = 1;
            push_single_voipstreamintercept(sync->glob->syncsendqs[i], rtp);
        }
    }
    return 0;
}

static inline voipcinmap_t *update_cin_callid_map(voipintercept_t *vint,
        uint32_t cin, char *callid, voipcinmap_t *existing) {

    voipcinmap_t *newcinmap;

    if (!existing) {
        newcinmap = (voipcinmap_t *)malloc(sizeof(voipcinmap_t));
        if (!newcinmap) {
            logger(LOG_DAEMON,
                    "OpenLI: out of memory in collector_sync thread.");
            return NULL;
        }
        newcinmap->cin = cin;
        newcinmap->iriseqno = 0;
        newcinmap->callid = strdup(callid);
        newcinmap->sdpkey.sessionid = 0;
        newcinmap->sdpkey.version = 0;
        existing = newcinmap;
    } else {
        if (existing->callid) {
            free(existing->callid);
        }
        existing->callid = strdup(callid);
    }

    HASH_ADD_KEYPTR(hh_callid, vint->cin_callid_map, existing->callid,
            strlen(existing->callid), existing);
    return existing;
}

static inline voipcinmap_t *update_cin_sdp_map(voipintercept_t *vint,
        uint32_t cin, sip_sdp_identifier_t *sdpo, voipcinmap_t *existing) {

    voipcinmap_t *newcinmap;

    if (!existing) {
        newcinmap = (voipcinmap_t *)malloc(sizeof(voipcinmap_t));
        if (!newcinmap) {
            logger(LOG_DAEMON,
                    "OpenLI: out of memory in collector_sync thread.");
            return NULL;
        }
        newcinmap->cin = cin;
        newcinmap->callid = NULL;
        newcinmap->iriseqno = 0;
        newcinmap->sdpkey.sessionid = sdpo->sessionid;
        newcinmap->sdpkey.version = sdpo->version;
        existing = newcinmap;
    } else {
        existing->sdpkey.sessionid = sdpo->sessionid;
        existing->sdpkey.version = sdpo->version;
    }

    HASH_ADD(hh_sdp, vint->cin_sdp_map, sdpkey,
            sizeof(sip_sdp_identifier_t), existing);
    return existing;
}

static int create_new_voipcin(rtpstreaminf_t **activecins, uint32_t cin_id,
        voipintercept_t *vint) {

    rtpstreaminf_t *newcin;

    newcin = (rtpstreaminf_t *)malloc(sizeof(rtpstreaminf_t));
    if (!newcin) {
        logger(LOG_DAEMON,
                "OpenLI: out of memory in collector_sync thread.");
        return -1;
    }

    newcin->streamkey = (char *)calloc(1, 256);
    newcin->cin = cin_id;
    newcin->parent = vint;
    newcin->active = 0;
    newcin->targetaddr = NULL;
    newcin->otheraddr = NULL;
    newcin->ai_family = 0;
    newcin->targetport = 0;
    newcin->otherport = 0;
    newcin->seqno = 0;
    newcin->invitecseq = NULL;
    newcin->byecseq = NULL;
    newcin->timeout_ev = NULL;
    newcin->byematched = 0;

    snprintf(newcin->streamkey, 256, "%s-%u", vint->liid, cin_id);

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
        voipcinmap_t *newcin, *cin1, *cin2;
        etsili_iri_type_t iritype = ETSILI_IRI_REPORT;

        cin1 = NULL;
        cin2 = NULL;

        if (strcmp(vint->sipuri, uri) != 0) {
            continue;
        }

        HASH_FIND(hh_callid, vint->cin_callid_map, callid, strlen(callid),
                cin1);
        if (sessid != NULL && sessversion != NULL) {
            HASH_FIND(hh_sdp, vint->cin_sdp_map, &sdpo, sizeof(sdpo),
                    cin2);
        }

        if (cin1 == NULL && cin2 == NULL) {
            /* Never seen this call ID or session before */
            cin_id = hashlittle(callid, strlen(callid), 0xbeefface);
            if (create_new_voipcin(&(vint->active_cins), cin_id,
                        vint) == -1) {
                ret = -1;
                goto endvoiplookup;
            }

            newcin = update_cin_callid_map(vint, cin_id, callid, NULL);
            if (newcin == NULL) {
                ret = -1;
                goto endvoiplookup;
            }
            if (sessid != NULL && sessversion != NULL) {
                if (update_cin_sdp_map(vint, cin_id, &sdpo, newcin) == NULL) {
                    ret = -1;
                    goto endvoiplookup;
                }
            }
            cin = newcin;
            iritype = ETSILI_IRI_BEGIN;
        } else if (cin1 == NULL && cin2 != NULL) {
            /* New call ID but already seen this session */
            cin_id = cin2->cin;
            if (update_cin_callid_map(vint, cin_id, callid, cin2) == NULL) {
                ret = -1;
                goto endvoiplookup;
            }
            cin = cin2;
            iritype = ETSILI_IRI_CONTINUE;

        } else if (cin2 == NULL && cin1 != NULL && sessid != NULL &&
                sessversion != NULL) {
            /* New session ID for a known call ID */
            cin_id = cin1->cin;
            if (update_cin_sdp_map(vint, cin_id, &sdpo, cin1) == NULL) {
                ret = -1;
                goto endvoiplookup;
            }
            cin = cin1;
            iritype = ETSILI_IRI_CONTINUE;
        } else {
            if (cin2) {
                assert(cin1->cin == cin2->cin);     // XXX temporary
            }
            cin_id = cin1->cin;
            cin = cin1;
            iritype = ETSILI_IRI_CONTINUE;
        }

        snprintf(rtpkey, 256, "%s-%u", vint->liid, cin_id);
        HASH_FIND(hh, vint->active_cins, rtpkey, strlen(rtpkey), thisrtp);
        if (thisrtp == NULL) {
            logger(LOG_DAEMON,
                    "OpenLI: unable to find %u in the active call list for %s, %s",
                    cin_id, vint->liid, vint->sipuri);
            continue;
        }

        /* TODO sort out direction tagging for RTP streams */

        /* Check for a new RTP stream announcement in an INVITE */
        if (sip_is_invite(sync->sipparser)) {
            ipstr = get_sip_media_ipaddr(sync->sipparser);
            portstr = get_sip_media_port(sync->sipparser);

            if (ipstr && portstr) {
                if (update_rtp_stream(sync, thisrtp, vint, ipstr, portstr,
                            0) == -1) {
                    logger(LOG_DAEMON,
                            "OpenLI: error adding new RTP stream for LIID %s (%s:%s)",
                            vint->liid, ipstr, portstr);
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
                                vint->liid, ipstr, portstr);
                        free(cseqstr);
                        continue;
                    }
                }
            } else if (thisrtp->byecseq && strcmp(thisrtp->byecseq,
                    cseqstr) == 0 && thisrtp->byematched == 0) {
                sync_epoll_t *timeout = (sync_epoll_t *)calloc(1,
                        sizeof(sync_epoll_t));

                /* Call for this session should be over */

                /* TODO this CIN should be scheduled to be removed at some
                 * point to free up resources -- not immediately though,
                 * as everything is UDP so we can't guarantee that the
                 * call will end right away.
                 */
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
                vint, cin, iritype);
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

static int new_voipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    voipintercept_t *vint, toadd;
    int i;

    if (decode_voipintercept_start(intmsg, msglen, &toadd) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: received invalid VOIP intercept from provisioner.");
        return -1;
    }

    HASH_FIND(hh_liid, sync->voipintercepts, toadd.liid, toadd.liid_len, vint);
    if (vint) {
        /* Duplicate LIID */
        if (strcmp(toadd.sipuri, vint->sipuri) != 0) {
            logger(LOG_DAEMON,
                    "OpenLI: duplicate VOIP intercept ID %s seen, but targets are different (was %s, now %s).",
                    vint->liid, vint->sipuri, toadd.sipuri);
            return -1;
        }
        vint->internalid = toadd.internalid;
        vint->awaitingconfirm = 0;
        vint->active = 1;
        return 0;
    }

    vint = (voipintercept_t *)malloc(sizeof(voipintercept_t));
    memcpy(vint, &toadd, sizeof(voipintercept_t));
    HASH_ADD_KEYPTR(hh_liid, sync->voipintercepts, vint->liid, vint->liid_len,
            vint);

    fprintf(stderr, "received VOIP intercept %lu %s %s\n", vint->internalid,
            vint->liid, vint->sipuri);

    for (i = 0; i < sync->glob->registered_syncqs; i++) {

        push_sip_uri(sync->glob->syncsendqs[i], vint->sipuri);

        /* Forward all active CINs to our collector threads */
        push_all_active_voipstreams(sync->glob->syncsendqs[i], vint);

    }
}

static int new_ipintercept(collector_sync_t *sync, uint8_t *intmsg,
        uint16_t msglen) {

    ipintercept_t cept;
    libtrace_list_node_t *n;
    int i;

    if (decode_ipintercept_start(intmsg, msglen, &cept) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: received invalid IP intercept from provisioner.");
        return -1;
    }

    /* Check if we already have this intercept */
    n = sync->ipintercepts->head;
    while (n) {
        ipintercept_t *x = (ipintercept_t *)(n->data);
        if (strcmp(x->liid, cept.liid) == 0 &&
                strcmp(x->authcc, cept.authcc) == 0) {
            /* Duplicate LIID */

            /* OpenLI-internal fields that could change value
             * if the provisioner was restarted.
             */
            if (strcmp(x->username, cept.username) != 0) {
                logger(LOG_DAEMON,
                        "OpenLI: duplicate IP ID %s seen, but targets are different (was %s, now %s).",
                        x->liid, x->username, cept.username);
                return -1;
            }
            x->internalid = cept.internalid;
            x->awaitingconfirm = 0;
            x->active = 1;
            /* our collector threads should already know about this intercept?
             */
            return 0;
        }

        n = n->next;
    }

    /* TODO try to find a CIN and IP address for this intercept, based on our
     * known RADIUS (or equivalent) state.
     *
     * Only push the intercept to the processing threads once we've
     * assigned a suitable CIN.
     */

    /* Temporary hard-coded mappings for testing.
     * Please remove once proper RADIUS support is added.
     */

    fprintf(stderr, "received IP intercept %lu %s %s\n", cept.internalid,
            cept.liid, cept.username);
    if (n == NULL) {
        temporary_map_user_to_address(&cept);

        libtrace_list_push_front(sync->ipintercepts, &cept);
        n = sync->ipintercepts->head;
    }

    for (i = 0; i < sync->glob->registered_syncqs; i++) {
        push_single_intercept(sync->glob->syncsendqs[i],
                (ipintercept_t *)(n->data));
    }

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
            case OPENLI_PROTO_ANNOUNCE_MEDIATOR:
                ret = new_mediator(sync, provmsg, msglen);
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
            case OPENLI_PROTO_NOMORE_INTERCEPTS:
                disable_unconfirmed_intercepts(sync);
                break;
            case OPENLI_PROTO_NOMORE_MEDIATORS:
                finish_init_mediators(sync);
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

static inline void touch_all_intercepts(libtrace_list_t *intlist) {
    libtrace_list_node_t *n;
    ipintercept_t *ipint;

    /* Set all intercepts to be "awaiting confirmation", i.e. if the
     * provisioner doesn't announce them in its initial batch of
     * intercepts then they are to be halted.
     */
    n = intlist->head;
    while (n) {
        ipint = (ipintercept_t *)(n->data);
        ipint->awaitingconfirm = 1;
        n = n->next;
    }
}

static inline void touch_all_voipintercepts(voipintercept_t *vints) {
    voipintercept_t *v;

    for (v = vints; v != NULL; v = v->hh_liid.next) {
        v->awaitingconfirm = 1;
    }
}

static inline void disconnect_provisioner(collector_sync_t *sync) {

    struct epoll_event ev;
    openli_export_recv_t expmsg;

    destroy_net_buffer(sync->outgoing);
    destroy_net_buffer(sync->incoming);

    sync->outgoing = NULL;
    sync->incoming = NULL;

    if (epoll_ctl(sync->glob->sync_epollfd, EPOLL_CTL_DEL, sync->instruct_fd,
            &ev) == -1) {
        logger(LOG_DAEMON, "OpenLI: error de-registering provisioner fd: %s.",
                strerror(errno));
    }

    close(sync->instruct_fd);
    sync->instruct_fd = -1;

    /* Leave all intercepts running, but require them to be confirmed
     * as active when we reconnect to the provisioner.
     */
    touch_all_intercepts(sync->ipintercepts);
    touch_all_voipintercepts(sync->voipintercepts);

    /* Same with mediators -- keep exporting to them, but flag them to be
     * disconnected if they are not announced after we reconnect. */
    expmsg.type = OPENLI_EXPORT_FLAG_MEDIATORS;
    expmsg.data.packet = NULL;

    libtrace_message_queue_put(&(sync->exportq), &expmsg);


}

static void push_all_active_intercepts(libtrace_list_t *intlist,
        libtrace_message_queue_t *q) {

    libtrace_list_node_t *n = intlist->head;
    ipintercept_t *orig;

    while (n) {
        orig = (ipintercept_t *)(n->data);
        if (!orig->active) {
            n = n->next;
            continue;
        }
        push_single_intercept(q, orig);

        n = n->next;
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
                disconnect_provisioner(sync);
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
                    disconnect_provisioner(sync);
                    return 0;
                }
            } else {
                if (recv_from_provisioner(sync) <= 0) {
                    disconnect_provisioner(sync);
                    return 0;
                }
            }
            continue;
        }

        if (syncev->fdtype == SYNC_EVENT_SIP_TIMEOUT) {
            struct rtpstreaminf *thisrtp;

            thisrtp = (struct rtpstreaminf *)(syncev->ptr);

            /* TODO remove this once we're sure this actually works */
            logger(LOG_DAEMON,
                    "OpenLI TESTING: RTP stream %s:%u has timed out",
                    thisrtp->streamkey, thisrtp->cin);

        }

        /* Must be from a processing thread queue, figure out which one */
        libtrace_message_queue_get((libtrace_message_queue_t *)(syncev->ptr),
                (void *)(&recvd));

        /* If a hello from a thread, push all active intercepts back */
        if (recvd.type == OPENLI_UPDATE_HELLO) {
            voipintercept_t *v;

            push_all_active_intercepts(sync->ipintercepts, recvd.data.replyq);
            for (v = sync->voipintercepts; v != NULL; v = v->hh_liid.next) {
                push_sip_uri(recvd.data.replyq, v->sipuri);
                push_all_active_voipstreams(recvd.data.replyq, v);
            }
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

void register_sync_queues(collector_global_t *glob,
        libtrace_message_queue_t *recvq, libtrace_message_queue_t *sendq) {

    struct epoll_event ev;
    sync_epoll_t *syncev;
    int ind;

    syncev = (sync_epoll_t *)malloc(sizeof(sync_epoll_t));
    syncev->fdtype = SYNC_EVENT_PROC_QUEUE;
    syncev->fd = libtrace_message_queue_get_fd(recvq);
    syncev->ptr = recvq;

    ev.data.ptr = (void *)syncev;
    ev.events = EPOLLIN;

    if (epoll_ctl(glob->sync_epollfd, EPOLL_CTL_ADD, syncev->fd, &ev) == -1) {
        /* TODO Do something? */
        logger(LOG_DAEMON, "OpenLI: failed to register processor->sync queue: %s",
                strerror(errno));
    }

    pthread_mutex_lock(&(glob->syncq_mutex));
    ind  = glob->registered_syncqs;

    glob->syncsendqs[ind] = sendq;
    glob->syncepollevs[ind] = syncev;
    glob->registered_syncqs ++;
    pthread_mutex_unlock(&(glob->syncq_mutex));

    printf("Registered sync queue %d\n", ind);

    push_hello_message(recvq, sendq);
}

void halt_processing_threads(collector_global_t *glob) {
    int i;

    for (i = 0; i < glob->inputcount; i++) {
        trace_pstop(glob->inputs[i].trace);
    }
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
