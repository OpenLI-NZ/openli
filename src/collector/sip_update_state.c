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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <libtrace.h>
#include "sipparsing.h"
#include "sip_worker.h"
#include "logger.h"
#include "util.h"
#include "location.h"

#define SIP_REDIRECT_GRACE_PERIOD 5

static openli_sip_identity_t *sipid_matches_target(libtrace_list_t *targets,
        openli_sip_identity_t *sipid) {

    libtrace_list_node_t *n;

    if (sipid->username == NULL) {
        return NULL;
    }

    n = targets->head;
    while (n) {
        openli_sip_identity_t *x = *((openli_sip_identity_t **) (n->data));
        n = n->next;

        if (x->active == 0) {
            continue;
        }

        if (x->username == NULL || strlen(x->username) == 0) {
            continue;
        }

        /* treat a '*' at the beginning of a SIP username as a wildcard,
         * so users can specify phone numbers as targets without worrying
         * about all possible combinations of (with area codes, without
         * area codes, with '+', without '+', etc.)
         */
        if (x->username[0] == '*') {
            int termlen = strlen(x->username) - 1;
            int idlen = strlen(sipid->username);

            if (idlen < termlen) {
                continue;
            }
            if (strncmp(x->username + 1, sipid->username + (idlen - termlen),
                    termlen) != 0) {
                continue;
            }
        } else if (strcmp(x->username, sipid->username) != 0) {
            continue;
        }

        if (x->realm == NULL || strcmp(x->realm, sipid->realm) == 0) {
            return x;
        }
    }
    return NULL;
}

int extract_sip_identities(openli_sip_parser_t *parser,
        openli_sip_identity_set_t *idset, uint8_t log_error) {

    int i, unused;
    openli_sip_identity_t authid;

    memset(idset, 0, sizeof(openli_sip_identity_set_t));

    if (get_sip_to_uri_identity(parser, &(idset->touriid)) < 0) {
        if (log_error) {
            logger(LOG_INFO,
                    "OpenLI: unable to derive SIP identity from To: URI");
        }
        return -1;
    }

    if (get_sip_from_uri_identity(parser, &(idset->fromuriid)) < 0) {
        if (log_error) {
            logger(LOG_INFO,
                    "OpenLI: unable to derive SIP identity from From: URI");
        }
        return -1;
    }

    if (get_sip_proxy_auth_identity(parser, 0, &(idset->proxyauthcount),
            &authid, log_error) < 0) {
        return -1;
    }

    if (idset->proxyauthcount > 0) {
        idset->proxyauths = calloc(idset->proxyauthcount,
                sizeof(openli_sip_identity_t));
        memcpy(&(idset->proxyauths[0]), &authid, sizeof(openli_sip_identity_t));

        for (i = 1; i < idset->proxyauthcount; i++) {
            if (get_sip_proxy_auth_identity(parser, i, &unused,
                    &(idset->proxyauths[i]), log_error) < 0) {
                return -1;
            }
        }
    }

    if (get_sip_auth_identity(parser, 0, &(idset->regauthcount),
            &authid, log_error) < 0) {
        return -1;
    }

    if (idset->regauthcount > 0) {
        idset->regauths = calloc(idset->regauthcount,
                sizeof(openli_sip_identity_t));
        memcpy(&(idset->regauths[0]), &authid, sizeof(openli_sip_identity_t));

        for (i = 1; i < idset->regauthcount; i++) {
            if (get_sip_auth_identity(parser, i, &unused,
                    &(idset->regauths[i]), log_error) < 0) {
                return -1;
            }
        }
    }

    if (get_sip_identity_by_header_name(parser, &(idset->passertid),
                "P-Asserted-Identity") < 0) {
        if (log_error) {
            logger(LOG_INFO,
                    "OpenLI: error while extracting P-Asserted-Identity from SIP message");
        }
        return -1;
    }

    if (get_sip_identity_by_header_name(parser, &(idset->ppreferredid),
                "P-Preferred-Identity") < 0) {
        if (log_error) {
            logger(LOG_INFO,
                    "OpenLI: error while extracting P-Preferred-Identity from SIP message");
        }
        return -1;
    }

    if (get_sip_identity_by_header_name(parser, &(idset->remotepartyid),
                "Remote-Party-ID") < 0) {
        if (log_error) {
            logger(LOG_INFO,
                    "OpenLI: error while extracting Remote-Party from SIP message");
        }
        return -1;
    }

    return 0;
}

openli_sip_identity_t *match_sip_target_against_identities(
        libtrace_list_t *targets, openli_sip_identity_set_t *idset,
        uint8_t trust_from) {

    int i;
    openli_sip_identity_t *matched = NULL;

    /* Try the To: uri first */
    if ((matched = sipid_matches_target(targets, &(idset->touriid)))) {
        return matched;
    }
    if ((matched = sipid_matches_target(targets, &(idset->passertid)))) {
        return matched;
    }
    if ((matched = sipid_matches_target(targets, &(idset->remotepartyid)))) {
        return matched;
    }
    for (i = 0; i < idset->proxyauthcount; i++) {
        if ((matched = sipid_matches_target(targets, &(idset->proxyauths[i]))))
        {
            return matched;
        }
    }
    for (i = 0; i < idset->regauthcount; i++) {
        if ((matched = sipid_matches_target(targets, &(idset->regauths[i]))))
        {
            return matched;
        }
    }

    if (trust_from && (matched = sipid_matches_target(targets, &(idset->ppreferredid)))) {
        return matched;
    }

    if (trust_from && (matched = sipid_matches_target(targets,
            &(idset->fromuriid)))) {
        return matched;
    }

    return NULL;
}

void release_openli_sip_identity_set(openli_sip_identity_set_t *idset) {
    if (idset->proxyauthcount > 0) {
        free(idset->proxyauths);
    }
    if (idset->regauthcount > 0) {
        free(idset->regauths);
    }
    if (idset->passertid.username) {
        free(idset->passertid.username);
    }
    if (idset->passertid.realm) {
        free(idset->passertid.realm);
    }
    if (idset->ppreferredid.username) {
        free(idset->ppreferredid.username);
    }
    if (idset->ppreferredid.realm) {
        free(idset->ppreferredid.realm);
    }
    if (idset->remotepartyid.username) {
        free(idset->remotepartyid.username);
    }
    if (idset->remotepartyid.realm) {
        free(idset->remotepartyid.realm);
    }
    if (idset->fromuriid.username) {
        free(idset->fromuriid.username);
    }
    if (idset->fromuriid.realm) {
        free(idset->fromuriid.realm);
    }
    if (idset->touriid.username) {
        free(idset->touriid.username);
    }
    if (idset->touriid.realm) {
        free(idset->touriid.realm);
    }
}

static void populate_sdp_identifier(openli_sip_parser_t *sipparser,
        sip_sdp_identifier_t *sdpo, uint8_t log_bad_sip, char *callid) {

    char *sessid, *sessversion, *sessaddr, *sessuser;

    memset(sdpo->address, 0, sizeof(sdpo->address));
    memset(sdpo->username, 0, sizeof(sdpo->username));

    sessid = get_sip_session_id(sipparser);
    sessversion = get_sip_session_version(sipparser);
    sessaddr = get_sip_session_address(sipparser);
    sessuser = get_sip_session_username(sipparser);

    if (sessid != NULL) {
        errno = 0;
        sdpo->sessionid = strtoul(sessid, NULL, 0);
        if (errno != 0) {
            if (log_bad_sip) {
                logger(LOG_INFO, "OpenLI: SIP worker saw an invalid session ID in SIP packet %s", sessid);
            }
            sessid = NULL;
            sdpo->sessionid = 0;
        }
    } else {
        sdpo->sessionid = 0;
    }

    if (sessversion != NULL) {
        errno = 0;
        sdpo->version = strtoul(sessversion, NULL, 0);
        if (errno != 0) {
            if (log_bad_sip) {
                logger(LOG_INFO, "OpenLI: invalid version in SIP packet %s",
                        sessid);
            }
            sessversion = NULL;
            sdpo->version = 0;
        }
    } else {
        sdpo->version = 0;
    }

    if (sessaddr != NULL) {
        strncpy(sdpo->address, sessaddr, sizeof(sdpo->address) - 1);
    } else {
        strncpy(sdpo->address, callid, sizeof(sdpo->address) - 1);
    }

    if (sessuser != NULL) {
        strncpy(sdpo->username, sessuser, sizeof(sdpo->username) - 1);
    } else {
        strncpy(sdpo->username, "unknown", sizeof(sdpo->username) - 1);
    }


}

static uint8_t apply_invite_cseq_to_call(rtpstreaminf_t *thisrtp,
        char *invitecseq, openli_export_recv_t *irimsg,
        etsili_iri_type_t iritype) {

    uint8_t dir = 0xff;

    if (thisrtp->invitecseq && invitecseq &&
            strcmp(thisrtp->invitecseq, invitecseq) == 0) {
        // duplicate of the original INVITE, can mostly ignore
        dir = 0xff;
    } else if (iritype == ETSILI_IRI_BEGIN) {
        // this is the original INVITE, so save the source IP as the
        // inviter
        memcpy(thisrtp->inviter, irimsg->data.ipmmiri.ipsrc, 16);
        thisrtp->inviterport = irimsg->data.ipmmiri.srcport;
        dir = 0;
    } else if (memcmp(thisrtp->inviter, irimsg->data.ipmmiri.ipsrc,
                16) == 0 &&
            irimsg->data.ipmmiri.srcport == thisrtp->inviterport) {
        // source IP matches the original inviter, so this is client->server
        dir = 0;
    } else if (memcmp(thisrtp->inviter, irimsg->data.ipmmiri.ipdest,
                16) == 0 &&
            irimsg->data.ipmmiri.dstport == thisrtp->inviterport) {
        // this must be server->client
        dir = 1;
    }

    /* A bit of an explanation of invitecseq, inviterport, inviter
     *
     * This is mainly dedicated to resolving issues that arise
     * when we see both sides of a proxied SIP session (i.e.
     * A->B followed by B->C and the reverse for the opposite
     * direction).
     *
     * In these cases, we have to be careful to only track the
     * RTP session for ONE of the sides of the proxying, otherwise
     * we get confused and try to intercept RTP streams that don't
     * exist (such as the outgoing port from A->B and the incoming
     * port for C->B).
     *
     * To further complicate matters, we can see reversed direction
     * INVITEs (e.g. on call connection to confirm the media port)
     * so we cannot assume that an INVITE is coming from the caller.
     *
     * So what I'm trying to do here is two things:
     *  1. always track the RTP stream for A->B session only.
     *  2. don't screw up if we see a reversed INVITE.
     *
     * I'm doing this by retaining the source IP address and port of
     * the initial INVITE for any given cseq. Then, when I see the
     * a 183 or 200 with that IP/port pair as the destination then
     * that response must belong to the initial A->B INVITE.
     *
     * For subsequent INVITEs, we only pay attention when the initial
     * inviting IP address was involved (either as a sender or receiver)
     * so if a reverse INVITE from C->B won't be looked at for RTP stream
     * tracking purposes until it is proxied to the B->A link.
     *
     * There is one edge case where this approach could cause issues
     * and that is where the proxy is not A->B and B->C, but instead is A->B
     * and B->A. I think that the addition of port numbers to the "inviter"
     * definition should resolve this, but I also wouldn't be surprised if
     * there are further issues down the line.
     */
    if (invitecseq) {
        if (dir != 0xff && thisrtp->invitecseq == NULL) {
            // this is the first INVITE for the call
            thisrtp->invitecseq = strdup(invitecseq);
        } else if (thisrtp->invitecseq != NULL &&
                strcmp(invitecseq, thisrtp->invitecseq) == 0) {
            // this is a copy of the original INVITE
        } else if (dir != 0xff && thisrtp->invitecseq != NULL) {
            // this is a subsequent INVITE
            free(thisrtp->invitecseq);
            thisrtp->invitecseq = NULL;
            thisrtp->invitecseq = strdup(invitecseq);
        }
    }

    return dir;
}

void purge_expired_sms_sessions(openli_sip_worker_t *sipworker) {
    struct timeval tv;
    sip_message_state_t *sms, *smstmp;
    voipintercept_t *vint, *vtmp;

    gettimeofday(&tv, NULL);
    HASH_ITER(hh_liid, sipworker->voipintercepts, vint, vtmp) {
        HASH_ITER(hh, vint->active_messages, sms, smstmp) {
            if (sms->created != 0 &&
                    tv.tv_sec - sms->created > SMS_SESSION_EXPIRY) {
                HASH_DELETE(hh, vint->active_messages, sms);
                free(sms->callid);
                free(sms);
            }
        }
    }
}

static int update_rtp_stream(rtpstreaminf_t *rtp, char *ipstr, char *portstr,
        char *mediatype, uint8_t dir) {

    int32_t port;
    struct sockaddr_storage *saddr;
    int family, i;
    struct sipmediastream *mstream = NULL;
    int changed = 0;

    errno = 0;
    port = strtoul(portstr, NULL, 0);

    if (errno != 0 || port > 65535) {
        return -1;
    }

    convert_ipstr_to_sockaddr(ipstr, &(saddr), &(family));

    for (i = 0; i < rtp->streamcount; i++) {
        if (strcmp(rtp->mediastreams[i].mediatype, mediatype) == 0) {
            mstream = &(rtp->mediastreams[i]);
            break;
        }
    }

    if (mstream == NULL) {
        if (rtp->streamcount > 0 && (rtp->streamcount %
                RTP_STREAM_ALLOC) == 0) {
            rtp->mediastreams = realloc(rtp->mediastreams,
                    (rtp->streamcount + RTP_STREAM_ALLOC) *
                        sizeof(struct sipmediastream));
            mstream = &(rtp->mediastreams[rtp->streamcount]);
        }
        mstream = &(rtp->mediastreams[rtp->streamcount]);
        rtp->streamcount ++;

        mstream->targetport = 0;
        mstream->otherport = 0;
        mstream->mediatype = strdup(mediatype);
    }

    /* SDP announcements always relate to the "sender" end of the connection */
    if (dir == ETSI_DIR_FROM_TARGET) {
        if (rtp->targetaddr) {
            /* has the address or port changed? should we warn? */
            if (memcmp(rtp->targetaddr, saddr, sizeof(struct sockaddr_storage))
                    != 0) {
                changed = 1;
            }
            free(rtp->targetaddr);
        }
        rtp->ai_family = family;
        rtp->targetaddr = saddr;
        if (port != mstream->targetport) {
            changed = 1;
        }
        mstream->targetport = (uint16_t)port;


    } else {
        if (rtp->otheraddr) {
            /* has the address or port changed? should we warn? */
            if (memcmp(rtp->otheraddr, saddr, sizeof(struct sockaddr_storage))
                    != 0) {
                changed = 1;
            }
            free(rtp->otheraddr);
        }
        rtp->ai_family = family;
        rtp->otheraddr = saddr;
        if (port != mstream->otherport) {
            changed = 1;
        }
        mstream->otherport = (uint16_t)port;
    }
    return changed;
}

static rtpstreaminf_t *create_new_voipcin(rtpstreaminf_t **activecins,
        uint32_t cin_id, voipintercept_t *vint, char *callid) {

    rtpstreaminf_t *newcin;

    newcin = create_rtpstream(vint, cin_id, callid);
    if (!newcin) {
        logger(LOG_INFO,
                "OpenLI: out of memory while creating new RTP stream in SIP worker thread");
        logger(LOG_INFO,
                "OpenLI: forcing collector to halt.");
        exit(-2);
    }

    HASH_ADD_KEYPTR(hh, *activecins, newcin->streamkey,
            strlen(newcin->streamkey), newcin);
    return newcin;
}

static sipregister_t *create_new_voip_registration(
        openli_sip_worker_t *sipworker, voipintercept_t *vint,
        char *callid, openli_sip_identity_t *targetuser, struct timeval *tv) {

    sipregister_t *newreg = NULL;
    uint32_t cin_id = 0;

    create_new_intercepted_voice_call(sipworker->call_state,
                sipworker->call_state_mutex, callid, NULL, NULL,
                targetuser, vint, sipworker->workerid, tv);

    HASH_FIND(hh, vint->active_registrations, callid, strlen(callid), newreg);
    if (!newreg) {
        cin_id = get_voice_call_cin_using_callid(sipworker->call_state,
                sipworker->call_state_mutex, callid);
        newreg = create_sipregister(vint, callid, cin_id);

        HASH_ADD_KEYPTR(hh, vint->active_registrations, newreg->callid,
                strlen(newreg->callid), newreg);
    }

    return newreg;
}

static int process_sip_register(openli_sip_worker_t *sipworker, char *callid,
        openli_export_recv_t *irimsg, libtrace_packet_t **pkts, int pkt_cnt,
        openli_location_t *locptr, int loc_cnt) {

    openli_sip_identity_t *matched = NULL;
    voipintercept_t *vint, *tmp;
    sipregister_t *sipreg;
    int exportcount = 0;
    uint8_t trust_sip_from;
    struct timeval tv;
    openli_sip_identity_set_t all_identities;

    locptr = NULL;
    loc_cnt = 0;

    if (extract_sip_identities(sipworker->sipparser, &all_identities,
            sipworker->debug.log_bad_sip) < 0) {
        sipworker->debug.log_bad_sip = 0;
        release_openli_sip_identity_set(&all_identities);
        return -1;
    }

    pthread_rwlock_rdlock(sipworker->shared_mutex);
    trust_sip_from = sipworker->shared->trust_sip_from;
    pthread_rwlock_unlock(sipworker->shared_mutex);

    gettimeofday(&tv, NULL);
    HASH_ITER(hh_liid, sipworker->voipintercepts, vint, tmp) {
        sipreg = NULL;

        matched = match_sip_target_against_identities(vint->targets,
                &all_identities, trust_sip_from);
        if (matched == NULL) {
            continue;
        }
        sipreg = create_new_voip_registration(sipworker, vint, callid, matched,
                &tv);
        if (!sipreg) {
            continue;
        }
        create_sip_ipmmiri(sipworker, vint, irimsg, ETSILI_IRI_REPORT,
                sipreg->cin, locptr, loc_cnt, pkts, pkt_cnt);
        exportcount += 1;
    }

    release_openli_sip_identity_set(&all_identities);

    return exportcount;

}

static rtpstreaminf_t *match_call_to_intercept(openli_sip_worker_t *sipworker,
        voipintercept_t *vint, uint32_t *cin,
        uint8_t trust_sip_from, struct timeval *tv,
        openli_sip_identity_set_t *all_identities,
        etsili_iri_type_t iritype,
        char *callid, char *sessionid, sip_sdp_identifier_t *sdpkey) {

    openli_sip_identity_t *matched = NULL;
    rtpstreaminf_t *thisrtp;
    char rtpkey[256];
    int r = 0;

    matched = match_sip_target_against_identities(vint->targets,
            all_identities, trust_sip_from);
    // This is a new call leg, but only track it if an intercept target
    // is a participant
    if (iritype == ETSILI_IRI_BEGIN) {
        if (matched == NULL) {
            return NULL;
        }

        r = create_new_intercepted_voice_call(sipworker->call_state,
                    sipworker->call_state_mutex, callid, sdpkey, sessionid,
                    matched, vint, sipworker->workerid, tv);
        if (r < 0) {
            return NULL;
        }
    }

    /*
    if (r == 0) {
        update_voice_call_participant(sipworker->call_state,
                sipworker->call_state_mutex, callid, matched);
    }
    */

    *cin = get_voice_call_cin_using_callid(sipworker->call_state,
            sipworker->call_state_mutex, callid);
    if (cin == 0) {
        return NULL;
    }

    snprintf(rtpkey, 256, "%s-%u-%s", vint->common.liid, *cin, callid);
    HASH_FIND(hh, vint->active_cins, rtpkey, strlen(rtpkey), thisrtp);

    if (thisrtp == NULL && (iritype == ETSILI_IRI_BEGIN || matched != NULL)) {
        thisrtp = create_new_voipcin(&(vint->active_cins), *cin, vint,
                callid);
    }
    return thisrtp;
}

static int extract_media_streams_from_sdp(rtpstreaminf_t *thisrtp,
        openli_sip_parser_t *sipparser, uint8_t dir) {

    int i = 1, changed;
    char *ipstr, *portstr, *mediatype;

    ipstr = get_sip_media_ipaddr(sipparser);
    portstr = get_sip_media_port(sipparser, 0);
    mediatype = get_sip_media_type(sipparser, 0);

    while (ipstr && portstr && mediatype) {
        changed = update_rtp_stream(thisrtp, ipstr, portstr, mediatype, dir);
        if (changed == -1) {
            return -1;
        }
        portstr = get_sip_media_port(sipparser, i);
        mediatype = get_sip_media_type(sipparser, i);
        i++;

        if (changed) {
            thisrtp->changed = 1;
        }
    }

    return i - 1;
}

static int process_sip_invite(openli_sip_worker_t *sipworker, char *callid,
        openli_export_recv_t *irimsg, libtrace_packet_t **pkts, int pkt_cnt,
        openli_location_t *locptr, int loc_cnt, sip_sdp_identifier_t *sdpo) {


    voipintercept_t *vint, *tmp;
    uint8_t trust_sip_from;
    etsili_iri_type_t iritype = ETSILI_IRI_BEGIN;
    rtpstreaminf_t *thisrtp;
    uint32_t cin = 0;
    struct timeval tv;
    int exportcount = 0, r, begin;
    openli_sip_identity_set_t all_identities;
    char *invitecseq = NULL;
    uint8_t dir = 0xff;
    char *session_id = NULL;

    if (extract_sip_identities(sipworker->sipparser, &all_identities,
            sipworker->debug.log_bad_sip) < 0) {
        sipworker->debug.log_bad_sip = 0;
        return -1;
    }

    pthread_rwlock_rdlock(sipworker->shared_mutex);
    trust_sip_from = sipworker->shared->trust_sip_from;
    pthread_rwlock_unlock(sipworker->shared_mutex);

    gettimeofday(&tv, NULL);
    invitecseq = get_sip_cseq(sipworker->sipparser);

    get_sip_header_session_id(sipworker->sipparser, &session_id);

    begin = find_existing_voice_call(sipworker->call_state,
            sipworker->call_state_mutex, callid, sdpo, session_id);
    if (begin == 0) {
        iritype = ETSILI_IRI_CONTINUE;
    } else if (begin == 1) {
        iritype = ETSILI_IRI_BEGIN;
    }

    HASH_ITER(hh_liid, sipworker->voipintercepts, vint, tmp) {
        if (sipworker->sipparser->badsip) {
            break;
        }
        thisrtp = match_call_to_intercept(sipworker, vint,
                &cin, trust_sip_from, &tv, &all_identities, iritype,
                callid, session_id, sdpo);
        if (thisrtp == NULL) {
            continue;
        }
        thisrtp->changed = 0;

        dir = apply_invite_cseq_to_call(thisrtp, invitecseq, irimsg, iritype);
        if (dir != 0xff) {
            r = extract_media_streams_from_sdp(thisrtp, sipworker->sipparser,
                        dir);
            if (r < 0) {
                if (sipworker->debug.log_bad_sip) {
                    logger(LOG_INFO,
                            "OpenLI: error while extracting media streams from SDP -- SIP messages may be malformed");
                }
                sipworker->sipparser->badsip = 1;
                continue;
            }
        }

        create_sip_ipmmiri(sipworker, vint, irimsg, iritype, (int64_t)cin,
                locptr, loc_cnt, pkts, pkt_cnt);
        exportcount ++;
    }

    if (invitecseq) {
        free(invitecseq);
    }
    if (session_id) {
        free(session_id);
    }
    release_openli_sip_identity_set(&all_identities);
    if (sipworker->sipparser->badsip) {
        return -1;
    }
    return exportcount;
}

static sip_message_state_t *match_message_to_intercept(voipintercept_t *vint,
        char *callid, uint8_t trust_sip_from, struct timeval *tv,
        openli_sip_identity_set_t *all_identities) {

    openli_sip_identity_t *matched = NULL;
    sip_message_state_t *msg = NULL;

    matched = match_sip_target_against_identities(vint->targets,
            all_identities, trust_sip_from);
    if (matched == NULL) {
        return NULL;
    }

    HASH_FIND(hh, vint->active_messages, callid, strlen(callid), msg);
    if (!msg) {
        msg = calloc(1, sizeof(sip_message_state_t));
        msg->callid = strdup(callid);
        msg->cin = hashlittle(callid, strlen(callid), 0xbeeffecc);
        msg->cin = (msg->cin % (uint32_t)(pow(2, 31)));
        msg->created = tv->tv_sec;

        HASH_ADD_KEYPTR(hh, vint->active_messages, msg->callid,
                strlen(msg->callid), msg);

        add_target_call_reference(vint, matched, msg->cin, NULL, msg);
    }
    return msg;

}

static int process_sip_message(openli_sip_worker_t *sipworker, char *callid,
        openli_export_recv_t *irimsg, libtrace_packet_t **pkts, int pkt_cnt,
        openli_location_t *locptr, int loc_cnt) {

    voipintercept_t *vint, *tmp;
    uint8_t trust_sip_from;
    etsili_iri_type_t iritype = ETSILI_IRI_BEGIN;
    struct timeval tv;
    int exportcount = 0;
    openli_sip_identity_set_t all_identities;
    sip_message_state_t *msg = NULL;

    if (extract_sip_identities(sipworker->sipparser, &all_identities,
            sipworker->debug.log_bad_sip) < 0) {
        sipworker->debug.log_bad_sip = 0;
        return -1;
    }

    pthread_rwlock_rdlock(sipworker->shared_mutex);
    trust_sip_from = sipworker->shared->trust_sip_from;
    pthread_rwlock_unlock(sipworker->shared_mutex);

    gettimeofday(&tv, NULL);

    HASH_ITER(hh_liid, sipworker->voipintercepts, vint, tmp) {
        if (sipworker->sipparser->badsip) {
            break;
        }
        msg = match_message_to_intercept(vint, callid, trust_sip_from, &tv,
                &all_identities);
        if (msg == NULL) {
            continue;
        }
        if (vint->common.tomediate == OPENLI_INTERCEPT_OUTPUTS_IRIONLY) {
            /* TODO set a flag so that the encoder knows we need to use
             * iRIOnlySIPMessage as our IPMMIRIContents
             */
            mask_sms_message_content(irimsg->data.ipmmiri.content,
                    irimsg->data.ipmmiri.contentlen);
        }

        create_sip_ipmmiri(sipworker, vint, irimsg, iritype,
                (int64_t)msg->cin, locptr, loc_cnt, pkts, pkt_cnt);
        exportcount ++;
    }

    release_openli_sip_identity_set(&all_identities);
    if (sipworker->sipparser->badsip) {
        return -1;
    }
    return exportcount;
}

static int process_sip_response(openli_sip_worker_t *sipworker,
        rtpstreaminf_t *thisrtp,
        etsili_iri_type_t *iritype, openli_export_recv_t *irimsg) {

    char *cseqstr;
    uint8_t dir = 0xff;
    int r = 0;
    char *mediatype = NULL;

    if (!thisrtp->invitecseq && !thisrtp->byecseq) {
        return 0;
    }

    if (memcmp(thisrtp->inviter, irimsg->data.ipmmiri.ipsrc, 16) == 0 &&
            thisrtp->inviterport == irimsg->data.ipmmiri.srcport) {
        dir = 0;
    } else if (memcmp(thisrtp->inviter, irimsg->data.ipmmiri.ipdest, 16) == 0 &&
            thisrtp->inviterport == irimsg->data.ipmmiri.dstport) {
        dir = 1;
    }

    cseqstr = get_sip_cseq(sipworker->sipparser);

    if (thisrtp->invitecseq && strcmp(thisrtp->invitecseq, cseqstr) == 0) {
        mediatype = get_sip_media_type(sipworker->sipparser, 0);
        if (mediatype == NULL) {
            goto responseover;
        }
        if (dir == 1) {
            r = extract_media_streams_from_sdp(thisrtp, sipworker->sipparser,
                        dir);
            if (r < 0) {
                if (sipworker->debug.log_bad_sip) {
                    logger(LOG_INFO,
                            "OpenLI: error while extracting media streams from SDP -- SIP messages may be malformed");
                }
                sipworker->sipparser->badsip = 1;
            }
            if (thisrtp->changed) {
                if (sip_worker_announce_rtp_streams(sipworker, thisrtp)) {
                    if (thisrtp->invitecseq) {
                        free(thisrtp->invitecseq);
                        thisrtp->invitecseq = NULL;
                    }
                }
            }
        }
    } else if (thisrtp->byecseq && strcmp(thisrtp->byecseq, cseqstr) == 0 &&
            thisrtp->byematched == 0) {
        sip_worker_conclude_sip_call(sipworker, thisrtp);
        *iritype = ETSILI_IRI_END;
    }

responseover:
    free(cseqstr);
    if (sipworker->sipparser->badsip) {
        return -1;
    }
    return 0;

}

static int process_sip_other(openli_sip_worker_t *sipworker, char *callid,
        openli_export_recv_t *irimsg, libtrace_packet_t **pkts, int pkt_cnt,
        openli_location_t *locptr, int loc_cnt) {

    voipintercept_t *vint, *tmp;
    sipregister_t *findreg = NULL;
    char rtpkey[256];
    rtpstreaminf_t *thisrtp;
    etsili_iri_type_t iritype = ETSILI_IRI_CONTINUE;
    int exportcount = 0;
    uint32_t cin;
    sip_message_state_t *msg;

    cin = get_voice_call_cin_using_callid(sipworker->call_state,
            sipworker->call_state_mutex, callid);

    if (sipworker->sipparser->badsip) {
        return 0;
    }

    HASH_ITER(hh_liid, sipworker->voipintercepts, vint, tmp) {
        HASH_FIND(hh, vint->active_registrations, callid, strlen(callid),
                findreg);
        HASH_FIND(hh, vint->active_messages, callid, strlen(callid), msg);

        if (cin == 0 && !msg) {
            continue;
        }

        if (findreg) {
            create_sip_ipmmiri(sipworker, vint, irimsg,
                    ETSILI_IRI_REPORT, findreg->cin, NULL, 0, pkts,
                    pkt_cnt);
            exportcount ++;
            continue;
        }

        if (msg) {
            create_sip_ipmmiri(sipworker, vint, irimsg,
                    ETSILI_IRI_END, msg->cin, locptr, loc_cnt, pkts,
                    pkt_cnt);
            exportcount ++;
            continue;
        }

        snprintf(rtpkey, 256, "%s-%u-%s", vint->common.liid, cin, callid);
        HASH_FIND(hh, vint->active_cins, rtpkey, strlen(rtpkey), thisrtp);
        if (thisrtp == NULL) {
            continue;
        }

        if (sip_is_200ok(sipworker->sipparser)) {
            if (process_sip_response(sipworker, thisrtp, &iritype,
                        irimsg) < 0) {
                continue;
            }
        }
        /* Check for 183 Session Progress, as this can contain RTP info */
        /* Also check for 180, which can be handled in more or less the
         * same way from our perspective...
         */
        else if (sip_is_183sessprog(sipworker->sipparser) ||
                sip_is_180ringing(sipworker->sipparser)) {
            if (process_sip_response(sipworker, thisrtp, &iritype,
                        irimsg) < 0) {
                continue;
            }
        }

        else if ((sip_is_bye(sipworker->sipparser) ||
                    sip_is_cancel(sipworker->sipparser)) &&
                !thisrtp->byematched) {
            if (thisrtp->byecseq) {
                free(thisrtp->byecseq);
            }
            thisrtp->byecseq = get_sip_cseq(sipworker->sipparser);
        }

        if (thisrtp->byematched && iritype != ETSILI_IRI_END) {
            /* All post-END IRIs must be REPORTs */
            iritype = ETSILI_IRI_REPORT;
        }

        create_sip_ipmmiri(sipworker, vint, irimsg, iritype, cin,
               locptr, loc_cnt, pkts, pkt_cnt);
        exportcount += 1;

    }

    if (iritype == ETSILI_IRI_END) {
    /* If another worker has redirected SIP to us for this call, let them
     * know that it is over so they can remove it from their redirection
     * map.
     */
        conclude_redirected_sip_call(sipworker, callid);
    }


    if (sipworker->sipparser->badsip) {
        return -1;
    }
    return exportcount;
}

void redirect_sip_other_workers(openli_sip_worker_t *sipworker,
        libtrace_packet_t **pkts, int pkt_cnt, char *callid) {

    /* Don't redirect if the collector has just started up
     * as we'll most likely start capturing in the middle of a bunch
     * of ongoing SIP sessions and it is a waste of time to redirect
     * them all.
     */

    struct timeval tv;
    int i;
    char *cseq = NULL, *ptr = NULL;
    tv.tv_sec = 0;
    pthread_rwlock_rdlock(sipworker->shared_mutex);
    if (sipworker->shared->disable_sip_redirect) {
        pthread_rwlock_unlock(sipworker->shared_mutex);
        return;
    }
    pthread_rwlock_unlock(sipworker->shared_mutex);

    for (i = 0; i < pkt_cnt; i++) {
        if (pkts[i] == NULL) {
            continue;
        }
        tv = trace_get_timeval(pkts[i]);
        break;
    }

    if (tv.tv_sec == 0 || tv.tv_sec - sipworker->started <
            SIP_REDIRECT_GRACE_PERIOD) {
        return;
    }

    /* Don't bother forwarding OPTIONS or REGISTER messages -- they
     * should definitely be using the same 5-tuple for both directions
     * and, even if they didn't, the amount of work we'd be doing to
     * move these packets around far outweighs any benefit from it
     */
    cseq = get_sip_cseq(sipworker->sipparser);
    ptr = strtok(cseq, " ");
    if (ptr == NULL) {
        free(cseq);
        return;
    }
    ptr = strtok(NULL, " ");
    if (ptr == NULL) {
        free(cseq);
        return;
    }

    if (strcasecmp(ptr, "OPTIONS") == 0 || strcasecmp(ptr, "REGISTER") == 0)
    {
        free(cseq);
        return;
    }
    redirect_sip_worker_packets(sipworker, callid, pkts, pkt_cnt);
    free(cseq);
}

int sipworker_update_sip_state(openli_sip_worker_t *sipworker,
        libtrace_packet_t **pkts,
        int pkt_cnt, openli_export_recv_t *irimsg) {


    char *callid;
    sip_sdp_identifier_t sdpo;
    int iserr = 0;
    int ret = 0;
    openli_location_t *locptr = NULL;
    int loc_cnt = 0;

    if (sipworker->sipparser->badsip) {
        /* this should never happen, but just in case... */
        logger(LOG_INFO, "OpenLI: Invalid SIP message passed into sipworker_update_sip_state");
        iserr = 1;
        goto sipgiveup;
    }

    callid = get_sip_callid(sipworker->sipparser);

    if (callid == NULL) {
        if (sipworker->debug.log_bad_sip) {
            logger(LOG_INFO, "OpenLI: SIP message has no Call ID?");
        }
        sipworker->sipparser->badsip = 1;
        iserr = 1;
        goto sipgiveup;
    }

    get_sip_paccess_network_info(sipworker->sipparser, &locptr, &loc_cnt);
    if (sip_is_message(sipworker->sipparser)) {
        if (( ret = process_sip_message(sipworker, callid, irimsg, pkts,
                        pkt_cnt, locptr, loc_cnt)) < 0) {
            iserr = 1;
            if (sipworker->debug.log_bad_sip) {
                logger(LOG_INFO, "OpenLI: error in SIP worker thread %d while processing MESSAGE message", sipworker->workerid);
            }
            goto sipgiveup;
        }
    } else if (sip_is_invite(sipworker->sipparser)) {
        populate_sdp_identifier(sipworker->sipparser, &sdpo,
                sipworker->debug.log_bad_sip, callid);
        if (( ret = process_sip_invite(sipworker, callid, irimsg, pkts,
                        pkt_cnt, locptr, loc_cnt, &sdpo)) < 0) {
            iserr = 1;
            if (sipworker->debug.log_bad_sip) {
                logger(LOG_INFO, "OpenLI: error in SIP worker thread %d while processing INVITE message", sipworker->workerid);
            }
            goto sipgiveup;
        }
    } else if (sip_is_register(sipworker->sipparser)) {
        if (( ret = process_sip_register(sipworker, callid, irimsg, pkts,
                        pkt_cnt, locptr, loc_cnt)) < 0) {
            iserr = 1;
            if (sipworker->debug.log_bad_sip) {
                logger(LOG_INFO, "OpenLI: error in SIP worker thread %d while processing REGISTER message", sipworker->workerid);
            }
            goto sipgiveup;
        }
    } else {
        ret = process_sip_other(sipworker, callid, irimsg, pkts,
                        pkt_cnt, locptr, loc_cnt);

        if (ret < 0) {
            iserr = 1;
            if (sipworker->debug.log_bad_sip) {
                logger(LOG_INFO, "OpenLI: error in SIP worker thread %d while processing SIP message");
            }
            goto sipgiveup;
        }

        if (ret == 0 && sipworker->sipworker_threads > 1 && pkt_cnt > 0) {
            redirect_sip_other_workers(sipworker, pkts, pkt_cnt, callid);
        }

    }

sipgiveup:
    if (locptr) {
        free(locptr);
    }
    if (iserr) {
        pthread_mutex_lock(sipworker->stats_mutex);
        sipworker->stats->bad_sip_packets ++;
        pthread_mutex_unlock(sipworker->stats_mutex);
        return -1;
    }
    return 1;

}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
