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

#include "util.h"
#include "logger.h"
#include "intercept.h"

const char *cepttype_strings[] =
        {"Unknown", "IP", "VoIP", "Email"};

static inline void copy_intercept_common(intercept_common_t *src,
        intercept_common_t *dest) {

    dest->liid = strdup(src->liid);
    dest->authcc = strdup(src->authcc);
    dest->delivcc = strdup(src->delivcc);

    if (src->targetagency) {
        dest->targetagency = strdup(src->targetagency);
    } else {
        dest->targetagency = NULL;
    }

    dest->liid_len = src->liid_len;
    dest->authcc_len = src->authcc_len;
    dest->delivcc_len = src->delivcc_len;
    dest->destid = src->destid;
    dest->hi1_seqno = src->hi1_seqno;
    dest->tostart_time = src->tostart_time;
    dest->toend_time = src->toend_time;
    dest->tomediate = src->tomediate;
    dest->encrypt = src->encrypt;

    if (src->encryptkey) {
        dest->encryptkey = strdup(src->encryptkey);
    } else {
        dest->encryptkey = NULL;
    }
}

int update_modified_intercept_common(intercept_common_t *current,
        intercept_common_t *update, openli_intercept_types_t cepttype) {

    int encodingchanged = 0, keychanged = 0;

    if (cepttype < 0 || cepttype >= OPENLI_INTERCEPT_TYPE_EOL) {
        logger(LOG_INFO,
                "OpenLI: invalid intercept type passed to update_intercept_common(): %d\n", cepttype);
        return -1;
    }

    if (update->tostart_time != current->tostart_time ||
            update->toend_time != current->toend_time) {
        logger(LOG_INFO,
                "OpenLI: %s intercept %s has changed start / end times -- now %lu, %lu",
                cepttype_strings[cepttype], current->liid, update->tostart_time,
                update->toend_time);
        current->tostart_time = update->tostart_time;
        current->toend_time = update->toend_time;
    }

    if (update->tomediate != current->tomediate) {
        char space[1024];
        intercept_mediation_mode_as_string(update->tomediate, space,
                1024);
        logger(LOG_INFO,
                "OpenLI: %s intercept %s has changed mediation mode to: %s",
                cepttype_strings[cepttype], update->liid, space);
        current->tomediate = update->tomediate;
    }

    if (update->encrypt != current->encrypt) {
        char space[1024];
        intercept_encryption_mode_as_string(update->encrypt, space,
                1024);
        logger(LOG_INFO,
                "OpenLI: %s intercept %s has changed encryption mode to: %s",
                cepttype_strings[cepttype], update->liid, space);
        current->encrypt = update->encrypt;
        encodingchanged = 1;
    }

    if (current->encryptkey && update->encryptkey) {
        if (strcmp(current->encryptkey, update->encryptkey) != 0) {
            keychanged = 1;
        }
    } else if (current->encryptkey == NULL && update->encryptkey) {
        keychanged = 1;
    } else if (current->encryptkey && update->encryptkey == NULL) {
        keychanged = 1;
    }

    if (keychanged) {
        char *tmp;
        encodingchanged = 1;
        tmp = current->encryptkey;
        current->encryptkey = update->encryptkey;
        update->encryptkey = tmp;
    }

    if (strcmp(update->delivcc, current->delivcc) != 0 ||
            strcmp(update->authcc, current->authcc) != 0) {
        char *tmp;
        tmp = update->authcc;
        update->authcc = current->authcc;
        current->authcc = tmp;
        tmp = update->delivcc;
        update->delivcc = current->delivcc;
        current->delivcc = tmp;
        encodingchanged = 1;
    }

    return encodingchanged;
}

int are_sip_identities_same(openli_sip_identity_t *a,
        openli_sip_identity_t *b) {

    if (strcmp(a->username, b->username) != 0) {
        return 0;
    }

    if (a->realm == NULL && b->realm == NULL) {
        return 1;
    }

    if (a->realm == NULL || b->realm == NULL) {
        return 0;
    }

    if (strcmp(a->realm, b->realm) == 0) {
        return 1;
    }

    return 0;
}

void intercept_mediation_mode_as_string(intercept_outputs_t mode,
        char *space, int spacelen) {

    if (mode == OPENLI_INTERCEPT_OUTPUTS_IRIONLY) {
        snprintf(space, spacelen, "IRI-Only");
    } else if (mode == OPENLI_INTERCEPT_OUTPUTS_CCONLY) {
        snprintf(space, spacelen, "CC-Only");
    } else {
        snprintf(space, spacelen, "Both");
    }

}

void intercept_encryption_mode_as_string(payload_encryption_method_t method,
        char *space, int spacelen) {

    if (method == OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC) {
        snprintf(space, spacelen, "AES-192-CBC");
    } else {
        snprintf(space, spacelen, "None");
    }

}

sipregister_t *create_sipregister(voipintercept_t *vint, char *callid,
        uint32_t cin) {
    sipregister_t *newreg;

    newreg = (sipregister_t *)calloc(1, sizeof(sipregister_t));

    newreg->callid = strdup(callid);
    newreg->cin = cin;
    copy_intercept_common(&(vint->common), &(newreg->common));
    newreg->parent = vint;

    return newreg;
}

rtpstreaminf_t *create_rtpstream(voipintercept_t *vint, uint32_t cin) {

    rtpstreaminf_t *newcin = NULL;

    newcin = (rtpstreaminf_t *)malloc(sizeof(rtpstreaminf_t));
    if (!newcin) {
        return NULL;
    }

    newcin->streamkey = (char *)calloc(1, 256);
    if (!newcin->streamkey) {
        free(newcin);
        return NULL;
    }
    newcin->cin = cin;
    newcin->parent = vint;
    newcin->active = 0;
    newcin->changed = 0;
    newcin->targetaddr = NULL;
    newcin->otheraddr = NULL;
    newcin->ai_family = 0;
    newcin->seqno = 0;
    newcin->invitecseq = NULL;
    newcin->byecseq = NULL;
    newcin->timeout_ev = NULL;
    newcin->byematched = 0;

    newcin->streamcount = 0;
    newcin->mediastreams = calloc(RTP_STREAM_ALLOC,
            sizeof(struct sipmediastream));

    if (vint->options & (1UL << OPENLI_VOIPINT_OPTION_IGNORE_COMFORT)) {
        newcin->skip_comfort = 1;
    } else {
        newcin->skip_comfort = 0;
    }

    copy_intercept_common(&(vint->common), &(newcin->common));
    snprintf(newcin->streamkey, 256, "%s-%u", vint->common.liid, cin);
    return newcin;
}

rtpstreaminf_t *deep_copy_rtpstream(rtpstreaminf_t *orig) {
    rtpstreaminf_t *copy = NULL;
    int i;

    copy = (rtpstreaminf_t *)malloc(sizeof(rtpstreaminf_t));
    if (!copy) {
        return NULL;
    }

    copy->streamkey = strdup(orig->streamkey);
    copy->cin = orig->cin;
    copy->parent = NULL;
    copy->ai_family = orig->ai_family;
    copy->targetaddr = (struct sockaddr_storage *)malloc(
            sizeof(struct sockaddr_storage));

    if (!copy->targetaddr) {
        free(copy);
        return NULL;
    }

    memcpy(copy->targetaddr, orig->targetaddr, sizeof(struct sockaddr_storage));

    copy->otheraddr = (struct sockaddr_storage *)malloc(
            sizeof(struct sockaddr_storage));
    if (!copy->otheraddr) {
        free(copy->targetaddr);
        free(copy);
        return NULL;
    }

    copy->streamcount = orig->streamcount;
    copy->mediastreams = calloc(orig->streamcount,
            sizeof(struct sipmediastream));
    for (i = 0; i < copy->streamcount; i++) {
        copy->mediastreams[i].targetport = orig->mediastreams[i].targetport;
        copy->mediastreams[i].otherport = orig->mediastreams[i].otherport;
        copy->mediastreams[i].mediatype =
                strdup(orig->mediastreams[i].mediatype);
    }

    memcpy(copy->otheraddr, orig->otheraddr, sizeof(struct sockaddr_storage));
    copy->skip_comfort = orig->skip_comfort;
    copy->seqno = 0;
    copy->active = 1;
    copy->invitecseq = NULL;
    copy->byecseq = NULL;
    copy->timeout_ev = NULL;
    copy_intercept_common(&(orig->common), &(copy->common));

    return copy;
}


static inline void free_intercept_common(intercept_common_t *cept) {

    if (cept->liid) {
        free(cept->liid);
    }

    if (cept->authcc) {
        free(cept->authcc);
    }

    if (cept->delivcc) {
        free(cept->delivcc);
    }

    if (cept->targetagency) {
        free(cept->targetagency);
    }

    if (cept->encryptkey) {
        free(cept->encryptkey);
    }
}

char *list_email_targets(emailintercept_t *m, int maxchars) {

    char *space = NULL;
    int spaceused = 0;
    int required = 0;

    email_target_t *tgt, *tmp;

    HASH_ITER(hh, m->targets, tgt, tmp) {

        if (!space) {
            space = calloc(1, maxchars + 1);
        }

        if (!tgt->address) {
            continue;
        }

        required = strlen(tgt->address);
        if (spaceused > 0) {
            required += 1;
        }

        /* Only allowed a certain number of characters in the HI1 message, so
         * stop here */
        if (required > maxchars - spaceused) {
            break;
        }

        if (spaceused > 0) {
            *(space + spaceused) = ',';
            spaceused ++;
        }
        memcpy(space + spaceused, tgt->address, strlen(tgt->address));
        spaceused += strlen(tgt->address);
    }
    return space;
}
static void free_email_targets(emailintercept_t *m) {

    email_target_t *tgt, *tmp;

    HASH_ITER(hh, m->targets, tgt, tmp) {
        if (tgt->address) {
            free(tgt->address);
        }
        HASH_DELETE(hh, m->targets, tgt);
        free(tgt);
    }

}

void free_single_emailintercept(emailintercept_t *m) {

    free_intercept_common(&(m->common));
    if (m->targets) {
        free_email_targets(m);
    }
    free(m);
}

void free_single_ipintercept(ipintercept_t *cept) {
    static_ipranges_t *ipr, *tmp;

    free_intercept_common(&(cept->common));
    if (cept->username) {
        free(cept->username);
    }

    HASH_ITER(hh, cept->statics, ipr, tmp) {
        HASH_DELETE(hh, cept->statics, ipr);
        free_single_staticiprange(ipr);
    }

    free(cept);
}

void free_all_emailintercepts(emailintercept_t **mailintercepts) {
    emailintercept_t *cept, *tmp;
    HASH_ITER(hh_liid, *mailintercepts, cept, tmp) {
        HASH_DELETE(hh_liid, *mailintercepts, cept);
        free_single_emailintercept(cept);
    }
}

void free_all_ipintercepts(ipintercept_t **interceptlist) {

    ipintercept_t *cept, *tmp;

    HASH_ITER(hh_liid, *interceptlist, cept, tmp) {
        HASH_DELETE(hh_liid, *interceptlist, cept);
        free_single_ipintercept(cept);
    }
}

void free_voip_cinmap(voipcinmap_t *cins) {
    voipcinmap_t *c, *tmp;

    HASH_ITER(hh_callid, cins, c, tmp) {
        HASH_DELETE(hh_callid, cins, c);
        if (c->shared) {
            free(c->shared);
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

static inline void free_voip_sdpmap(voipsdpmap_t *sdps) {
    voipsdpmap_t *s, *tmp;

    HASH_ITER(hh_sdp, sdps, s, tmp) {
        HASH_DELETE(hh_sdp, sdps, s);
        if (s->username) {
            free(s->username);
        }
        if (s->realm) {
            free(s->realm);
        }
        free(s);
    }
}

static void free_voip_cins(rtpstreaminf_t *cins) {
    rtpstreaminf_t *rtp, *tmp;

    HASH_ITER(hh, cins, rtp, tmp) {
        HASH_DEL(cins, rtp);
        free_single_rtpstream(rtp);
    }

}

static void free_single_register(sipregister_t *sipr) {
    free_intercept_common(&(sipr->common));
    if (sipr->callid) {
        free(sipr->callid);
    }
    free(sipr);
}

static void free_voip_registrations(sipregister_t *sipregs) {
    sipregister_t *r, *tmp;

    HASH_ITER(hh, sipregs, r, tmp) {
        HASH_DEL(sipregs, r);
        free_single_register(r);
    }

}

char *list_sip_targets(voipintercept_t *v, int maxchars) {

    char *space = NULL;
    int spaceused = 0;
    int required = 0;

    openli_sip_identity_t *sipid;
    libtrace_list_node_t *n;
    n = v->targets->head;

    while (n) {
        sipid = *((openli_sip_identity_t **)(n->data));

        if (!space) {
            space = calloc(1, maxchars + 1);
        }
        n = n->next;

        if (!sipid->username) {
            continue;
        }

        required = strlen(sipid->username);
        if (sipid->realm) {
            required += (1 + strlen(sipid->realm));
        }
        if (spaceused > 0) {
            required += 1;
        }

        /* Only allowed a certain number of characters in the HI1 message, so
         * stop here */
        if (required > maxchars - spaceused) {
            break;
        }

        if (spaceused > 0) {
            *(space + spaceused) = ',';
            spaceused ++;
        }
        memcpy(space + spaceused, sipid->username, strlen(sipid->username));
        spaceused += strlen(sipid->username);
        if (sipid->realm) {
            *(space + spaceused) = '@';
            spaceused ++;
            memcpy(space + spaceused, sipid->realm, strlen(sipid->realm));
            spaceused += strlen(sipid->realm);
        }
    }
    return space;
}

static void free_sip_targets(libtrace_list_t *targets) {

    libtrace_list_node_t *n;
    n = targets->head;
    while (n) {
        openli_sip_identity_t *sipid = *((openli_sip_identity_t **)(n->data));
        if (sipid->username) {
            free(sipid->username);
        }
        if (sipid->realm) {
            free(sipid->realm);
        }
        free(sipid);
        n = n->next;
    }
    libtrace_list_deinit(targets);
}

void disable_sip_target_from_list(voipintercept_t *vint,
        openli_sip_identity_t *sipid) {

    openli_sip_identity_t *iter;
    libtrace_list_node_t *n;

    n = vint->targets->head;
    while (n) {
        iter = *((openli_sip_identity_t **)(n->data));
        if (are_sip_identities_same(iter, sipid)) {
            iter->active = 0;
            iter->awaitingconfirm = 0;
            break;
        }
        n = n->next;
    }
}

void flag_voip_intercepts_as_unconfirmed(voipintercept_t **voipintercepts) {
    voipintercept_t *v;
    libtrace_list_node_t *n;
    openli_sip_identity_t *sipid;

    for (v = (*voipintercepts); v != NULL; v = v->hh_liid.next) {
        v->awaitingconfirm = 1;

        n = v->targets->head;
        while (n) {
            sipid = *((openli_sip_identity_t **)(n->data));
            if (sipid->active) {
                sipid->awaitingconfirm = 1;
            }
            n = n->next;
        }
    }
}

void disable_unconfirmed_voip_intercepts(voipintercept_t **voipintercepts,
        void (*percept)(voipintercept_t *, void *),
        void *percept_arg,
        void (*pertgt)(openli_sip_identity_t *, voipintercept_t *vint, void *),
        void *pertgt_arg) {

    voipintercept_t *v, *tmp;
    libtrace_list_node_t *n;
    openli_sip_identity_t *sipid;

    HASH_ITER(hh_liid, *voipintercepts, v, tmp) {
        if (v->awaitingconfirm && v->active) {
            v->active = 0;

            if (percept) {
                percept(v, percept_arg);
            }
            HASH_DELETE(hh_liid, *voipintercepts, v);
            free_single_voipintercept(v);
        } else if (v->active) {
            /* Deal with any unconfirmed SIP targets */

            n = v->targets->head;
            while (n) {
                sipid = *((openli_sip_identity_t **)(n->data));
                n = n->next;

                if (sipid->active && sipid->awaitingconfirm) {
                    sipid->active = 0;
                    if (pertgt) {
                        pertgt(sipid, v, pertgt_arg);
                    }
                }
            }
        }
    }
}

void add_new_sip_target_to_list(voipintercept_t *vint,
        openli_sip_identity_t *sipid) {
    openli_sip_identity_t *newid, *iter;
    libtrace_list_node_t *n;

    /* First, check if this ID is already in the list. If so, we can
     * just confirm it as being still active. If not, add it to the
     * list.
     *
     * TODO consider a hashmap instead if we often get more than 2 or
     * 3 targets per intercept?
     */
    n = vint->targets->head;
    while (n) {
        iter = *((openli_sip_identity_t **)(n->data));
        if (are_sip_identities_same(iter, sipid)) {
            if (iter->active == 0) {
                iter->active = 1;
            }
            iter->awaitingconfirm = 0;
            if (sipid->username) {
                free(sipid->username);
            }
            if (sipid->realm) {
                free(sipid->realm);
            }
            return;
        }
        n = n->next;
    }

    newid = (openli_sip_identity_t *)calloc(1, sizeof(openli_sip_identity_t));
    newid->realm = sipid->realm;
    newid->realm_len = sipid->realm_len;
    newid->username = sipid->username;
    newid->username_len = sipid->username_len;
    newid->awaitingconfirm = 0;
    newid->active = 1;

    sipid->realm = NULL;
    sipid->username = NULL;

    libtrace_list_push_back(vint->targets, &newid);
}

void free_single_voipintercept(voipintercept_t *v) {
    free_intercept_common(&(v->common));
    if (v->cin_sdp_map) {
        free_voip_sdpmap(v->cin_sdp_map);
    }

    if (v->cin_callid_map) {
        free_voip_cinmap(v->cin_callid_map);
    }
    if (v->active_cins) {
        free_voip_cins(v->active_cins);
    }
    if (v->active_registrations) {
        free_voip_registrations(v->active_registrations);
    }

    if (v->targets) {
        free_sip_targets(v->targets);
    }
    free(v);
}

void free_all_voipintercepts(voipintercept_t **vints) {

    voipintercept_t *v, *tmp;
    HASH_ITER(hh_liid, *vints, v, tmp) {
        HASH_DELETE(hh_liid, *vints, v);
        free_single_voipintercept(v);
    }

}

void free_single_rtpstream(rtpstreaminf_t *rtp) {
    int i;

    if (rtp->mediastreams) {
        for (i = 0; i < rtp->streamcount; i++) {
            free(rtp->mediastreams[i].mediatype);
        }

        free(rtp->mediastreams);
    }

    free_intercept_common(&(rtp->common));
    if (rtp->targetaddr) {
        free(rtp->targetaddr);
    }
    if (rtp->otheraddr) {
        free(rtp->otheraddr);
    }
    if (rtp->streamkey) {
        free(rtp->streamkey);
    }
    if (rtp->invitecseq) {
        free(rtp->invitecseq);
    }
    if (rtp->byecseq) {
        free(rtp->byecseq);
    }
    if (rtp->timeout_ev) {
        free(rtp->timeout_ev);
    }
    free(rtp);

}

void free_all_rtpstreams(rtpstreaminf_t **streams) {
    rtpstreaminf_t *rtp, *tmp;

    HASH_ITER(hh, *streams, rtp, tmp) {
        HASH_DELETE(hh, *streams, rtp);
        free_single_rtpstream(rtp);
    }
}

vendmirror_intercept_t *create_vendmirror_intercept(ipintercept_t *ipint) {
    vendmirror_intercept_t *jm;

    jm = (vendmirror_intercept_t *)malloc(sizeof(vendmirror_intercept_t));
    if (jm == NULL) {
        return NULL;
    }

    jm->sessionid = ipint->vendmirrorid;
    copy_intercept_common(&(ipint->common), &(jm->common));

    return jm;
}

void free_single_vendmirror_intercept(vendmirror_intercept_t *jm) {
    free_intercept_common(&(jm->common));
    free(jm);
}

void free_all_vendmirror_intercepts(vendmirror_intercept_list_t **jmints) {

    vendmirror_intercept_list_t *parent, *ptmp;
    vendmirror_intercept_t *jm, *tmp;
    HASH_ITER(hh, *jmints, parent, ptmp) {

        HASH_ITER(hh, parent->intercepts, jm, tmp) {
            HASH_DELETE(hh, parent->intercepts, jm);
            free_single_vendmirror_intercept(jm);
        }
        HASH_DELETE(hh, *jmints, parent);
        free(parent);
    }
}


staticipsession_t *create_staticipsession(ipintercept_t *ipint, char *rangestr,
        uint32_t cin) {

    staticipsession_t *statint;

    statint = (staticipsession_t *)malloc(sizeof(staticipsession_t));
    if (statint == NULL) {
        return NULL;
    }

    if (rangestr) {
        statint->rangestr = strdup(rangestr);
    } else {
        statint = NULL;
    }

    statint->references = 0;
    statint->cin = cin;
    statint->nextseqno = 0;
    copy_intercept_common(&(ipint->common), &(statint->common));
    statint->key = (char *)calloc(1, 128);
    snprintf(statint->key, 127, "%s-%u", ipint->common.liid, cin);

    return statint;
}

void free_single_staticiprange(static_ipranges_t *ipr) {
    if (!ipr) {
        return;
    }
    if (ipr->rangestr) {
        free(ipr->rangestr);
    }
    if (ipr->liid) {
        free(ipr->liid);
    }
    free(ipr);
}

void free_single_staticipsession(staticipsession_t *statint) {

    free_intercept_common(&(statint->common));
    if (statint->rangestr) {
        free(statint->rangestr);
    }
    free(statint->key);
    free(statint);
}

void free_all_staticipsessions(staticipsession_t **statintercepts) {
    staticipsession_t *statint, *tmp;
    HASH_ITER(hh, *statintercepts, statint, tmp) {
        HASH_DELETE(hh, *statintercepts, statint);
        free_single_staticipsession(statint);
    }
}

ipsession_t *create_ipsession(ipintercept_t *ipint, uint32_t cin,
        int ipfamily, struct sockaddr *assignedip, uint8_t prefixlen) {

    ipsession_t *ipsess;

    ipsess = (ipsession_t *)malloc(sizeof(ipsession_t));
    if (ipsess == NULL) {
        return NULL;
    }

    ipsess->nextseqno = 0;
    ipsess->cin = cin;
    ipsess->ai_family = ipfamily;
    ipsess->prefixlen = prefixlen;
    ipsess->targetip = (struct sockaddr_storage *)(malloc(
            sizeof(struct sockaddr_storage)));
    if (!ipsess->targetip) {
        free(ipsess);
        return NULL;
    }
    memcpy(ipsess->targetip, assignedip, sizeof(struct sockaddr_storage));
    ipsess->accesstype = ipint->accesstype;

    copy_intercept_common(&(ipint->common), &(ipsess->common));

    ipsess->streamkey = (char *)(calloc(1, 256));
    if (!ipsess->streamkey) {
        free(ipsess->targetip);
        free(ipsess);
        return NULL;
    }
    snprintf(ipsess->streamkey, 256, "%s-%u", ipint->common.liid, cin);

    return ipsess;
}

void free_single_ipsession(ipsession_t *sess) {

    free_intercept_common(&(sess->common));
    if (sess->streamkey) {
        free(sess->streamkey);
    }
    if (sess->targetip) {
        free(sess->targetip);
    }
    free(sess);
}

void free_all_ipsessions(ipsession_t **sessions) {
    ipsession_t *s, *tmp;
    HASH_ITER(hh, *sessions, s, tmp) {
        HASH_DELETE(hh, *sessions, s);
        free_single_ipsession(s);
    }
}

int add_intercept_to_email_user_intercept_list(
        email_user_intercept_list_t **ulist, emailintercept_t *em,
        email_target_t *tgt) {

    email_user_intercept_list_t *found;
    email_intercept_ref_t *intref;

    if (tgt->address == NULL) {
        logger(LOG_INFO,
                "OpenLI: attempted to add address-less email intercept to user intercept list.");
        return -1;
    }

    HASH_FIND(hh, *ulist, tgt->address, strlen(tgt->address), found);
    if (!found) {
        found = (email_user_intercept_list_t *)
                malloc(sizeof(email_user_intercept_list_t));
        if (!found) {
            logger(LOG_INFO,
                    "OpenLI: out of memory in add_intercept_to_email_user_intercept_list()");
            return -1;
        }
        found->emailaddr = strdup(tgt->address);
        if (!found->emailaddr) {
            free(found);
            logger(LOG_INFO,
                    "OpenLI: out of memory in add_intercept_to_email_user_intercept_list()");
            return -1;
        }
        found->intlist = NULL;
        HASH_ADD_KEYPTR(hh, *ulist, found->emailaddr, strlen(found->emailaddr),
                found);
    }

    HASH_FIND(hh, found->intlist, em->common.liid, em->common.liid_len, intref);
    if (!intref) {
        intref = calloc(1, sizeof(email_intercept_ref_t));
        intref->em = em;

        HASH_ADD_KEYPTR(hh, found->intlist, em->common.liid,
                em->common.liid_len, intref);
    }
    return 0;
}

int add_intercept_to_user_intercept_list(user_intercept_list_t **ulist,
        ipintercept_t *ipint) {

    user_intercept_list_t *found;
    ipintercept_t *check;

    if (ipint->username == NULL) {
        logger(LOG_INFO,
                "OpenLI: attempted to add non-user-based IP intercept to user intercept list.");
        return -1;
    }

    HASH_FIND(hh, *ulist, ipint->username, ipint->username_len, found);
    if (!found) {
        found = (user_intercept_list_t *)malloc(sizeof(user_intercept_list_t));
        if (!found) {
            logger(LOG_INFO,
                    "OpenLI: out of memory in add_intercept_to_userlist()");
            return -1;
        }
        found->username = strdup(ipint->username);
        if (!found->username) {
            free(found);
            logger(LOG_INFO,
                    "OpenLI: out of memory in add_intercept_to_userlist()");
            return -1;
        }
        found->intlist = NULL;
        HASH_ADD_KEYPTR(hh, *ulist, found->username, ipint->username_len,
                found);
    }

    HASH_FIND(hh_user, found->intlist, ipint->common.liid,
            ipint->common.liid_len, check);
    if (check) {
        logger(LOG_INFO,
                "OpenLI: user %s already has an intercept with ID %s?",
                found->username, ipint->common.liid);
        return -1;
    }

    HASH_ADD_KEYPTR(hh_user, found->intlist, ipint->common.liid,
            ipint->common.liid_len, ipint);
    return 0;
}

int remove_intercept_from_email_user_intercept_list(
        email_user_intercept_list_t **ulist, emailintercept_t *em,
        email_target_t *tgt) {

    email_user_intercept_list_t *found;
    email_intercept_ref_t *existing;

    if (tgt->address == NULL) {
        logger(LOG_INFO,
                "OpenLI: attempted to remove address-less email intercept from user intercept list.");
        return -1;
    }

    HASH_FIND(hh, *ulist, tgt->address, strlen(tgt->address), found);

    if (!found) {
        return 0;
    }

    HASH_FIND(hh, found->intlist, em->common.liid, em->common.liid_len,
            existing);
    if (!existing) {
        return 0;
    }

    HASH_DELETE(hh, found->intlist, existing);
    free(existing);

    /* If there are no intercepts left associated with this address, we can
     * remove them from the user list */
    if (HASH_CNT(hh, found->intlist) == 0) {
        HASH_DELETE(hh, *ulist, found);
        free(found->emailaddr);
        free(found);
    }
    return 0;
}

int remove_intercept_from_user_intercept_list(user_intercept_list_t **ulist,
        ipintercept_t *ipint) {

    user_intercept_list_t *found;
    ipintercept_t *existing;

    if (ipint->username == NULL) {
        logger(LOG_INFO,
                "OpenLI: attempted to remove non-user-based IP intercept from user intercept list.");
        return -1;
    }

    HASH_FIND(hh, *ulist, ipint->username, ipint->username_len, found);

    if (!found) {
        printf("!found: %s\n", ipint->username);
        return 0;
    }

    HASH_FIND(hh_user, found->intlist, ipint->common.liid,
            ipint->common.liid_len, existing);
    if (!existing) {
        printf("!existing: %s\n", ipint->common.liid);
        return 0;
    }

    HASH_DELETE(hh_user, found->intlist, existing);
    /* Don't free existing -- the caller should do that instead */

    /* If there are no intercepts left associated with this user, we can
     * remove them from the user list */
    if (HASH_CNT(hh_user, found->intlist) == 0) {
        HASH_DELETE(hh, *ulist, found);
        free(found->username);
        free(found);
    }
    return 0;
}

void clear_user_intercept_list(user_intercept_list_t *ulist) {
    user_intercept_list_t *u, *tmp;
    ipintercept_t *ipint, *tmp2;

    HASH_ITER(hh, ulist, u, tmp) {
        /* Again, don't free the ipintercepts in the list -- someone else
         * should have that covered. */
        HASH_ITER(hh_user, u->intlist, ipint, tmp2) {
            HASH_DELETE(hh_user, u->intlist, ipint);
        }
        HASH_DELETE(hh, ulist, u);
        free(u->username);
        free(u);
    }
}

void clear_email_user_intercept_list(email_user_intercept_list_t *ulist) {
    email_user_intercept_list_t *u, *tmp;
    email_intercept_ref_t *em, *tmp2;

    HASH_ITER(hh, ulist, u, tmp) {
        /* Again, don't free the email intercepts in the list -- someone else
         * should have that covered. */
        HASH_ITER(hh, u->intlist, em, tmp2) {
            HASH_DELETE(hh, u->intlist, em);
            free(em);
        }

        HASH_DELETE(hh, ulist, u);
        free(u->emailaddr);
        free(u);
    }
}

uint32_t map_radius_ident_string(char *confstr) {
    if (strcasecmp(confstr, "csid") == 0) {
        return (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_CSID);
    }

    if (strncasecmp(confstr, "user", 4) == 0) {
        return (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_USER);
    }
    return 0;
}

const char *get_radius_ident_string(uint32_t radoptions) {

    if (radoptions == (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_CSID)) {
        return "csid";
    }

    if (radoptions == (1 << OPENLI_IPINT_OPTION_RADIUS_IDENT_USER)) {
        return "user";
    }

    return "any";
}

const char *get_access_type_string(internet_access_method_t method) {

    switch(method) {
        case INTERNET_ACCESS_TYPE_DIALUP:
            return "dialup";
        case INTERNET_ACCESS_TYPE_XDSL:
            return "xDSL";
        case INTERNET_ACCESS_TYPE_CABLEMODEM:
            return "cable";
        case INTERNET_ACCESS_TYPE_LAN:
            return "LAN";
        case INTERNET_ACCESS_TYPE_WIRELESS_LAN:
            return "wifi";
        case INTERNET_ACCESS_TYPE_FIBER:
            return "fiber";
        case INTERNET_ACCESS_TYPE_WIMAX:
            return "wimax";
        case INTERNET_ACCESS_TYPE_SATELLITE:
            return "satellite";
        case INTERNET_ACCESS_TYPE_MOBILE:
            return "mobile";
        case INTERNET_ACCESS_TYPE_WIRELESS_OTHER:
            return "wireless-other";
        default:
            break;
    }

    return "undefined";
}

payload_encryption_method_t map_encrypt_method_string(char *encstr) {
    if (strcasecmp(encstr, "aes-192-cbc") == 0) {
        return OPENLI_PAYLOAD_ENCRYPTION_AES_192_CBC;
    }

    return OPENLI_PAYLOAD_ENCRYPTION_NONE;
}

uint8_t map_email_decompress_option_string(char *decstr) {
    if (strcasecmp(decstr, "as-is") == 0) {
        return OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS;
    } else if (strcasecmp(decstr, "decompressed") == 0) {
        return OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED;
    } else if (strcasecmp(decstr, "inflated") == 0) {
        return OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED;
    } else if (strcasecmp(decstr, "default") == 0) {
        return OPENLI_EMAILINT_DELIVER_COMPRESSED_DEFAULT;
    }
    return OPENLI_EMAILINT_DELIVER_COMPRESSED_NOT_SET;
}

void email_decompress_option_as_string(uint8_t opt, char *space, int spacelen) {
    if (opt == OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS) {
        snprintf(space, spacelen, "as-is");
    } else if (opt == OPENLI_EMAILINT_DELIVER_COMPRESSED_INFLATED) {
        snprintf(space, spacelen, "decompressed");
    } else {
        snprintf(space, spacelen, "default");
    }
}


internet_access_method_t map_access_type_string(char *confstr) {

    if (strcasecmp(confstr, "dialup") == 0 ||
            strcasecmp(confstr, "dial-up") == 0) {
        return INTERNET_ACCESS_TYPE_DIALUP;
    }

    if (strcasecmp(confstr, "adsl") == 0 || strcasecmp(confstr, "vdsl") == 0 ||
            strcasecmp(confstr, "dsl") == 0 ||
            strcasecmp(confstr, "adsl2") == 0 ||
            strcasecmp(confstr, "xdsl") == 0) {
        return INTERNET_ACCESS_TYPE_XDSL;
    }

    if (strcasecmp(confstr, "cable") == 0 ||
            strcasecmp(confstr, "cablemodem") == 0 ||
            strcasecmp(confstr, "cable-modem") == 0) {
        return INTERNET_ACCESS_TYPE_CABLEMODEM;
    }

    if (strcasecmp(confstr, "lan") == 0 ||
            strcasecmp(confstr, "ethernet") == 0) {
        return INTERNET_ACCESS_TYPE_LAN;
    }

    if (strcasecmp(confstr, "wirelesslan") == 0 ||
            strcasecmp(confstr, "wireless-lan") == 0 ||
            strcasecmp(confstr, "wireless") == 0 ||
            strcasecmp(confstr, "wifi-lan") == 0 ||
            strcasecmp(confstr, "wifi") == 0) {
        return INTERNET_ACCESS_TYPE_WIRELESS_LAN;
    }

    if (strcasecmp(confstr, "fibre") == 0 || strcasecmp(confstr, "fiber") == 0
            || strcasecmp(confstr, "ufb") == 0) {
        return INTERNET_ACCESS_TYPE_FIBER;
    }

    if (strcasecmp(confstr, "wimax") == 0 ||
            strcasecmp(confstr, "hiperman") == 0) {
        return INTERNET_ACCESS_TYPE_WIMAX;
    }

    if (strcasecmp(confstr, "satellite") == 0) {
        return INTERNET_ACCESS_TYPE_SATELLITE;
    }

    if (strcasecmp(confstr, "wireless-other") == 0 ||
            strcasecmp(confstr, "wifi-other") == 0 ||
            strcasecmp(confstr, "wifiother") == 0 ||
            strcasecmp(confstr, "wirelessother") == 0) {
        return INTERNET_ACCESS_TYPE_WIRELESS_OTHER;
    }

    if (strcasecmp(confstr, "mobile") == 0 ||
            strcasecmp(confstr, "3g") == 0 ||
            strcasecmp(confstr, "4g") == 0 ||
            strcasecmp(confstr, "5g") == 0 ||
            strcasecmp(confstr, "lte") == 0) {
        return INTERNET_ACCESS_TYPE_MOBILE;
    }

    return INTERNET_ACCESS_TYPE_UNDEFINED;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
