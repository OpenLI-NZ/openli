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

#include "logger.h"
#include "intercept.h"

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

    memcpy(copy->otheraddr, orig->otheraddr, sizeof(struct sockaddr_storage));
    copy->targetport = orig->targetport;
    copy->otherport = orig->otherport;
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
}

void free_single_ipintercept(ipintercept_t *cept) {
    static_ipranges_t *ipr, *tmp;

    free_intercept_common(&(cept->common));
    if (cept->username) {
        free(cept->username);
    }

    HASH_ITER(hh, cept->statics, ipr, tmp) {
        HASH_DELETE(hh, cept->statics, ipr);
        if (ipr->rangestr) {
            free(ipr->rangestr);
        }
        if (ipr->liid) {
            free(ipr->liid);
        }
        free(ipr);
    }

    free(cept);
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
        free(c->callid);
        free(c);
    }

}

static inline void free_voip_sdpmap(voipsdpmap_t *sdps) {
    voipsdpmap_t *s, *tmp;

    HASH_ITER(hh_sdp, sdps, s, tmp) {
        HASH_DELETE(hh_sdp, sdps, s);
        free(s);
    }
}

void free_single_voip_cin(rtpstreaminf_t *rtp) {
    free_intercept_common(&(rtp->common));
    if (rtp->invitecseq) {
        free(rtp->invitecseq);
    }
    if (rtp->byecseq) {
        free(rtp->byecseq);
    }
    if (rtp->targetaddr) {
        free(rtp->targetaddr);
    }
    if (rtp->otheraddr) {
        free(rtp->otheraddr);
    }
    if (rtp->streamkey) {
        free(rtp->streamkey);
    }
    if (rtp->timeout_ev) {
        free(rtp->timeout_ev);
    }
    free(rtp);
}

static void free_voip_cins(rtpstreaminf_t *cins) {
    rtpstreaminf_t *rtp, *tmp;

    HASH_ITER(hh, cins, rtp, tmp) {
        HASH_DEL(cins, rtp);
        free_single_voip_cin(rtp);
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

    jm->nextseqno = 0;
    jm->cin = 0;
    jm->interceptid = ipint->vendmirrorid;
    copy_intercept_common(&(ipint->common), &(jm->common));

    return jm;
}

void free_single_vendmirror_intercept(vendmirror_intercept_t *jm) {
    free_intercept_common(&(jm->common));
    free(jm);
}

void free_all_vendmirror_intercepts(vendmirror_intercept_t **jmints) {
    vendmirror_intercept_t *jm, *tmp;
    HASH_ITER(hh, *jmints, jm, tmp) {
        HASH_DELETE(hh, *jmints, jm);
        free_single_vendmirror_intercept(jm);
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
        int ipfamily, struct sockaddr *assignedip) {

    ipsession_t *ipsess;

    ipsess = (ipsession_t *)malloc(sizeof(ipsession_t));
    if (ipsess == NULL) {
        return NULL;
    }

    ipsess->nextseqno = 0;
    ipsess->cin = cin;
    ipsess->ai_family = ipfamily;
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
        return 0;
    }

    HASH_FIND(hh_user, found->intlist, ipint->common.liid,
            ipint->common.liid_len, existing);
    if (!existing) {
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

    return INTERNET_ACCESS_TYPE_UNDEFINED;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
