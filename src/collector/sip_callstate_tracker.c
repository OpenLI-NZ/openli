/*
 *
 * Copyright (c) 2026 SearchLight Ltd, New Zealand.
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

#include <stdlib.h>
#include <string.h>
#include "sipparsing.h"
#include "sip_worker.h"
#include "logger.h"
#include "util.h"
#include "intercept.h"

static void destroy_voice_call(shared_voice_call_state_t *state,
        intercepted_voice_call_t *vc) {

    /** Assumes the write lock is already held before calling the function! */

    voice_callid_t *id, *tmp;
    voice_participant_t *tgt, *tgttmp;

    if (vc->sessionid) {
        HASH_DELETE(hh_sessionid, state->cept_calls_by_sessionid, vc);
    }
    if (vc->sdpvalid) {
        HASH_DELETE(hh_sdpo, state->cept_calls_by_sdpo, vc);
    }

    HASH_ITER(hh, vc->callids, id, tmp) {
        HASH_DELETE(hh, vc->callids, id);
        free(id->callid);
        free(id);
    }

    free(vc);
}

void remove_voice_call_by_callid(
        shared_voice_call_state_t *state, pthread_rwlock_t *lock,
        char *callid) {

    intercepted_voice_call_t *vc = NULL;
    intercepted_callid_t *kc = NULL;
    voice_callid_t *found = NULL;

    pthread_rwlock_wrlock(lock);
    HASH_FIND(hh, state->known_callids, callid, strlen(callid), kc);
    if (kc) {
        vc = kc->call;

        HASH_DELETE(hh, state->known_callids, kc);

        if (vc) {
            HASH_FIND(hh, vc->callids, callid, strlen(callid), found);
            if (found) {
                HASH_DELETE(hh, vc->callids, found);
                free(found->callid);
                free(found);

                if (HASH_CNT(hh, vc->callids) == 0) {
                    // All call legs have ended
                    destroy_voice_call(state, vc);
                }
            }
        }
        free(kc->callid);
        free(kc);
    }
    pthread_rwlock_unlock(lock);

}

static intercepted_voice_call_t *get_voice_call_by_callid(
        shared_voice_call_state_t *state, pthread_rwlock_t *lock,
        char *callid) {

    intercepted_voice_call_t *vc = NULL;
    intercepted_callid_t *kc = NULL;

    HASH_FIND(hh, state->known_callids, callid, strlen(callid), kc);
    if (kc) {
        vc = kc->call;
    }

    return vc;
}

static intercepted_voice_call_t *get_voice_call_by_sessionid(
        shared_voice_call_state_t *state, pthread_rwlock_t *lock,
        char *sessionid) {

    intercepted_voice_call_t *vc = NULL;
    if (sessionid == NULL) {
        return NULL;
    }
    HASH_FIND(hh, state->cept_calls_by_sessionid, sessionid, strlen(sessionid),
            vc);

    return vc;
}

static intercepted_voice_call_t *get_voice_call_by_sdpo(
        shared_voice_call_state_t *state, pthread_rwlock_t *lock,
        sip_sdp_identifier_t *sdpkey) {

    intercepted_voice_call_t *vc = NULL;

    if (sdpkey == NULL) {
        return NULL;
    }
    HASH_FIND(hh, state->cept_calls_by_sdpo, sdpkey, sizeof(sdpkey), vc);

    return vc;
}

static void add_new_callid_to_existing_voice_call(
        shared_voice_call_state_t *state, intercepted_voice_call_t *vc,
        char *callid) {

    voice_callid_t *cid, *cidfound;
    intercepted_callid_t *rev, *revfound;

    cid = calloc(1, sizeof(voice_callid_t));
    cid->callid = strdup(callid);

    rev = calloc(1, sizeof(intercepted_callid_t));
    rev->callid = strdup(callid);
    rev->call = vc;

    HASH_FIND(hh, vc->callids, cid->callid, strlen(cid->callid), cidfound);
    if (cidfound) {
        free(cid->callid);
        free(cid);
    } else {
        HASH_ADD_KEYPTR(hh, vc->callids, cid->callid, strlen(cid->callid), cid);
    }

    HASH_FIND(hh, state->known_callids, rev->callid, strlen(rev->callid),
            revfound);
    if (revfound) {
        free(rev->callid);
        free(rev);
    } else {
        HASH_ADD_KEYPTR(hh, state->known_callids, rev->callid,
                strlen(rev->callid), rev);
    }
}

int find_existing_voice_call(
        shared_voice_call_state_t *state, pthread_rwlock_t *lock,
        char *callid, sip_sdp_identifier_t *sdpkey, char *sessionid) {

    intercepted_voice_call_t *lookup_callid = NULL;
    intercepted_voice_call_t *lookup_sdpo = NULL;
    intercepted_voice_call_t *lookup_sessionid = NULL;
    int ret = -1;

    pthread_rwlock_wrlock(lock);
    lookup_callid = get_voice_call_by_callid(state, callid);

    if (sdpkey) {
        lookup_sdpo = get_voice_call_by_sdpo(state, sdpkey);
    }

    if (sessionid) {
        lookup_sessionid = get_voice_call_by_sessionid(state, sessionid);
    }

    if (lookup_callid) {
        if (lookup_sdpo == NULL && sdpo) {
            // Same call ID, but a new SDP-O identifier?
            // Add it anyway -- we might be going through some weird proxying
            update_voice_call_identifiers(lookup_callid, sdpo, NULL);

        }

        if (lookup_sessionid == NULL && session_id) {
            // Call ID already exists, but a new session ID.
            // Again, unlikely but let's roll with it
            update_voice_call_identifiers(lookup_callid, NULL, sessionid);
        }

        ret = 0;
    } else if (lookup_sdpo == NULL && lookup_sessionid == NULL) {
        // Never seen this call before, will need to add it to the global call
        // state IF one of our intercept targets is a participant
        ret = 1;
    } else {
        // This is a new call ID, but the session ID and/or the SDP-O
        // identifier matches a session that we've already seen so we
        // can combine them.
        //
        // Ideally, lookup_session == lookup_sdpo (or one of them is NULL).
        // If they're both not NULL and not the same call, something weird
        // is going on (probably non-unique SDP-O identifiers) so it is
        // probably a good idea to ignore SDP-O if session ID is usable.
        // My main concern is avoiding a situation where a Call ID can point
        // to more than one call in the intercepted_voice_call map
        if (lookup_sessionid) {
            add_new_callid_to_existing_voice_call(sipworker->call_state,
                    lookup_sessionid, callid);
        } else if (lookup_sdpo) {
            add_new_callid_to_existing_voice_call(sipworker->call_state,
                    lookup_sdpo, callid);
        }
        ret = 0;
    }

    pthread_rwlock_unlock(lock);
    return ret;
}


int create_new_intercepted_voice_call(
        shared_voice_call_state_t *state, pthread_rwlock_t *lock,
        char *callid, sip_sdp_identifier_t *sdpkey, char *sessionid,
        openli_sip_identity_t *matched, voipintercept_t *vint,
        int owner, struct timeval *tv) {

    intercepted_voice_call_t *vc, *vcfound;
    voice_callid_t *cid;
    intercepted_callid_t *rev, *revfound;
    uint32_t cin_copy;

    if (callid == NULL) {
        return -1 ;
    }

    pthread_rwlock_rdlock(lock);
    HASH_FIND(hh, state->known_callids, rev->callid, strlen(rev->callid),
            revfound);
    if (revfound) {
        return 0;
    }
    pthread_rwlock_unlock(lock);

    vc = calloc(1, sizeof(intercepted_voice_call_t));
    vc->owner = owner;
    vc->created = tv->tv_sec;
    vc->cin = hashlittle(callid, strlen(callid), 0xceefface);
    vc->cin = (vc->cin % (uint32_t)(pow(2, 31)));
    cincopy = vc->cin;

    if (sessionid) {
        vc->sessionid = strdup(sessionid);
    }
    if (sdpkey) {
        memcpy(&(vc->sdpkey), sdpkey, sizeof(vc->sdpkey));
        vc->sdpvalid = 1;
    }

    cid = calloc(1, sizeof(voice_callid_t));
    cid->callid = strdup(callid);
    HASH_ADD_KEYPTR(hh, vc->callids, cid->callid, strlen(cid->callid), cid);

    rev = calloc(1, sizeof(intercepted_callid_t));
    rev->callid = strdup(callid);
    rev->call = vc;

    pthread_rwlock_wrlock(lock);
    HASH_ADD_KEYPTR(hh, state->known_callids, rev->callid,
            strlen(rev->callid), rev);

    HASH_FIND(hh_sdpo, state->cept_calls_by_sdpo, &(vc->sdpkey),
            sizeof(vc->sdpkey), vcfound);
    if (!vcfound) {
        HASH_ADD_KEYPTR(hh_sdpo, state->cept_calls_by_sdpo, &(vc->sdpkey),
                sizeof(vc->sdpkey), vc);
    }

    HASH_FIND(hh_sessionid, state->cept_calls_by_sessionid, vc->sessionid,
            strlen(vc->sessionid), vcfound);
    if (!vcfound) {
        HASH_ADD_KEYPTR(hh_sessionid, state->cept_calls_by_sessionid,
                vc->sessionid, strlen(vc->sessionid), vc);
    }

    add_target_call_reference(vint, matched, cin_copy, vc, NULL);
    pthread_rwlock_unlock(lock);

    return 1;
}

void remove_target_call_reference(voipintercept_t *vint, uint32_t cin) {

    target_call_ref_t *tgtref, *reftmp;
    target_call_map_t *tgtmap;

    HASH_ITER(hh, vint->target_cin_map, tgtref, reftmp) {
        HASH_FIND(hh, tgtref->tgtcalls, &cin, sizeof(cin), tgtmap);
        if (tgtmap) {
            HASH_DELETE(hh, tgtref->tgtcalls, tgtmap);
            free(tgtmap);
        }
    }

}

void add_target_call_reference(voipintercept_t *vint,
        openli_sip_identity_t *matched, uint32_t cin,
        char *callid, sip_message_state_t *msg) {

    target_call_ref_t *tgtref;
    target_call_map_t *tgtmap;
    char tgtkey[512];

    if (matched->realm) {
        snprintf(tgtkey, 512, "%s@%s", matched->username, matched->realm);
        tgt->realm = strdup(matched->realm);
    } else {
        snprintf(tgtkey, 512, "%s", matched->username);
    }

    HASH_FIND(hh, vint->target_cin_map, tgtkey, strlen(tgtkey), tgtref);
    if (!tgtref) {
        tgtref = calloc(1, sizeof(target_call_ref_t));
        tgtref->key = strdup(tgtkey);

        HASH_ADD_KEYPTR(hh, vint->target_cin_map, tgtref->key,
                strlen(tgtref->key), tgtref);
    }

    HASH_FIND(hh, tgtref->tgtcalls, &(cin), sizeof(cin), tgtmap);
    if (tgtmap) {
        // already in here
        return;
    }

    tgtmap = calloc(1, sizeof(target_call_map_t));
    tgtmap->cin = cin;

    // one of these should be NULL
    tgtmap->callid = strdup(callid);
    tgtmap->msg = msg;

    HASH_ADD_KEYPTR(hh, tgtref->tgtcalls, &(tgtmap->cin), sizeof(tgtmap->cin),
            tgtmap);

}

static void update_voice_call_identifiers(shared_voice_call_state_t *state,
        intercepted_voice_call_t *vc,
        sip_sdp_identifier_t *sdpkey, char *sessionid) {

    if (sessionid) {
        if (vc->sessionid) {
            HASH_DELETE(hh_sessionid, state->cept_calls_by_sessionid, vc);
            free(vc->sessionid);
        }
        vc->sessionid = sessionid;
        HASH_ADD_KEYPTR(hh_sessionid, state->cept_calls_by_sessionid,
                vc->sessionid, strlen(vc->sessionid), vc);
    }

    if (sdpkey) {
        intercepted_voice_call_t *found;
        HASH_FIND(hh_sdp, state->cept_calls_by_sdpo, &(vc->sdpkey),
                sizeof(vc->sdpkey), found);
        if (found) {
            HASH_DELETE(hh_sdp, state->cept_calls_by_sdpo, found);
        }
        memcpy(&(vc->sdpkey), sdpkey, sizeof(vc->sdpkey));
        HASH_ADD_KEYPTR(hh_sdp, state->cept_calls_by_sdpo, &(vc->sdpkey),
                sizeof(vc->sdpkey), vc);
    }

    pthread_rwlock_unlock(lock);

}

int get_voice_call_owner(pthread_rwlock_t *lock, intercepted_voice_call_t *vc) {
    int owner;

    pthread_rwlock_rdlock(lock);
    owner = vc->owner;
    pthread_rwlock_unlock(lock);
    return owner;
}

uint32_t get_voice_call_cin_using_callid(shared_voice_call_state_t *state,
        pthread_rwlock_t *lock, char *callid) {

    uint32_t cin = 0;
    intercepted_callid_t *kc;

    pthread_rwlock_rdlock(lock);
    HASH_FIND(hh, state->known_callids, callid, strlen(callid), kc);
    if (kc) {
        cin = kc->call->cin;
    }
    pthread_rwlock_unlock(lock);
    return cin;
}

