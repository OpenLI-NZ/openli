/*
 *
 * Copyright (c) 2025 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * This code has been developed by Searchlight Ltd.
 * For further information please see https://searchlight.nz/
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

#include <uthash.h>

#include "logger.h"
#include "agency.h"
#include "coll_recv_thread.h"
#include "liidmapping.h"

int update_agency_digest_config_map(agency_digest_config_t **map,
        liagency_t *lea) {

    agency_digest_config_t *found = NULL;

    HASH_FIND(hh, *map, lea->agencyid, strlen(lea->agencyid), found);

    if (found) {
        free_liagency(found->config);
        found->config = lea;
        found->disabled = 0;

        /* For now, I'll just let any current timers expire rather
         * than trying to adjust them to suit the new config. After that,
         * any future timers will be based off the new options (although
         * realistically, the likelihood of having to modify an existing
         * agencies integrity check config is very very small).
         */
         return 0;
    }

    found = calloc(1, sizeof(agency_digest_config_t));
    found->agencyid = strdup(lea->agencyid);
    found->config = lea;
    found->disabled = 0;

    HASH_ADD_KEYPTR(hh, *map, found->agencyid, strlen(found->agencyid),
            found);

    return 1;
}

void free_agency_digest_config(agency_digest_config_t *dig) {

    if (dig->agencyid) {
        free(dig->agencyid);
    }
    if (dig->config) {
        free_liagency(dig->config);
    }

    free(dig);
}

void remove_agency_digest_config(agency_digest_config_t **map,
        char *agencyid) {

    agency_digest_config_t *found;

    HASH_FIND(hh, *map, agencyid, strlen(agencyid), found);
    if (!found) {
        return;
    }

    /* Just disable it because there may be references to 'found' stored
     * in other objects and we don't want to break those
     */
    found->disabled = 1;

}

static integrity_check_state_t *lookup_integrity_check_state(
        integrity_check_state_t **map, char *liid,
        openli_proto_msgtype_t msgtype, wandder_etsispec_t *decoder) {

    /** map key is LIID, CIN and msgtype, separated by space characeters.
     *  For performance reasons, CIN and msgtype are encoded in binary format
     *  so we don't have to call snprintf on every intercept record.
     */
    uint32_t cin;
    integrity_check_state_t *found = NULL;
    char key[64];
    char *ptr = key;

    memset(ptr, 0, 64);

    memcpy(key, liid, strlen(liid));
    ptr += strlen(liid);
    *ptr = ' ';
    ptr ++;
    *ptr = (uint8_t)msgtype;
    ptr ++;
    *ptr = ' ';
    ptr ++;

    cin = wandder_etsili_get_cin(decoder);
    if (cin == 0) {
        return NULL;
    }

    memcpy(ptr, &cin, sizeof(uint32_t));

    HASH_FIND(hh, *map, key, strlen(key), found);
    if (!found) {
        found = calloc(1, sizeof(integrity_check_state_t));
        found->key = strdup(key);
        found->agency = NULL;
        found->intercept = NULL;
        found->cin = cin;
        found->msgtype = msgtype;
        found->liid = strdup(liid);
        HASH_ADD_KEYPTR(hh, *map, found->key, strlen(found->key), found);
    }

    return found;
}

static inline void reset_hash_context(integrity_check_state_t *found) {

    if (found->hash_ctx == NULL) {
        found->hash_ctx = EVP_MD_CTX_new();
    }

    switch(found->agency->config->digest_hash_method) {
        case OPENLI_DIGEST_HASH_ALGO_SHA256:
            EVP_DigestInit_ex(found->hash_ctx, EVP_sha256(), NULL);
            break;
        case OPENLI_DIGEST_HASH_ALGO_SHA512:
            EVP_DigestInit_ex(found->hash_ctx, EVP_sha512(), NULL);
            break;
        case OPENLI_DIGEST_HASH_ALGO_SHA1:
            EVP_DigestInit_ex(found->hash_ctx, EVP_sha1(), NULL);
            break;
        case OPENLI_DIGEST_HASH_ALGO_SHA384:
            EVP_DigestInit_ex(found->hash_ctx, EVP_sha384(), NULL);
            break;
    }
}

static inline void printable_integrity_key(integrity_check_state_t *ics,
        char *buf, size_t buflen) {

    snprintf(buf, buflen, "%s-%s-%u", ics->liid,
            ics->msgtype == OPENLI_PROTO_ETSI_IRI ? "IRI" : "CC",
            ics->cin);

}

uint8_t update_integrity_check_state(integrity_check_state_t **map,
        col_known_liid_t *known, uint8_t *msgbody, uint16_t msglen,
        openli_proto_msgtype_t msgtype, int epoll_fd,
        wandder_etsispec_t *decoder) {

    //char keydump[128];
    integrity_check_state_t *found;
    uint8_t action = INTEGRITY_CHECK_NO_ACTION;

    if (msgtype != OPENLI_PROTO_ETSI_IRI && msgtype != OPENLI_PROTO_ETSI_CC) {
        return action;
    }

    wandder_attach_etsili_buffer(decoder, msgbody, msglen, false);

    found = lookup_integrity_check_state(map, known->liid, msgtype, decoder);
    //printable_integrity_key(found, keydump, 128);  // TODO remove
    if (found->agency == NULL) {
        /* this is a new stream */
        found->agency = known->digest_config;
        found->intercept = known;
        found->hash_ctx = NULL;

        reset_hash_context(found);

        /* do not start the timers until we've seen at least one PDU */
        found->hash_timer = create_mediator_timer(epoll_fd, found,
                MED_EPOLL_INTEGRITY_HASH_TIMER, 0);
        found->sign_timer = create_mediator_timer(epoll_fd, found,
                MED_EPOLL_INTEGRITY_SIGN_TIMER, 0);

        found->pdus_since_last_hashrec = 0;
        found->hashes_since_last_signrec = 0;
    } else {
        found->agency = known->digest_config;
    }


    if (msgtype == OPENLI_PROTO_ETSI_IRI) {

    } else if (msgtype == OPENLI_PROTO_ETSI_CC) {

    }

    if (found->pdus_since_last_hashrec == 0 &&
            found->agency->config->digest_hash_pdulimit > 1) {
        if (start_mediator_timer(found->hash_timer,
                    found->agency->config->digest_hash_timeout) < 0) {
            /* what can we do here? */
        }
    }
    found->pdus_since_last_hashrec += 1;

    if (found->pdus_since_last_hashrec >=
            found->agency->config->digest_hash_pdulimit) {
        halt_mediator_timer(found->hash_timer);

        found->pdus_since_last_hashrec = 0;

        action = INTEGRITY_CHECK_SEND_HASH;

    }

    return action;

}

int integrity_hash_timer_callback(coll_recv_t *col, med_epoll_ev_t *mev) {

    integrity_check_state_t *ics;
    //char keydump[128];

    (void)col;

    if (mev == NULL) {
        return -1;
    }

    ics = (integrity_check_state_t *)(mev->state);
    halt_mediator_timer(mev);

    if (ics->pdus_since_last_hashrec == 0) {
        /* shouldn't happen, but just in case... */
        return 0;
    }

    //printable_integrity_key(ics, keydump, 128);

    /* TODO generate a hash digest record and push it into the appropriate
     * RMQ for the LIID
     */

    ics->pdus_since_last_hashrec = 0;

    // don't restart the timer until we've seen at least one hashable PDU

    return 1;
}

void free_integrity_check_state(integrity_check_state_t *integ) {
    if (integ == NULL) {
        return;
    }
    if (integ->key) free(integ->key);
    if (integ->liid) free(integ->liid);
    if (integ->hash_ctx) EVP_MD_CTX_free(integ->hash_ctx);
    if (integ->hash_timer) destroy_mediator_timer(integ->hash_timer);
    if (integ->sign_timer) destroy_mediator_timer(integ->sign_timer);
    free(integ);
}
