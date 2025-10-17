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

#include <string.h>
#include "config.h"
#include "configparser_provisioner.h"
#include "provisioner.h"
#include "logger.h"
#include "util.h"
#include "updateserver.h"
#include "intercept_timers.h"
#include "intercept.h"

typedef struct xid_hash {
    uuid_t xid;
    const char *liid;
    UT_hash_handle hh;
} xid_hash_t;


static inline int reload_staticips(provision_state_t *currstate,
        ipintercept_t *ipint, ipintercept_t *newequiv) {

    static_ipranges_t *ipr, *tmp, *found;
    int changed = 0;

    HASH_ITER(hh, ipint->statics, ipr, tmp) {
        HASH_FIND(hh, newequiv->statics, ipr->rangestr, strlen(ipr->rangestr),
                found);
        if (!found || found->cin != ipr->cin) {
            remove_existing_staticip_range(currstate, ipint, ipr);
            changed = 1;
        } else {
            found->awaitingconfirm = 0;
        }
    }

    HASH_ITER(hh, newequiv->statics, ipr, tmp) {
        if (ipr->awaitingconfirm == 0) {
            continue;
        }
        add_new_staticip_range(currstate, ipint, ipr);
        changed = 1;
    }

    return changed;
}

static inline int common_intercept_equal(intercept_common_t *a,
        intercept_common_t *b) {

    if (strcmp(a->liid, b->liid) != 0) {
        return 0;
    }

    if (a->liid_format != b->liid_format) {
        return 0;
    }

    if (a->tostart_time != b->tostart_time) {
        return 0;
    }

    if (a->toend_time != b->toend_time) {
        return 0;
    }

    if (strcmp(a->authcc, b->authcc) != 0) {
        return 0;
    }

    if (strcmp(a->delivcc, b->delivcc) != 0) {
        return 0;
    }

    if (a->encrypt != b->encrypt) {
        return 0;
    }

    if (a->tomediate != b->tomediate) {
        return 0;
    }

    if (strcmp(a->targetagency, b->targetagency) != 0) {
        return 0;
    }

    if (compare_xid_list(a, b) != 0) {
        return 0;
    }

    /* Binary key comparison: lengths must match; if >0, bytes must match */
    if (a->encrypt != OPENLI_PAYLOAD_ENCRYPTION_NONE ||
        b->encrypt != OPENLI_PAYLOAD_ENCRYPTION_NONE) {
        if (a->encryptkey_len != b->encryptkey_len) {
            return 0;
        }
        if (a->encryptkey_len > 0 &&
            memcmp(a->encryptkey, b->encryptkey, a->encryptkey_len) != 0) {
            return 0;
        }
    }

    if (a->time_fmt != b->time_fmt) {
        return 0;
    }

    return 1;
}

static inline int ip_intercept_equal(ipintercept_t *a, ipintercept_t *b) {

    if (common_intercept_equal(&(a->common), &(b->common)) == 0) {
        return 0;
    }

    if (a->username && b->username && strcmp(a->username, b->username) != 0) {
        return 0;
    }

    if (a->vendmirrorid != b->vendmirrorid) {
        return 0;
    }

    if (a->udp_sink && !b->udp_sink) {
        return 0;
    }
    if (b->udp_sink && !a->udp_sink) {
        return 0;
    }
    if (a->udp_sink && b->udp_sink && strcmp(a->udp_sink, b->udp_sink) != 0) {
        return 0;
    }

    if (a->accesstype != b->accesstype) {
        return 0;
    }

    if (a->accesstype == INTERNET_ACCESS_TYPE_MOBILE &&
            b->accesstype == INTERNET_ACCESS_TYPE_MOBILE &&
            a->mobileident != b->mobileident) {
        return 0;
    }

    return 1;
}

static inline int voip_intercept_equal(voipintercept_t *a, voipintercept_t *b) {
    if (common_intercept_equal(&(a->common), &(b->common)) == 0) {
        return 0;
    }
    if (a->options != b->options) {
        return 0;
    }
    return 1;
}

static inline int email_intercept_equal(emailintercept_t *a,
        emailintercept_t *b) {

    if (a->delivercompressed != b->delivercompressed) {
        return 0;
    }
    return common_intercept_equal(&(a->common), &(b->common));
}

static int reload_intercept_config_filename(provision_state_t *currstate,
        provision_state_t *newstate) {

	if (newstate->interceptconffile == NULL) {
		newstate->interceptconffile = strdup(DEFAULT_INTERCEPT_CONFIG_FILE);
	}

    if (strcmp(newstate->interceptconffile, currstate->interceptconffile)
            != 0) {
        logger(LOG_INFO,
                "OpenLI: intercept configuration is now being read from %s.",
                newstate->interceptconffile);
        free(currstate->interceptconffile);
        currstate->interceptconffile = newstate->interceptconffile;
        newstate->interceptconffile = NULL;
        return 1;
    }
    return 0;
}

static int _update_xid_map(xid_hash_t **map, intercept_common_t *common) {

    xid_hash_t *found;
    size_t i;
    uuid_t u;
    for (i = 0; i < common->xid_count; i++) {
        uuid_copy(u, common->xids[i]);
        HASH_FIND(hh, *map, u, sizeof(uuid_t), found);

        if (found) {
            char uuidstr[128];

            uuid_unparse(u, uuidstr);
            logger(LOG_INFO,
                    "OpenLI: invalid intercept configuration -- XID %s has been associated with multiple LIIDs (%s and %s)",
                    uuidstr, found->liid, common->liid);
            return -1;
        }
        found = calloc(1, sizeof(xid_hash_t));
        uuid_copy(found->xid, u);
        found->liid = strdup(common->liid);
        HASH_ADD_KEYPTR(hh, *map, found->xid, sizeof(uuid_t), found);
    }
    return 0;
}

int check_for_duplicate_xids(prov_intercept_conf_t *intconf, size_t xid_count,
        uuid_t *xids, char *xid_liid) {

    xid_hash_t *map = NULL;
    emailintercept_t *em, *emtmp;
    voipintercept_t *vint, *vtmp;
    ipintercept_t *ipint, *iptmp;
    xid_hash_t *iter, *tmp;
    int ret = 0;

    /* Populate our map of known XIDS across all intercepts. If we
     * find a duplicate in the existing config, we can throw an error
     * right away
     */
    HASH_ITER(hh_liid, intconf->ipintercepts, ipint, iptmp) {
        if (_update_xid_map(&map, &(ipint->common)) < 0) {
            ret = -1;
            goto endxidcheck;
        }
    }

    HASH_ITER(hh_liid, intconf->voipintercepts, vint, vtmp) {
        if (_update_xid_map(&map, &(vint->common)) < 0) {
            ret = -1;
            goto endxidcheck;
        }
    }

    HASH_ITER(hh_liid, intconf->emailintercepts, em, emtmp) {
        if (_update_xid_map(&map, &(em->common)) < 0) {
            ret = -1;
            goto endxidcheck;
        }
    }

    /* If the caller has a set of XIDs they want to perform a check on then
     * we can now do so.
     */
    if (xid_count > 0) {
        for (size_t i = 0; i < xid_count; i++) {
            HASH_FIND(hh, map, xids[i], sizeof(uuid_t), iter);
            /* A XID allowed to already be in the map if it is for the
             * same LIID as the one that prompted the check in the first
             * place.
             */
            if (iter && xid_liid && strcmp(iter->liid, xid_liid) != 0) {
                char uuidstr[128];

                uuid_unparse(xids[i], uuidstr);
                logger(LOG_INFO,
                        "OpenLI: invalid intercept configuration -- XID %s is already associated with another LIID (%s)",
                    uuidstr, iter->liid);
                ret = -1;
                goto endxidcheck;
            }
        }
    }

endxidcheck:
    HASH_ITER(hh, map, iter, tmp) {
        HASH_DELETE(hh, map, iter);
        free((void *)iter->liid);
        free(iter);
    }
    return ret;
}

static int reload_leas(provision_state_t *state, prov_intercept_conf_t *curr,
        prov_intercept_conf_t *latest) {

    prov_agency_t *lea, *tmp, *newequiv;

    HASH_ITER(hh, curr->leas, lea, tmp) {
        HASH_FIND_STR(latest->leas, lea->ag->agencyid, newequiv);

        if (!newequiv) {
            /* Agency has been withdrawn entirely */
            withdraw_agency_from_mediators(state, lea);
        } else if (agency_equal(lea->ag, newequiv->ag)) {
            newequiv->announcereq = 0;
        } else {
            /* Agency has changed, re-announce the new version */
            //withdraw_agency_from_mediators(state, lea);
            newequiv->announcereq = 1;
        }
    }

    HASH_ITER(hh, latest->leas, lea, tmp) {
        if (lea->announcereq) {
            announce_lea_to_mediators(state, lea);
            update_inherited_encryption_settings(state, lea->ag);
            lea->announcereq = 0;
        }
    }

    return 0;
}

static int reload_default_radius_users(provision_state_t *state,
        default_radius_user_t *currusers, default_radius_user_t *newusers) {

    default_radius_user_t *dru, *tmp, *newequiv;

    HASH_ITER(hh, currusers, dru, tmp) {
        HASH_FIND(hh, newusers, dru->name, dru->namelen, newequiv);
        if (!newequiv) {
            withdraw_default_radius_username(state, dru);
        } else {
            newequiv->awaitingconfirm = 0;
        }
    }

    HASH_ITER(hh, newusers, dru, tmp) {
        if (dru->awaitingconfirm) {
            announce_default_radius_username(state, dru);
        }
    }

    return 0;
}

static int reload_coreservers(provision_state_t *state, coreserver_t *currserv,
        coreserver_t *newserv) {

    coreserver_t *cs, *tmp, *newequiv;

    HASH_ITER(hh, currserv, cs, tmp) {
        HASH_FIND(hh, newserv, cs->serverkey, strlen(cs->serverkey), newequiv);
        if (!newequiv) {
            announce_coreserver_change(state, cs, false);
        } else {
            newequiv->awaitingconfirm = 0;
        }
    }

    HASH_ITER(hh, newserv, cs, tmp) {
        if (cs->awaitingconfirm) {
            announce_coreserver_change(state, cs, true);
        }
    }
    return 0;
}

static void remove_withdrawn_intercept(provision_state_t *currstate,
        intercept_common_t *common, char *target_info, int droppedmeds) {

    remove_liid_mapping(currstate, common->liid, common->liid_len, droppedmeds);
    if (!droppedmeds) {
        announce_hi1_notification_to_mediators(currstate,
                common, target_info, HI1_LI_DEACTIVATED);
    }

    if (common->local) {
        free(common->local);
        common->local = NULL;
    }

    logger(LOG_INFO, "OpenLI provisioner: LIID %s has been withdrawn following a config reload.",
            common->liid);
}

static int enable_new_intercept(provision_state_t *currstate,
        intercept_common_t *common, prov_intercept_conf_t *intconf,
        char *target_info, int droppedmeds) {

    liid_hash_t *h = NULL;
    struct timeval tv;
    prov_agency_t *lea = NULL;
    prov_intercept_data_t *local;


    if (strcmp(common->targetagency, "pcapdisk") != 0) {
        HASH_FIND_STR(intconf->leas, common->targetagency, lea);
        if (lea == NULL) {
            return 0;
        }
    }

    gettimeofday(&tv, NULL);
    local = (prov_intercept_data_t *)(common->local);
    if (local && (common->tostart_time > 0 || common->toend_time > 0)) {

        if (add_intercept_timer(currstate->epoll_fd,
                    common->tostart_time, tv.tv_sec,
                    local, PROV_EPOLL_INTERCEPT_START) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to schedule HI1 notification for starting email intercept %s", common->liid);

            return -1;
        }

        if (add_intercept_timer(currstate->epoll_fd,
                    common->toend_time, tv.tv_sec,
                    local, PROV_EPOLL_INTERCEPT_HALT) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to schedule HI1 notification for halting email intercept %s", common->liid);

            return -1;
        }
    }

    /* Add the LIID mapping */
    h = add_liid_mapping(intconf, common);

    if (!droppedmeds && announce_hi1_notification_to_mediators(currstate,
                common, target_info, HI1_LI_ACTIVATED) == -1) {
        logger(LOG_INFO,
                "OpenLI provisioner: unable to send HI1 notification for new Email intercept to mediators.");
        return -1;
    }

    if (!droppedmeds && announce_liidmapping_to_mediators(currstate, h) == -1) {
        logger(LOG_INFO,
                "OpenLI provisioner: unable to announce new Email intercept to mediators.");
        return -1;
    }
    return 1;
}

static int update_reconfigured_intercept(provision_state_t *currstate,
        intercept_common_t *old_common, intercept_common_t *new_common,
        prov_intercept_conf_t *intconf, int cept_changed, int agencychanged,
        int encryptchanged, int droppedmeds, char *old_targets,
        char *new_targets) {

    char errorstring[1024];

    prov_intercept_data_t *local, *oldlocal;
    /* save the "hi1 sent" status from the original intercept
     * instance.
     */
    oldlocal = (prov_intercept_data_t *)(old_common->local);
    local = (prov_intercept_data_t *)(new_common->local);

    local->start_hi1_sent = oldlocal->start_hi1_sent;
    local->end_hi1_sent = oldlocal->end_hi1_sent;
    new_common->hi1_seqno = old_common->hi1_seqno;

    if (agencychanged || cept_changed) {
        logger(LOG_INFO,
                "OpenLI provisioner: Details for intercept %s have changed -- updating collectors",
                new_common->liid);
    }

    if (!droppedmeds && agencychanged) {
        announce_hi1_notification_to_mediators(currstate,
                old_common, old_targets, HI1_LI_DEACTIVATED);
        new_common->hi1_seqno = 0;
        announce_hi1_notification_to_mediators(currstate,
                new_common, new_targets, HI1_LI_ACTIVATED);
    } else if (!droppedmeds && cept_changed) {
        announce_hi1_notification_to_mediators(currstate,
                new_common, new_targets, HI1_LI_MODIFIED);
    }


    /* clear the old HI1 timers, since they will be pointing
     * at an intercept instance that is going to be removed
     * when we complete the config reload.
     */
    free_prov_intercept_data(old_common, currstate->epoll_fd);

    /* add new intercept timers, and also send any required
     * HI1 messages
     */
    if (reset_intercept_timers(currstate, new_common,
                new_targets, errorstring, 1024) < 0) {
        logger(LOG_INFO, "OpenLI provisioner: unable to reset intercept timers: %s", errorstring);
    }

    if (agencychanged || encryptchanged) {
        apply_intercept_encryption_settings(intconf, new_common);
        add_liid_mapping(intconf, new_common);
    }

    return 0;
}

static int reload_emailintercepts(provision_state_t *currstate,
        emailintercept_t *curremail, emailintercept_t *newemail,
		prov_intercept_conf_t *intconf, int droppedcols, int droppedmeds) {

    emailintercept_t *mailint, *tmp, *newequiv;
    char *target_info;
    struct timeval tv;

    /* TODO error handling in the "inform other components about changes"
     * functions?
     */
    HASH_ITER(hh_liid, curremail, mailint, tmp) {
        HASH_FIND(hh_liid, newemail, mailint->common.liid,
                mailint->common.liid_len, newequiv);

        if (!newequiv) {
            /* Intercept has been withdrawn entirely */
            if (!droppedcols) {
                halt_existing_intercept(currstate, (void *)mailint,
                        OPENLI_PROTO_HALT_EMAILINTERCEPT);
            }
            target_info = list_email_targets(mailint, 256);
            remove_withdrawn_intercept(currstate, &(mailint->common),
                    target_info, droppedmeds);
            if (target_info) {
                free(target_info);
            }

            continue;
        } else {
            int intsame = email_intercept_equal(mailint, newequiv);
            int agencychanged = strcmp(mailint->common.targetagency,
                    newequiv->common.targetagency);
            int changedtargets = compare_email_targets(currstate, mailint,
                    newequiv);
            int encryptchanged = compare_intercept_encrypt_configuration(
                    &(mailint->common), &(newequiv->common));
            char *old_target_info = list_email_targets(mailint, 256);
            char *new_target_info = list_email_targets(newequiv, 256);

            newequiv->awaitingconfirm = 0;
            if (update_reconfigured_intercept(currstate, &(mailint->common),
                    &(newequiv->common), intconf, (!intsame || changedtargets),
                    agencychanged, encryptchanged, droppedmeds, old_target_info,
                    new_target_info) < 0) {
                return -1;
            }

            if (!intsame && !droppedcols) {
                modify_existing_intercept_options(currstate, (void *)newequiv,
                        OPENLI_PROTO_MODIFY_EMAILINTERCEPT);
            }

            if (old_target_info) {
                free(old_target_info);
            }
            if (new_target_info) {
                free(new_target_info);
            }
        }
    }

    gettimeofday(&tv, NULL);

    HASH_ITER(hh_liid, newemail, mailint, tmp) {
        int r = 0;

        if (!mailint->awaitingconfirm) {
            continue;
        }
        target_info = list_email_targets(mailint, 256);
        r = enable_new_intercept(currstate, &(mailint->common), intconf,
                target_info, droppedmeds);
        if (target_info) {
            free(target_info);
        }
        if (r < 0) {
            return r;
        }
        if (r == 0) {
            continue;
        }

        if (!droppedcols && announce_single_intercept(currstate,
                (void *)mailint, push_emailintercept_onto_net_buffer) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to announce new Email intercept to collectors.");
            return -1;
        }

        if (!droppedcols && announce_all_email_targets(currstate, mailint) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing targets for Email intercept %s onto buffer.", mailint->common.liid);
            return -1;
        }
    }

    return 0;
}

static int reload_voipintercepts(provision_state_t *currstate,
        voipintercept_t *currvoip, voipintercept_t *newvoip,
		prov_intercept_conf_t *intconf, int droppedcols, int droppedmeds) {

    voipintercept_t *voipint, *tmp, *newequiv;
    char *target_info;
    struct timeval tv;

    /* TODO error handling in the "inform other components about changes"
     * functions?
     */
    HASH_ITER(hh_liid, currvoip, voipint, tmp) {
        HASH_FIND(hh_liid, newvoip, voipint->common.liid,
                voipint->common.liid_len, newequiv);

        if (newequiv && currstate->ignorertpcomfort) {
            newequiv->options |= (1 << OPENLI_VOIPINT_OPTION_IGNORE_COMFORT);
        }

        if (!newequiv) {
            /* Intercept has been withdrawn entirely */
            if (!droppedcols) {
                halt_existing_intercept(currstate, (void *)voipint,
                        OPENLI_PROTO_HALT_VOIPINTERCEPT);
            }
            target_info = list_sip_targets(voipint, 256);
            remove_withdrawn_intercept(currstate, &(voipint->common),
                    target_info, droppedmeds);
            if (target_info) {
                free(target_info);
            }
            continue;
        } else {
            int intsame = voip_intercept_equal(voipint, newequiv);
            int agencychanged = strcmp(voipint->common.targetagency,
                    newequiv->common.targetagency);
            int changedtargets = compare_sip_targets(currstate, voipint,
                    newequiv);
            int encryptchanged = compare_intercept_encrypt_configuration(
                    &(voipint->common), &(newequiv->common));
            char *old_target_info = list_sip_targets(voipint, 256);
            char *new_target_info = list_sip_targets(newequiv, 256);

            newequiv->awaitingconfirm = 0;
            if (update_reconfigured_intercept(currstate, &(voipint->common),
                    &(newequiv->common), intconf, (!intsame || changedtargets),
                    agencychanged, encryptchanged, droppedmeds, old_target_info,
                    new_target_info) < 0) {
                return -1;
            }

            if (!intsame && !droppedcols) {
                modify_existing_intercept_options(currstate, (void *)newequiv,
                        OPENLI_PROTO_MODIFY_VOIPINTERCEPT);
            }

            if (old_target_info) {
                free(old_target_info);
            }
            if (new_target_info) {
                free(new_target_info);
            }

        }
    }
    gettimeofday(&tv, NULL);

    HASH_ITER(hh_liid, newvoip, voipint, tmp) {
        int r = 0;

        if (!voipint->awaitingconfirm) {
            continue;
        }
        target_info = list_sip_targets(voipint, 256);
        if (currstate->ignorertpcomfort) {
            voipint->options |= (1 << OPENLI_VOIPINT_OPTION_IGNORE_COMFORT);
        }
        r = enable_new_intercept(currstate, &(voipint->common), intconf,
                target_info, droppedmeds);
        if (target_info) {
            free(target_info);
        }
        if (r < 0) {
            return r;
        }
        if (r == 0) {
            continue;
        }

        if (!droppedcols && announce_single_intercept(currstate,
                (void *)voipint, push_voipintercept_onto_net_buffer) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to announce new VOIP intercept to collectors.");
            return -1;
        }

        if (!droppedcols && announce_all_sip_targets(currstate, voipint) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing SIP targets for VOIP intercept %s onto buffer.", voipint->common.liid);
            return -1;
        }
    }

    return 0;
}

static int reload_ipintercepts(provision_state_t *currstate,
        ipintercept_t *currints, ipintercept_t *newints,
		prov_intercept_conf_t *intconf, int droppedcols, int droppedmeds) {

    ipintercept_t *ipint, *tmp, *newequiv;

    HASH_ITER(hh_liid, currints, ipint, tmp) {
        HASH_FIND(hh_liid, newints, ipint->common.liid,
                ipint->common.liid_len, newequiv);

        if (!newequiv) {
            /* Intercept has been withdrawn entirely */
            if (!droppedcols) {
                halt_existing_intercept(currstate, (void *)ipint,
                        OPENLI_PROTO_HALT_IPINTERCEPT);
            }
            remove_withdrawn_intercept(currstate, &(ipint->common),
                    ipint->username, droppedmeds);
            continue;
        } else {
            int staticchanged = reload_staticips(currstate, ipint, newequiv);
            int intsame = ip_intercept_equal(ipint, newequiv);
            int agencychanged = strcmp(ipint->common.targetagency,
                    newequiv->common.targetagency);
            int encryptchanged = compare_intercept_encrypt_configuration(
                    &(ipint->common), &(newequiv->common));

            newequiv->awaitingconfirm = 0;

            if (update_reconfigured_intercept(currstate, &(ipint->common),
                    &(newequiv->common), intconf, (!intsame || staticchanged),
                    agencychanged, encryptchanged, droppedmeds, ipint->username,
                    newequiv->username) < 0) {
                return -1;
            }

            if (!intsame && !droppedcols) {
                modify_existing_intercept_options(currstate, (void *)newequiv,
                        OPENLI_PROTO_MODIFY_IPINTERCEPT);
            }
        }
    }

    HASH_ITER(hh_liid, newints, ipint, tmp) {
        int r = 0;

        if (!ipint->awaitingconfirm) {
            continue;
        }

        r = enable_new_intercept(currstate, &(ipint->common), intconf,
                ipint->username, droppedmeds);
        if (r < 0) {
            return r;
        }
        if (r == 0) {
            continue;
        }

        if (!droppedcols && announce_single_intercept(currstate,
                (void *)ipint, push_ipintercept_onto_net_buffer) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to announce new IP intercept to collectors.");
            return -1;
        }
    }
    return 0;
}

static int reload_intercept_config(provision_state_t *currstate,
        int mediatorchanged, int clientchanged) {
    prov_intercept_conf_t newconf;

    init_intercept_config(&newconf);

    if (parse_intercept_config(currstate->interceptconffile, &(newconf),
                currstate->encpassfile) == -1)
    {
        logger(LOG_INFO, "OpenLI provisioner: error while parsing intercept config file '%s'", currstate->interceptconffile);
        return -1;
    }

    pthread_mutex_lock(&(currstate->interceptconf.safelock));
    currstate->interceptconf.destroy_pending = 1;
    pthread_mutex_unlock(&(currstate->interceptconf.safelock));

    if (check_for_duplicate_xids(&newconf, 0, NULL, NULL) == -1) {
        return -1;
    }

    if (map_intercepts_to_leas(&(newconf)) < 0) {
        return -1;
    }

    /* Check each section of the config for changes and update the
     * collectors and mediators accordingly.
     */
    if (!mediatorchanged) {
        if (reload_leas(currstate, &(currstate->interceptconf), &newconf) < 0) {
            return -1;
        }
    }

    if (!clientchanged) {
        if (reload_coreservers(currstate,
                currstate->interceptconf.radiusservers, newconf.radiusservers)
                < 0) {
            return -1;
        }

        if (reload_coreservers(currstate,
                currstate->interceptconf.sipservers, newconf.sipservers) < 0) {
            return -1;
        }

        if (reload_coreservers(currstate,
                currstate->interceptconf.smtpservers,
                newconf.smtpservers) < 0) {
            return -1;
        }

        if (reload_coreservers(currstate,
                currstate->interceptconf.imapservers,
                newconf.imapservers) < 0) {
            return -1;
        }

        if (reload_coreservers(currstate,
                currstate->interceptconf.pop3servers,
                newconf.pop3servers) < 0) {
            return -1;
        }

        if (reload_coreservers(currstate,
                currstate->interceptconf.gtpservers, newconf.gtpservers) < 0) {
            return -1;
        }

        if (reload_default_radius_users(currstate,
                currstate->interceptconf.defradusers, newconf.defradusers) < 0)
        {
            return -1;
        }
    }

	if (reload_voipintercepts(currstate,
				currstate->interceptconf.voipintercepts,
				newconf.voipintercepts, &newconf,
				clientchanged, mediatorchanged) < 0) {
		return -1;
	}

	if (reload_emailintercepts(currstate,
				currstate->interceptconf.emailintercepts,
				newconf.emailintercepts, &newconf,
				clientchanged, mediatorchanged) < 0) {
		return -1;
	}

	if (reload_ipintercepts(currstate,
				currstate->interceptconf.ipintercepts,
				newconf.ipintercepts, &newconf,
				clientchanged, mediatorchanged) < 0) {
		return -1;
    }

    clear_intercept_state(&(currstate->interceptconf));
    currstate->interceptconf = newconf;
    announce_latest_default_email_decompress(currstate);
    announce_all_updated_liidmappings_to_mediators(currstate);
    return 0;
}

static inline int reload_voipoptions_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    if (currstate->ignorertpcomfort != newstate->ignorertpcomfort) {
        currstate->ignorertpcomfort = newstate->ignorertpcomfort;
        if (currstate->ignorertpcomfort) {
            logger(LOG_INFO, "OpenLI: provisioner ignoring RTP comfort noise for all VOIP intercepts");
        } else {
            logger(LOG_INFO, "OpenLI: provisioner intercepting RTP comfort noise for all VOIP intercepts");
        }
        return 1;
    }

    return 0;
}

static inline int reload_collector_socket_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    struct epoll_event ev;

    /* TODO this will trigger on a whitespace change */
    if (strcmp(newstate->listenaddr, currstate->listenaddr) != 0 ||
            strcmp(newstate->listenport, currstate->listenport) != 0) {

        logger(LOG_INFO,
                "OpenLI provisioner: collector listening socket configuration has changed.");
        stop_all_collectors(currstate->epoll_fd, &(currstate->collectors));

        if (epoll_ctl(currstate->epoll_fd, EPOLL_CTL_DEL,
                currstate->clientfd->fd, &ev) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: Failed to remove mediator fd from epoll: %s.",
                    strerror(errno));
            return -1;
        }

        close(currstate->clientfd->fd);
        free(currstate->clientfd);
        free(currstate->listenaddr);
        free(currstate->listenport);
        currstate->listenaddr = strdup(newstate->listenaddr);
        currstate->listenport = strdup(newstate->listenport);

        if (start_main_listener(currstate) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: Warning, listening socket did not restart. Will not be able to accept collector clients.");
            return -1;
        }
        return 1;
    }
    return 0;
}

static inline int reload_mediator_socket_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    struct epoll_event ev;

    /* TODO this will trigger on a whitespace change */
    if (strcmp(newstate->mediateaddr, currstate->mediateaddr) != 0 ||
            strcmp(newstate->mediateport, currstate->mediateport) != 0) {

        free_all_mediators(currstate->epoll_fd, &(currstate->mediators),
                &(currstate->knownmeds));

        if (epoll_ctl(currstate->epoll_fd, EPOLL_CTL_DEL,
                currstate->mediatorfd->fd, &ev) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: Failed to remove mediator fd from epoll: %s.",
                    strerror(errno));
            return -1;
        }

        close(currstate->mediatorfd->fd);
        free(currstate->mediatorfd);
        free(currstate->mediateaddr);
        free(currstate->mediateport);
        currstate->mediateaddr = strdup(newstate->mediateaddr);
        currstate->mediateport = strdup(newstate->mediateport);

        logger(LOG_INFO,
                "OpenLI provisioner: mediation socket configuration has changed.");
        if (start_mediator_listener(currstate) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: Warning, mediation socket did not restart. Will not be able to control mediators.");
            return -1;
        }
        return 1;
    }
    return 0;
}

static inline void replace_clientdb_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    if (currstate->clientdbfile) {
        free(currstate->clientdbfile);
    }
    if (currstate->clientdbkey) {
        free(currstate->clientdbkey);
    }
    currstate->clientdbfile = newstate->clientdbfile;
    currstate->clientdbkey = newstate->clientdbkey;
    newstate->clientdbfile = NULL;
    newstate->clientdbkey = NULL;
}

static inline void replace_restauth_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    if (currstate->restauthdbfile) {
        free(currstate->restauthdbfile);
    }
    if (currstate->restauthkey) {
        free(currstate->restauthkey);
    }
    currstate->restauthdbfile = newstate->restauthdbfile;
    currstate->restauthkey = newstate->restauthkey;
    newstate->restauthdbfile = NULL;
    newstate->restauthkey = NULL;
}

static int reload_clientdb_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    if (currstate->clientdbenabled == 0 &&
            (newstate->clientdbfile == NULL || newstate->clientdbkey == NULL)
            ) {
        /* tracking was disabled and the new config doesn't change that */
        logger(LOG_INFO, "OpenLI provisioner: Client tracking will remain disabled.");
        return 0;
    }

    if (currstate->clientdbenabled == 0) {
        /* tracking was disabled and the new config wants to enable it */
        replace_clientdb_config(currstate, newstate);
    } else {
        if (newstate->clientdbfile == NULL || newstate->clientdbkey == NULL) {
            /* tracking was enabled and now it has been disabled */
            replace_clientdb_config(currstate, newstate);
        } else if (strcmp(currstate->clientdbfile,
                    newstate->clientdbfile) == 0 &&
                strcmp(currstate->clientdbkey, newstate->clientdbkey) == 0) {
            /* tracking is enabled but database etc is unchanged, leave as is */
            logger(LOG_INFO, "OpenLI provisioner: Client tracking database config is unchanged.");
            return 0;
        } else {
            /* tracking was enabled but database or key has changed */
            replace_clientdb_config(currstate, newstate);
        }
    }

    if (currstate->clientdbfile && currstate->clientdbkey) {
#ifdef HAVE_SQLCIPHER
        if (init_clientdb(currstate) < 0) {
            logger(LOG_INFO, "OpenLI provisioner: error while opening client tracking database");
            return -1;
        }
#else
        logger(LOG_INFO, "OpenLI provisioner: Client tracking database options are set, but your OpenLI provisioner was not built with SQLCipher support.");
        logger(LOG_INFO, "OpenLI provisioner: Client tracking will not occur.");
        currstate->clientdbenabled = 0;
#endif
    } else {
        logger(LOG_INFO, "OpenLI provisioner: Client tracking has been disabled");
        currstate->clientdbenabled = 0;
    }

    return 1;
}

static int reload_restauth_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    if (currstate->restauthenabled == 0 &&
            (newstate->restauthdbfile == NULL || newstate->restauthkey == NULL)
            ) {
        /* Auth was disabled and the new config doesn't change that */
        logger(LOG_INFO, "OpenLI provisioner: REST API authentication will remain disabled.");
        return 0;
    }

    if (currstate->restauthenabled == 0) {
        /* Auth was disabled and the new config wants to enable it */
        replace_restauth_config(currstate, newstate);
    } else {
        if (newstate->restauthdbfile == NULL || newstate->restauthkey == NULL) {
            /* Auth was enabled and now it has been disabled */
            replace_restauth_config(currstate, newstate);
        } else if (strcmp(currstate->restauthdbfile,
                    newstate->restauthdbfile) == 0 &&
                strcmp(currstate->restauthkey, newstate->restauthkey) == 0) {
            /* Auth is enabled but database etc is unchanged, leave as is */
            logger(LOG_INFO, "OpenLI provisioner: REST API authentication config is unchanged.");
            return 0;
        } else {
            /* Auth was enabled but database or key has changed */
            replace_restauth_config(currstate, newstate);
        }
    }

    if (currstate->restauthdbfile && currstate->restauthkey) {
#ifdef HAVE_SQLCIPHER
        if (init_restauth_db(currstate) < 0) {
            logger(LOG_INFO, "OpenLI provisioner: error while opening REST authentication database");
            return -1;
        }
#else
        logger(LOG_INFO, "OpenLI provisioner: REST Auth DB options are set, but your system does not support using an Auth DB.");
        logger(LOG_INFO, "OpenLI provisioner: Auth DB options ignored.");
        currstate->restauthenabled = 0;
#endif
    } else {
        logger(LOG_INFO, "OpenLI provisioner: REST API does NOT require authentication");
        currstate->restauthenabled = 0;
    }

    return 1;
}

static inline int reload_push_socket_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    int changed = 0;

    /* TODO this will trigger on a whitespace change */

    if (strcmp(newstate->pushport, currstate->pushport) != 0 ||
            (currstate->pushaddr == NULL && newstate->pushaddr != NULL) ||
            (currstate->pushaddr != NULL && newstate->pushaddr == NULL) ||
            (currstate->pushaddr && newstate->pushaddr &&
             strcmp(newstate->pushaddr, currstate->pushaddr) != 0)) {

        if (currstate->updatedaemon) {
            MHD_stop_daemon(currstate->updatedaemon);
        }
        currstate->updatedaemon = NULL;

        if (currstate->pushaddr) {
            free(currstate->pushaddr);
        }
        free(currstate->pushport);

        if (newstate->pushaddr) {
            currstate->pushaddr = newstate->pushaddr;
            newstate->pushaddr = NULL;
        } else {
            currstate->pushaddr = NULL;
        }
        currstate->pushport = newstate->pushport;
        newstate->pushport = NULL;
        changed = 1;
    }

    if (changed) {
        logger(LOG_INFO,
                "OpenLI provisioner: update socket configuration has changed.");
        if (strcmp(currstate->pushport, "0") == 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: disabling update socket.");
            logger(LOG_INFO,
                    "OpenLI provisioner: warning -- intercept configuration can not be updated while the provisioner is running.");
            currstate->updatesockfd = -1;
        } else {
            currstate->updatesockfd = create_listener(currstate->pushaddr,
                    currstate->pushport, "update socket");

            if (currstate->updatesockfd != -1) {
                start_mhd_daemon(currstate);
            }

            if (currstate->updatesockfd == -1 || currstate->updatedaemon == NULL) {
                logger(LOG_INFO,
                        "OpenLI provisioner: Warning, update socket did not restart. Will not be able to receive live updates.");
                return -1;
            }
        }
        return 1;
    }
    return 0;

}


int reload_provisioner_config(provision_state_t *currstate) {
	provision_state_t newstate;
    int mediatorchanged = 0;
    int clientchanged = 0;
    int pushchanged = 0;
    int tlschanged = 0;
    int voipoptschanged = 0;
    int restauthchanged = 0, clientdbchanged = 0;
    char *target_info;

    if (init_prov_state(&newstate, currstate->conffile,
                currstate->encpassfile) == -1) {
        logger(LOG_INFO,
                "OpenLI: Error reloading config file for provisioner.");
        return -1;
    }

    /* integrity signing key changes are local to the provisioner, so
     * there is no need to notify clients
     */
    if (currstate->integrity_sign_private_key_location) {
        free(currstate->integrity_sign_private_key_location);
    }
    currstate->integrity_sign_private_key_location =
            newstate.integrity_sign_private_key_location;
    newstate.integrity_sign_private_key_location = NULL;
    load_integrity_signing_privatekey(currstate);


    /* Only make changes if the relevant configuration has changed, so as
     * to minimise interruptions.
     */
    mediatorchanged = reload_mediator_socket_config(currstate, &newstate);
    if (mediatorchanged == -1) {
        clear_prov_state(&newstate);
        return -1;
    }

    pushchanged = reload_push_socket_config(currstate, &newstate);
    if (pushchanged == -1) {
        clear_prov_state(&newstate);
        return -1;
    }

    restauthchanged = reload_restauth_config(currstate, &newstate);
    if (restauthchanged == -1) {
        clear_prov_state(&newstate);
        return -1;
    }

    clientdbchanged = reload_clientdb_config(currstate, &newstate);
    if (clientdbchanged == -1) {
        clear_prov_state(&newstate);
        return -1;
    }

    clientchanged = reload_collector_socket_config(currstate, &newstate);
    if (clientchanged == -1) {
        clear_prov_state(&newstate);
        return -1;
    }

    tlschanged = reload_ssl_config(&(currstate->sslconf), &(newstate.sslconf));
    if (tlschanged == -1) {
        clear_prov_state(&newstate);
        return -1;
    }

    if (reload_intercept_config_filename(currstate, &newstate) < 0) {
        clear_prov_state(&newstate);
        return -1;
    }

    voipoptschanged = reload_voipoptions_config(currstate, &newstate);
    if (voipoptschanged && !clientchanged) {
        voipintercept_t *vint, *tmp;

        pthread_mutex_lock(&(currstate->interceptconf.safelock));
        HASH_ITER(hh_liid, currstate->interceptconf.voipintercepts, vint, tmp) {
            if (currstate->ignorertpcomfort) {
                vint->options |= (1UL << OPENLI_VOIPINT_OPTION_IGNORE_COMFORT);
            } else {
                vint->options &= ~(1UL << OPENLI_VOIPINT_OPTION_IGNORE_COMFORT);
            }

            modify_existing_intercept_options(currstate, (void *)vint,
                    OPENLI_PROTO_MODIFY_VOIPINTERCEPT);
            target_info = list_sip_targets(vint, 256);
            announce_hi1_notification_to_mediators(currstate,
                    &(vint->common), target_info,
                    HI1_LI_MODIFIED);
            if (target_info) {
                free(target_info);
            }
        }
        pthread_mutex_unlock(&(currstate->interceptconf.safelock));
    }

    if (tlschanged != 0) {
        if (!mediatorchanged) {
            free_all_mediators(currstate->epoll_fd, &(currstate->mediators),
                    &(currstate->knownmeds));
            mediatorchanged = 1;
        }
        if (!clientchanged) {
            stop_all_collectors(currstate->epoll_fd, &(currstate->collectors));
            clientchanged = 1;
        }
    }

    if (mediatorchanged && !clientchanged) {
        /* Tell all collectors to drop their mediators until further notice */
        disconnect_mediators_from_collectors(currstate);

    }

    if (!clientchanged) {
        if (announce_latest_default_email_decompress(currstate) < 0) {
            clear_prov_state(&newstate);
            return -1;
        }
    }

    if (reload_intercept_config(currstate, mediatorchanged, clientchanged) < 0)
    {
        clear_prov_state(&newstate);
        return -1;
    }

    clear_prov_state(&newstate);

    return 0;


}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
