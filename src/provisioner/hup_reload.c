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

#include "config.h"
#include "provisioner.h"
#include "logger.h"
#include "util.h"
#include "configparser.h"
#include "updateserver.h"

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

static inline int ip_intercept_equal(ipintercept_t *a, ipintercept_t *b) {
    if (strcmp(a->common.liid, b->common.liid) != 0) {
        return 0;
    }

    if (strcmp(a->common.authcc, b->common.authcc) != 0) {
        return 0;
    }

    if (strcmp(a->common.delivcc, b->common.delivcc) != 0) {
        return 0;
    }

    if (a->username && b->username && strcmp(a->username, b->username) != 0) {
        return 0;
    }

    if (a->vendmirrorid != b->vendmirrorid) {
        return 0;
    }

    if (strcmp(a->common.targetagency, b->common.targetagency) != 0) {
        return 0;
    }

    if (a->accesstype != b->accesstype) {
        return 0;
    }

    return 1;
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
            /* Agency has changed, withdraw current and announce new */
            withdraw_agency_from_mediators(state, lea);
            newequiv->announcereq = 1;
        }
    }

    HASH_ITER(hh, latest->leas, lea, tmp) {
        if (lea->announcereq) {
            announce_lea_to_mediators(state, lea);
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

static int reload_voipintercepts(provision_state_t *currstate,
        voipintercept_t *currvoip, voipintercept_t *newvoip,
		prov_intercept_conf_t *intconf, int droppedcols, int droppedmeds) {

    voipintercept_t *voipint, *tmp, *newequiv;
    int changedtargets = 0;

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
            remove_liid_mapping(currstate, voipint->common.liid,
                    voipint->common.liid_len, droppedmeds);
            if (!droppedmeds) {
                announce_hi1_notification_to_mediators(currstate,
                        &(voipint->common), HI1_LI_DEACTIVATED);
            }
            continue;
        } else if (!voip_intercept_equal(voipint, newequiv)) {
            /* VOIP intercept has changed somehow -- this probably
             * shouldn't happen but deal with it anyway
             */
            logger(LOG_INFO,
                    "OpenLI provisioner: Details for VOIP intercept %s have changed -- updating collectors",
                    voipint->common.liid);

            if (!droppedcols) {
                halt_existing_intercept(currstate, (void *)voipint,
                        OPENLI_PROTO_HALT_VOIPINTERCEPT);
            }
            if (!droppedmeds) {
                announce_hi1_notification_to_mediators(currstate,
                        &(voipint->common), HI1_LI_MODIFIED);
            }
            remove_liid_mapping(currstate, voipint->common.liid,
                    voipint->common.liid_len, droppedmeds);

        } else {
            if ((changedtargets = compare_sip_targets(currstate, voipint,
                    newequiv)) < 0) {
                return -1;
            }
            if (changedtargets > 0) {
                if (announce_hi1_notification_to_mediators(currstate,
                        &(voipint->common), HI1_LI_MODIFIED) == -1) {
                    logger(LOG_INFO,
                            "OpenLI provisioner: unable to send HI1 notification for modified VOIP intercept to mediators.");
                    return -1;
                }
            }
            newequiv->awaitingconfirm = 0;
        }

        newequiv->common.hi1_seqno = voipint->common.hi1_seqno;

        if (voipint->options != newequiv->options &&
                HASH_CNT(hh, currstate->collectors) > 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: Options for VOIP intercept %s have changed",
                    voipint->common.liid);
            if (!droppedcols) {
                modify_existing_intercept_options(currstate, (void *)newequiv,
                        OPENLI_PROTO_MODIFY_IPINTERCEPT);
            }
            /* Probably don't need to announce an HI1 modification here, as
             * these options are not part of the intercept definition */
        }
    }

    HASH_ITER(hh_liid, newvoip, voipint, tmp) {
        liid_hash_t *h = NULL;
        int skip = 0;
        prov_agency_t *lea = NULL;

        if (!voipint->awaitingconfirm) {
            continue;
        }

        if (strcmp(voipint->common.targetagency, "pcapdisk") != 0) {
            HASH_FIND_STR(intconf->leas, voipint->common.targetagency, lea);
            if (lea == NULL) {
                skip = 1;
            }
        }

        if (skip) {
            continue;
        }

        if (currstate->ignorertpcomfort) {
            voipint->options |= (1 << OPENLI_VOIPINT_OPTION_IGNORE_COMFORT);
        }

        /* Add the LIID mapping */
        h = add_liid_mapping(intconf, voipint->common.liid,
                voipint->common.targetagency);

        if (!droppedmeds && announce_hi1_notification_to_mediators(currstate,
                &(voipint->common), HI1_LI_ACTIVATED) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to send HI1 notification for new VOIP intercept to mediators.");
            return -1;
        }

        if (!droppedmeds && announce_liidmapping_to_mediators(currstate,
                h) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to announce new VOIP intercept to mediators.");
            return -1;
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
    liid_hash_t *h = NULL;

    /* TODO error handling in the "inform other components about changes"
     * functions?
     */
    HASH_ITER(hh_liid, currints, ipint, tmp) {
        HASH_FIND(hh_liid, newints, ipint->common.liid,
                ipint->common.liid_len, newequiv);
        if (!newequiv) {
            /* Intercept has been withdrawn entirely */
            if (!droppedcols) {
                halt_existing_intercept(currstate, (void *)ipint,
                        OPENLI_PROTO_HALT_IPINTERCEPT);
            }
            remove_liid_mapping(currstate, ipint->common.liid,
                    ipint->common.liid_len, droppedmeds);
            if (!droppedmeds) {
                announce_hi1_notification_to_mediators(currstate,
                        &(ipint->common), HI1_LI_DEACTIVATED);
            }
            logger(LOG_INFO, "OpenLI provisioner: LIID %s has been withdrawn",
                    ipint->common.liid);
            continue;
        } else if (!ip_intercept_equal(ipint, newequiv)) {
            /* IP intercept has changed somehow -- this probably
             * shouldn't happen but deal with it anyway
             */
            logger(LOG_INFO, "OpenLI provisioner: Details for IP intercept %s have changed -- updating collectors",
                    ipint->common.liid);

            newequiv->common.hi1_seqno = ipint->common.hi1_seqno;

            if (!droppedmeds) {
                announce_hi1_notification_to_mediators(currstate,
                        &(newequiv->common), HI1_LI_MODIFIED);
            }

            if (!droppedcols) {
                modify_existing_intercept_options(currstate, (void *)newequiv,
                        OPENLI_PROTO_MODIFY_IPINTERCEPT);
                newequiv->awaitingconfirm = 0;
            }

            if (strcmp(ipint->common.targetagency,
                    newequiv->common.targetagency) != 0) {
                remove_liid_mapping(currstate, ipint->common.liid,
                        ipint->common.liid_len, droppedmeds);

                if (newequiv->awaitingconfirm == 0) {
                    h = add_liid_mapping(intconf, newequiv->common.liid,
                            newequiv->common.targetagency);

                    if (!droppedmeds &&
                            announce_liidmapping_to_mediators(currstate, h)
                            == -1) {
                        logger(LOG_INFO,
                                "OpenLI provisioner: unable to announce new IP intercept to mediators.");
                        return -1;
                    }
                }
            }
        } else {
            newequiv->common.hi1_seqno = ipint->common.hi1_seqno;
            if (reload_staticips(currstate, ipint, newequiv) > 0) {
                if (!droppedmeds) {
                    announce_hi1_notification_to_mediators(currstate,
                            &(newequiv->common), HI1_LI_MODIFIED);

                }
            }

            newequiv->awaitingconfirm = 0;
        }
    }

    HASH_ITER(hh_liid, newints, ipint, tmp) {
        int skip = 0;
        prov_agency_t *lea = NULL;

        if (!ipint->awaitingconfirm) {
            continue;
        }

        if (strcmp(ipint->common.targetagency, "pcapdisk") != 0) {
            HASH_FIND_STR(intconf->leas, ipint->common.targetagency, lea);
            if (lea == NULL) {
                skip = 1;
            }
        }

        if (skip) {
            continue;
        }

        /* Add the LIID mapping */
        h = add_liid_mapping(intconf, ipint->common.liid,
                ipint->common.targetagency);

        if (!droppedmeds && announce_hi1_notification_to_mediators(currstate,
                &(ipint->common), HI1_LI_ACTIVATED) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to send HI1 notification for new IP intercept to mediators.");
            return -1;
        }

        if (!droppedmeds && announce_liidmapping_to_mediators(currstate,
                h) == -1) {
            logger(LOG_INFO,
                    "OpenLI provisioner: unable to announce new IP intercept to mediators.");
            return -1;
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

    if (parse_intercept_config(currstate->interceptconffile, &(newconf)) == -1)
    {
        logger(LOG_INFO, "OpenLI provisioner: error while parsing intercept config file '%s'", currstate->interceptconffile);
        return -1;
    }

    pthread_mutex_lock(&(currstate->interceptconf.safelock));
    currstate->interceptconf.destroy_pending = 1;
    pthread_mutex_unlock(&(currstate->interceptconf.safelock));

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

	if (reload_ipintercepts(currstate,
				currstate->interceptconf.ipintercepts,
				newconf.ipintercepts, &newconf,
				clientchanged, mediatorchanged) < 0) {
		return -1;
    }

    clear_intercept_state(&(currstate->interceptconf));
    currstate->interceptconf = newconf;
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

static int reload_restauth_config(provision_state_t *currstate,
        provision_state_t *newstate) {

    int changed = 0;

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
        changed = 1;
    } else {
        if (newstate->restauthdbfile == NULL || newstate->restauthkey == NULL) {
            /* Auth was enabled and now it has been disabled */
            replace_restauth_config(currstate, newstate);
            changed = 1;
        } else if (strcmp(currstate->restauthdbfile,
                    newstate->restauthdbfile) == 0 &&
                strcmp(currstate->restauthkey, newstate->restauthkey) == 0) {
            /* Auth is enabled but database etc is unchanged, leave as is */
            logger(LOG_INFO, "OpenLI provisioner: REST API authentication config is unchanged.");
            return 0;
        } else {
            /* Auth was enabled but database or key has changed */
            replace_restauth_config(currstate, newstate);
            changed = 1;
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
    int restauthchanged = 0;

    if (init_prov_state(&newstate, currstate->conffile) == -1) {
        logger(LOG_INFO,
                "OpenLI: Error reloading config file for provisioner.");
        return -1;
    }

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
            announce_hi1_notification_to_mediators(currstate,
                    &(vint->common), HI1_LI_MODIFIED);
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

    if (reload_intercept_config(currstate, mediatorchanged, clientchanged) < 0)
    {
        clear_prov_state(&newstate);
        return -1;
    }

    clear_prov_state(&newstate);

    return 0;


}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
