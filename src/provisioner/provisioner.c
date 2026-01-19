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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <errno.h>
#include <libtrace/linked_list.h>
#include <unistd.h>
#include <assert.h>

#include "configparser_provisioner.h"
#include "logger.h"
#include "intercept.h"
#include "provisioner.h"
#include "util.h"
#include "agency.h"
#include "netcomms.h"
#include "coreserver.h"
#include "openli_tls.h"
#include "provisioner_client.h"
#include "updateserver.h"
#include "intercept_timers.h"

volatile int provisioner_halt = 0;
volatile int reload_config = 0;

static void halt_signal(int signal) {
    (void) signal;
    provisioner_halt = 1;
}

static void reload_signal(int signal) {
    (void) signal;
    reload_config = 1;
}

static inline const char *get_event_description(prov_epoll_ev_t *pev) {
    if (pev->fdtype == PROV_EPOLL_MEDIATOR) return "mediator";
    if (pev->fdtype == PROV_EPOLL_COLLECTOR) return "collector";
    if (pev->fdtype == PROV_EPOLL_SIGNAL) return "signal";
    if (pev->fdtype == PROV_EPOLL_FD_TIMER) return "auth timer";
    if (pev->fdtype == PROV_EPOLL_UPDATE) return "updater";
    if (pev->fdtype == PROV_EPOLL_MAIN_TIMER) return "main timer";
    if (pev->fdtype == PROV_EPOLL_FD_IDLETIMER) return "client idle timer";
    if (pev->fdtype == PROV_EPOLL_INTERCEPT_START)
        return "intercept start timer";
    if (pev->fdtype == PROV_EPOLL_INTERCEPT_HALT) return "intercept halt timer";
    return "unknown";
}

void start_mhd_daemon(provision_state_t *state) {

    int fd, off, len;
    char rndseed[8];

    assert(state->updatesockfd >= 0);

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        if (state->restauthenabled == 1) {
            logger(LOG_INFO, "Failed to generate random seed for REST authentication: %s", strerror(errno));
            return;
        }
    }
    off = 0;
    while (off < 8) {
        if ((len = read(fd, rndseed + off, 8 - off)) == -1) {
            if (state->restauthenabled == 1) {
                logger(LOG_INFO, "Failed to populate random seed for REST authentication: %s", strerror(errno));
                close(fd);
                return;
            }
        }
        off += len;
    }
    close(fd);

    if (state->sslconf.certfile && state->sslconf.keyfile) {
        if (load_pem_into_memory(state->sslconf.keyfile, &(state->key_pem)) < 0)
        {
            goto startnotls;
        }
        if (load_pem_into_memory(state->sslconf.certfile, &(state->cert_pem))
                < 0) {
            goto startnotls;
        }

        state->updatedaemon = MHD_start_daemon(
                MHD_USE_SELECT_INTERNALLY | MHD_USE_SSL,
                0,
                NULL,
                NULL,
                &handle_update_request,
                state,
                MHD_OPTION_LISTEN_SOCKET,
                state->updatesockfd,
                MHD_OPTION_NOTIFY_COMPLETED,
                &complete_update_request,
                state,
                MHD_OPTION_HTTPS_MEM_KEY,
                state->key_pem,
                MHD_OPTION_HTTPS_MEM_CERT,
                state->cert_pem,
                MHD_OPTION_NONCE_NC_SIZE,
                300,
                MHD_OPTION_DIGEST_AUTH_RANDOM,
                sizeof(rndseed), rndseed,
                MHD_OPTION_END);
        return;
    }

startnotls:
    state->updatedaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
            0,
            NULL,
            NULL,
            &handle_update_request,
            state,
            MHD_OPTION_LISTEN_SOCKET,
            state->updatesockfd,
            MHD_OPTION_NOTIFY_COMPLETED,
            &complete_update_request,
            state,
            MHD_OPTION_NONCE_NC_SIZE,
            300,
            MHD_OPTION_DIGEST_AUTH_RANDOM,
            sizeof(rndseed), rndseed,
            MHD_OPTION_END);
}

void init_intercept_config(prov_intercept_conf_t *state) {

    state->radiusservers = NULL;
    state->gtpservers = NULL;
    state->sipservers = NULL;
    state->smtpservers = NULL;
    state->imapservers = NULL;
    state->pop3servers = NULL;
    state->voipintercepts = NULL;
    state->emailintercepts = NULL;
    state->ipintercepts = NULL;
    state->liid_map = NULL;
    state->leas = NULL;
    state->defradusers = NULL;
    state->udp_sink_intercept_mappings = NULL;
    state->destroy_pending = 0;
    state->was_encrypted = 0;
    state->default_email_deliver_compress =
            OPENLI_EMAILINT_DELIVER_COMPRESSED_ASIS;
    pthread_mutex_init(&(state->safelock), NULL);
}

static int liid_hash_sort(liid_hash_t *a, liid_hash_t *b) {

    int x;

    x = strcmp(a->agency, b->agency);
    if (x != 0) {
        return x;
    }
    return strcmp(a->liid, b->liid);
}

int map_intercepts_to_leas(prov_intercept_conf_t *conf) {

    int failed = 0;
    ipintercept_t *ipint, *iptmp;
    voipintercept_t *vint;
    emailintercept_t *mailint;

    /* Do IP Intercepts */
    HASH_ITER(hh_liid, conf->ipintercepts, ipint, iptmp) {
        apply_intercept_encryption_settings(conf, &(ipint->common));
        add_liid_mapping(conf, &(ipint->common));
    }

    /* Now do the VOIP intercepts */
    for (vint = conf->voipintercepts; vint != NULL; vint = vint->hh_liid.next)
    {
        apply_intercept_encryption_settings(conf, &(vint->common));
        add_liid_mapping(conf, &(vint->common));
    }

    for (mailint = conf->emailintercepts; mailint != NULL;
            mailint = mailint->hh_liid.next) {
        apply_intercept_encryption_settings(conf, &(mailint->common));
        add_liid_mapping(conf, &(mailint->common));
    }

    /* Sort the final mapping nicely */
    HASH_SORT(conf->liid_map, liid_hash_sort);

    return failed;

}

static void free_openli_mediator(openli_mediator_t *med) {
    if (!med) {
        return;
    }
    if (med->portstr) {
        free(med->portstr);
    }
    if (med->ipstr) {
        free(med->ipstr);
    }
    free(med);
}

int init_prov_state(provision_state_t *state, char *configfile,
        const char *encpassfile) {

    sigset_t sigmask;

    state->conffile = configfile;
    state->encpassfile = encpassfile;
    state->interceptconffile = NULL;
    state->updatedaemon = NULL;
    state->updatesockfd = -1;

    state->epoll_fd = epoll_create1(0);
    state->mediators = NULL;
    state->collectors = NULL;
    state->pendingclients = NULL;
    state->knownmeds = NULL;

    /* Three listening sockets
     *
     * listen:  collectors should connect to this socket to receive IIs
     * mediate: mediators should connect to this socket to receive mediation
     *          instructions
     * push:    new IIs or config changes will come via this socket
     */
    state->listenport = NULL;
    state->listenaddr = NULL;
    state->mediateport = NULL;
    state->mediateaddr = NULL;
    state->pushport = NULL;
    state->pushaddr = NULL;

    state->sslconf.certfile = NULL;
    state->sslconf.keyfile = NULL;
    state->sslconf.cacertfile = NULL;
    state->sslconf.logkeyfile = NULL;
    state->sslconf.ctx = NULL;

    state->key_pem = NULL;
    state->cert_pem = NULL;

    state->encrypt_intercept_config = 0;
    state->ignorertpcomfort = 0;
    state->restauthenabled = 0;
    state->restauthdbfile = NULL;
    state->restauthkey = NULL;
    state->clientdbfile = NULL;
    state->clientdbkey = NULL;
    state->clientdb = NULL;
    state->authdb = NULL;
    state->integrity_sign_private_key = NULL;
    state->integrity_sign_private_key_location = NULL;
    state->sign_ctx = NULL;

    init_intercept_config(&(state->interceptconf));

    if (parse_provisioning_config(configfile, state) == -1) {
        logger(LOG_INFO, "OpenLI provisioner: error while parsing provisioner config in %s", configfile);
        return -1;
    }

    if (state->encrypt_intercept_config && state->encpassfile == NULL) {
        logger(LOG_INFO, "OpenLI provisioner: configuration requested that intercept config file be encrypted, but no key has been provided via the -K option!");
        logger(LOG_INFO, "OpenLI provisioner: disabling intercept config encryption");
        state->encrypt_intercept_config = 0;
    }

    if (state->encrypt_intercept_config) {
        logger(LOG_INFO, "OpenLI provisioner: intercept configuration will be encrypted");
    } else {
        logger(LOG_INFO, "OpenLI provisioner: intercept configuration will be plain text");
    }

    if (state->pushport == NULL) {
        state->pushport = strdup("8992");
    }
    if (state->listenport == NULL) {
        state->listenport = strdup("8993");
    }
    if (state->mediateport == NULL) {
        state->mediateport = strdup("8994");
    }

    state->clientfd = NULL;
    state->mediatorfd = NULL;
    state->timerfd = NULL;

    if (create_ssl_context(&(state->sslconf)) < 0) {
        return -1;
    }

    if (load_integrity_signing_privatekey(state) < 0) {
        return -1;
    }

    /* Use an fd to catch signals during our main epoll loop, so that we
     * can provide our own signal handling without causing epoll_wait to
     * return EINTR.
     */
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGTERM);
    sigaddset(&sigmask, SIGINT);
    sigaddset(&sigmask, SIGHUP);

    state->signalfd = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));
    state->signalfd->fdtype = PROV_EPOLL_SIGNAL;
    state->signalfd->fd = signalfd(-1, &sigmask, 0);
    state->signalfd->client = NULL;

    return 0;
}

static int announce_mediator(provision_state_t *state,
        prov_mediator_t *med) {

    prov_collector_t *col, *coltmp;

    HASH_ITER(hh, state->collectors, col, coltmp) {
        prov_sock_state_t *cs = (prov_sock_state_t *)(col->client->state);

        if (cs == NULL) {
            continue;
        }

        if (col->client->commev == NULL ||
                col->client->commev->fdtype != PROV_EPOLL_COLLECTOR) {
            continue;
        }

        if (col->client->commev->fd == -1) {
            continue;
        }

        if (cs->trusted == 0) {
            continue;
        }

        if (push_mediator_onto_net_buffer(cs->outgoing, med->details) < 0) {
            if (cs->log_allowed) {
                logger(LOG_INFO,
                    "OpenLI provisioner: error pushing mediator %s:%s onto buffer for writing to collector %s.",
                    med->details->ipstr, med->details->portstr,
                    col->identifier);
            }
            return -1;
        }
        if (enable_epoll_write(state, col->client->commev) == -1) {
            if (cs->log_allowed) {
                logger(LOG_INFO,
                    "OpenLI provisioner: cannot enable epoll write event to transmit mediator update to collector %s -- %s.",
                    col->identifier, strerror(errno));
            }
            return -1;
        }
    }
    return 0;
}

static int announce_mediator_withdraw(provision_state_t *state,
        prov_mediator_t *med) {

    prov_collector_t *col, *coltmp;

    HASH_ITER(hh, state->collectors, col, coltmp) {
        prov_sock_state_t *cs = (prov_sock_state_t *)(col->client->state);

        if (cs == NULL) {
            continue;
        }

        if (col->client->commev == NULL ||
                col->client->commev->fdtype != PROV_EPOLL_COLLECTOR) {
            continue;
        }

        if (col->client->commev->fd == -1) {
            continue;
        }

        if (cs->trusted == 0) {
            continue;
        }

        if (push_mediator_withdraw_onto_net_buffer(cs->outgoing,
                med->details) < 0) {
            if (cs->log_allowed) {
                logger(LOG_INFO,
                        "OpenLI provisioner: error pushing mediator withdrawal %s:%s onto buffer for writing to collector %s.",
                        med->details->ipstr, med->details->portstr,
                        col->identifier);
            }
            return -1;
        }
        if (enable_epoll_write(state, col->client->commev) == -1) {
            if (cs->log_allowed) {
                logger(LOG_INFO,
                    "OpenLI provisioner: cannot enable epoll write event to transmit mediator update to collector %s -- %s.",
                    col->identifier, strerror(errno));
            }
            return -1;
        }
    }
    return 0;
}

static int add_collector_to_hashmap(provision_state_t *state,
        prov_client_t *client, prov_sock_state_t *cs, uint8_t *msgbody,
        uint16_t msglen) {

    prov_collector_t *col;
    char *jsonconfig = NULL;
    char *uuidstr = NULL;

    if (decode_component_name(msgbody, msglen, &jsonconfig, &uuidstr) < 0) {
        logger(LOG_INFO, "OpenLI provisioner: invalid formatting of collector authentication announcement from %s", client->identifier);
        return -1;
    }

    if (!uuidstr) {
        logger(LOG_INFO, "OpenLI provisioner: collector authentication announcement from %s does not include a UUID -- is there a version mismatch between the provisioner and collector?", client->identifier);
        return -1;
    }

    HASH_FIND(hh, state->collectors, uuidstr, strlen(uuidstr), col);

    if (!col) {
        col = calloc(1, sizeof(prov_collector_t));
        col->identifier = uuidstr;
        col->jsonconfig = jsonconfig;
        col->client = client;
        HASH_ADD_KEYPTR(hh, state->collectors, col->identifier,
                strlen(col->identifier), col);
    } else if (col->client != client) {
        HASH_DELETE(hh, state->collectors, col);
        destroy_provisioner_client(state->epoll_fd, col->client,
                col->client->identifier);
        if (col->identifier) {
            free(col->identifier);
        }
        if (col->jsonconfig) {
            free(col->jsonconfig);
        }
        col->identifier = uuidstr;
        col->jsonconfig = jsonconfig;
        col->client = client;
        HASH_ADD_KEYPTR(hh, state->collectors, col->identifier,
                strlen(col->identifier), col);
    } else {
        free(jsonconfig);
        free(uuidstr);
    }

    cs->parent = (void *)col;
    logger(LOG_INFO,
            "OpenLI provisioner: collector %s is now active",
            col->identifier);

    return 0;
}

static int update_mediator_details(provision_state_t *state, uint8_t *medmsg,
        uint16_t msglen, prov_sock_state_t *cs, char *clientname) {

    openli_mediator_t *med = (openli_mediator_t *)malloc(
            sizeof(openli_mediator_t));
    openli_mediator_t *tmp = NULL;
    prov_client_t *pending;
    mediator_address_t *knownaddr;
    prov_mediator_t *provmed = NULL, *prevmed = NULL;
    char identifier[1024];
    int ret = 0, skipannounce = 0;

    if (decode_mediator_announcement(medmsg, msglen, med) == -1) {
        logger(LOG_INFO,
                "OpenLI: provisioner received bogus mediator announcement.");
        free(med);
        return -1;
    }

    HASH_FIND(hh, state->pendingclients, clientname, strlen(clientname),
            pending);

    if (!pending) {
        logger(LOG_INFO,
                "OpenLI provisioner: received an announcement from mediator %u via %s, but this mediator is unknown to us?",
                med->mediatorid, clientname);
        free(med->ipstr);
        free(med->portstr);
        free(med);
        return -1;
    }

    HASH_FIND(hh, state->mediators, &(med->mediatorid), sizeof(med->mediatorid),
            prevmed);

    if (prevmed) {

        if (prevmed->mediatorid == med->mediatorid &&
                strcmp(prevmed->details->ipstr, med->ipstr) == 0 &&
                strcmp(prevmed->details->portstr, med->portstr) == 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: mediator %u has reconnected (%s:%s)",
                    med->mediatorid, med->ipstr, med->portstr);
            skipannounce = 1;
        } else {

            logger(LOG_INFO,
                    "OpenLI provisioner: replacing mediator %u (%s:%s) with %u (%s:%s)",
                    prevmed->mediatorid, prevmed->details->ipstr,
                    prevmed->details->portstr,
                    med->mediatorid, med->ipstr, med->portstr);
        }

        //announce_mediator_withdraw(state, prevmed);
        tmp = prevmed->details;
        prevmed->details = med;
        provmed = prevmed;

        free(tmp->ipstr);
        free(tmp->portstr);
        free(tmp);
    } else {

        provmed = calloc(1, sizeof(prov_mediator_t));
        provmed->mediatorid = med->mediatorid;
        provmed->details = med;

        HASH_ADD_KEYPTR(hh, state->mediators, &(provmed->mediatorid),
                sizeof(provmed->mediatorid), provmed);
    }

    if (provmed->client != NULL) {
        destroy_provisioner_client(state->epoll_fd, provmed->client,
                provmed->client->identifier);
    }

    provmed->client = pending;
    HASH_DELETE(hh, state->pendingclients, pending);
    cs->parent = (void *)provmed;

    if (skipannounce) {
        return ret;
    }

    /* If another mediator is using the same IP + port as a previous one,
     * we need to make sure collectors do not connect to that socket for
     * the old mediator.
     */
    snprintf(identifier, 1024, "%s-%s", med->ipstr, med->portstr);

    HASH_FIND(hh, state->knownmeds, identifier, strlen(identifier), knownaddr);
    if (!knownaddr) {
        knownaddr = calloc(1, sizeof(mediator_address_t));
        knownaddr->medid = provmed->mediatorid;
        knownaddr->ipportstr = strdup(identifier);

        HASH_ADD_KEYPTR(hh, state->knownmeds, knownaddr->ipportstr,
                strlen(knownaddr->ipportstr), knownaddr);
    } else {
        logger(LOG_INFO,
                "OpenLI provisioner: duplicate use of %s by mediators %u and %u, removing %u",
                identifier, knownaddr->medid, provmed->mediatorid,
                knownaddr->medid);
        HASH_FIND(hh, state->mediators, &(knownaddr->medid),
                sizeof(knownaddr->medid), prevmed);
        knownaddr->medid = provmed->mediatorid;

        if (prevmed) {
            announce_mediator_withdraw(state, prevmed);
            HASH_DELETE(hh, state->mediators, prevmed);
            free_openli_mediator(prevmed->details);
            destroy_provisioner_client(state->epoll_fd, prevmed->client,
                    identifier);
            free(prevmed);
        }
    }

    if (provmed) {
        announce_mediator(state, provmed);
    }

    return ret;
}

static void free_all_pending(int epollfd, prov_client_t **pending) {

    prov_client_t *client, *tmp;

    HASH_ITER(hh, *pending, client, tmp) {
        HASH_DELETE(hh, *pending, client);
        destroy_provisioner_client(epollfd, client, client->identifier);
    }
}

void free_all_mediators(int epollfd, prov_mediator_t **mediators,
        mediator_address_t **knownmeds) {

    prov_mediator_t *med, *medtmp;
    mediator_address_t *kaddr, *ktmp;

    HASH_ITER(hh, *mediators, med, medtmp) {
        HASH_DELETE(hh, *mediators, med);
        destroy_provisioner_client(epollfd, med->client, med->details->ipstr);
        free_openli_mediator(med->details);
        free(med);
    }

    HASH_ITER(hh, *knownmeds, kaddr, ktmp) {
        HASH_DELETE(hh, *knownmeds, kaddr);
        if (kaddr->ipportstr) {
            free(kaddr->ipportstr);
        }
        free(kaddr);
    }
}

void stop_all_collectors(int epollfd, prov_collector_t **collectors) {

    prov_collector_t *col, *coltmp;

    HASH_ITER(hh, *collectors, col, coltmp) {
        HASH_DELETE(hh, *collectors, col);
        destroy_provisioner_client(epollfd, col->client, col->identifier);
        free(col->identifier);
        if (col->jsonconfig) {
            free(col->jsonconfig);
        }
        free(col);
    }
}

void clear_intercept_state(prov_intercept_conf_t *conf) {

    liid_hash_t *h, *tmp;
    prov_agency_t *h2, *tmp2;
    default_radius_user_t *h3, *tmp3;
    udp_sink_intercept_mapping_t *h4, *tmp4;

    pthread_mutex_lock(&(conf->safelock));
    conf->destroy_pending = 1;
    pthread_mutex_unlock(&(conf->safelock));

    HASH_ITER(hh, conf->liid_map, h, tmp) {
        HASH_DEL(conf->liid_map, h);
        free(h);
    }

    HASH_ITER(hh, conf->defradusers, h3, tmp3) {
        HASH_DEL(conf->defradusers, h3);
        if (h3->name) {
            free(h3->name);
        }
        free(h3);
    }

    HASH_ITER(hh, conf->leas, h2, tmp2) {
        HASH_DEL(conf->leas, h2);
        free_liagency(h2->ag);
        free(h2);
    }

    HASH_ITER(hh, conf->udp_sink_intercept_mappings, h4, tmp4) {
        HASH_DEL(conf->udp_sink_intercept_mappings, h4);
        if (h4->udpsink) {
            free(h4->udpsink);
        }
        if (h4->liid) {
            free(h4->liid);
        }
        free(h4);
    }

    free_all_ipintercepts(&(conf->ipintercepts));
    free_all_voipintercepts(&(conf->voipintercepts));
    free_all_emailintercepts(&(conf->emailintercepts));
    free_coreserver_list(conf->radiusservers);
    free_coreserver_list(conf->gtpservers);
    free_coreserver_list(conf->smtpservers);
    free_coreserver_list(conf->imapservers);
    free_coreserver_list(conf->pop3servers);
    free_coreserver_list(conf->sipservers);

    pthread_mutex_destroy(&(conf->safelock));
}

void clear_prov_state(provision_state_t *state) {

    clear_intercept_state(&(state->interceptconf));

    free_all_pending(state->epoll_fd, &(state->pendingclients));
    stop_all_collectors(state->epoll_fd, &(state->collectors));
    free_all_mediators(state->epoll_fd, &(state->mediators),
            &(state->knownmeds));

    close(state->epoll_fd);
    close_restauth_db(state);
    close_clientdb(state);

    if (state->clientfd) {
        close(state->clientfd->fd);
        free(state->clientfd);
    }
    if (state->mediatorfd) {
        close(state->mediatorfd->fd);
        free(state->mediatorfd);
    }
    if (state->timerfd) {
        if (state->timerfd->fd != -1) {
            close(state->timerfd->fd);
        }
        free(state->timerfd);
    }
    if (state->signalfd) {
        close(state->signalfd->fd);
        free(state->signalfd);
    }

    if (state->pushport) {
        free(state->pushport);
    }
    if (state->pushaddr) {
        free(state->pushaddr);
    }
    if (state->listenport) {
        free(state->listenport);
    }
    if (state->listenaddr) {
        free(state->listenaddr);
    }
    if (state->mediateaddr) {
        free(state->mediateaddr);
    }
    if (state->mediateport) {
        free(state->mediateport);
    }
    if (state->interceptconffile) {
        free(state->interceptconffile);
    }
    if (state->key_pem) {
        free(state->key_pem);
    }
    if (state->cert_pem) {
        free(state->cert_pem);
    }
    if (state->restauthdbfile) {
        free(state->restauthdbfile);
    }
    if (state->restauthkey) {
        free(state->restauthkey);
    }
    if (state->clientdbfile) {
        free(state->clientdbfile);
    }
    if (state->clientdbkey) {
        free(state->clientdbkey);
    }
    if (state->sign_ctx) {
        EVP_PKEY_CTX_free(state->sign_ctx);
    }
    if (state->integrity_sign_private_key) {
        EVP_PKEY_free(state->integrity_sign_private_key);
    }
    if (state->integrity_sign_private_key_location) {
        free(state->integrity_sign_private_key_location);
    }
    free_ssl_config(&(state->sslconf));
}

static int push_coreservers(coreserver_t *servers, uint8_t cstype,
        net_buffer_t *nb) {
    coreserver_t *cs, *tmp;

    HASH_ITER(hh, servers, cs, tmp) {
        if (push_coreserver_onto_net_buffer(nb, cs, cstype) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing %s server %s onto buffer for writing to collector.",
                    coreserver_type_to_string(cstype), cs->ipstr);
            return -1;
        }
    }
    return 0;
}

static int push_default_email_compression(uint8_t defaultcompress,
        net_buffer_t *nb) {

    if (push_default_email_compression_onto_net_buffer(nb,
            defaultcompress) < 0) {
        return -1;
    }
    return 0;
}

static int push_all_default_radius(default_radius_user_t *users,
        net_buffer_t *nb) {
    default_radius_user_t *defuser, *tmp;

    HASH_ITER(hh, users, defuser, tmp) {
        if (defuser->name == NULL) {
            continue;
        }
        if (push_default_radius_onto_net_buffer(nb, defuser) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing default RADIUS user %s onto buffer for writing to collector.",
                    defuser->name);
            return -1;
        }
    }
    return 0;
}

static int push_all_mediators(prov_mediator_t *mediators, net_buffer_t *nb) {

    prov_mediator_t *pmed, *medtmp;

    HASH_ITER(hh, mediators, pmed, medtmp) {
        if (pmed->details == NULL) {
            continue;
        }
        if (push_mediator_onto_net_buffer(nb, pmed->details) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing mediator %s:%s onto buffer for writing to collector.",
                    pmed->details->ipstr, pmed->details->portstr);
            return -1;
        }
    }
    return 0;
}

static int push_all_email_targets(net_buffer_t *nb, email_target_t *targets,
        emailintercept_t *mailint) {

    email_target_t *tgt, *tmp;

    HASH_ITER(hh, targets, tgt, tmp) {
        if (push_email_target_onto_net_buffer(nb, tgt, mailint) < 0) {
            return -1;
        }
    }
    return 0;
}

static int push_all_sip_targets(net_buffer_t *nb, libtrace_list_t *targets,
        voipintercept_t *vint) {


    libtrace_list_node_t *n;
    openli_sip_identity_t *sipid;

    n = targets->head;
    while (n) {
        sipid = *((openli_sip_identity_t **)(n->data));
        n = n->next;

        if (push_sip_target_onto_net_buffer(nb, sipid, vint) < 0) {
            return -1;
        }
    }
    return 0;
}

static int push_all_voipintercepts(provision_state_t *state,
        voipintercept_t *voipintercepts, net_buffer_t *nb,
        prov_agency_t *agencies) {

    voipintercept_t *v;
    prov_agency_t *lea;
    int skip = 0;

    for (v = voipintercepts; v != NULL; v = v->hh_liid.next) {
        if (v->active == 0) {
            continue;
        }
        skip = 0;
        if (strcmp(v->common.targetagency, "pcapdisk") != 0) {
            HASH_FIND_STR(agencies, v->common.targetagency, lea);
            if (lea == NULL) {
                skip = 1;
            }
        }

        if (skip) {
            continue;
        }

        v->options = 0;
        if (state->ignorertpcomfort == 1) {
            v->options |= (1UL << OPENLI_VOIPINT_OPTION_IGNORE_COMFORT);
        }

        if (push_voipintercept_onto_net_buffer(nb, v) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing VOIP intercept %s onto buffer for writing to collector.",
                    v->common.liid);
            return -1;
        }

        if (push_all_sip_targets(nb, v->targets, v) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing SIP targets for VOIP intercept %s onto buffer.", v->common.liid);
            return -1;
        }
    }
    return 0;
}

static int push_all_emailintercepts(emailintercept_t *mailintercepts,
        net_buffer_t *nb, prov_agency_t *agencies) {

    emailintercept_t *m;
    prov_agency_t *lea;
    int skip = 0;

    for (m = mailintercepts; m != NULL; m = m->hh_liid.next) {
        skip = 0;
        if (strcmp(m->common.targetagency, "pcapdisk") != 0) {
            HASH_FIND_STR(agencies, m->common.targetagency, lea);
            if (lea == NULL) {
                skip = 1;
            }
        }

        if (skip) {
            continue;
        }

        if (push_emailintercept_onto_net_buffer(nb, m) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing Email intercept %s onto buffer for writing to collector.",
                    m->common.liid);
            return -1;
        }

        if (push_all_email_targets(nb, m->targets, m) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing targets for Email intercept %s onto buffer.", m->common.liid);
            return -1;
        }
    }
    return 0;
}

static int push_all_ipintercepts(ipintercept_t *ipintercepts,
        net_buffer_t *nb, prov_agency_t *agencies) {

    ipintercept_t *cept;
    prov_agency_t *lea;
    int skip = 0;

    for (cept = ipintercepts; cept != NULL; cept = cept->hh_liid.next) {
        skip = 0;
        if (strcmp(cept->common.targetagency, "pcapdisk") != 0) {
            HASH_FIND_STR(agencies, cept->common.targetagency, lea);
            if (lea == NULL) {
                skip = 1;
            }
        }

        if (skip) {
            continue;
        }

        if (push_ipintercept_onto_net_buffer(nb, cept) < 0) {
            logger(LOG_INFO,
                    "OpenLI provisioner: error pushing IP intercept %s onto buffer for writing to collector.",
                    cept->common.liid);
            return -1;
        }
    }

    return 0;
}

static int respond_collector_auth(provision_state_t *state,
        prov_epoll_ev_t *pev, net_buffer_t *outgoing) {

    /* Collector just authed successfully, so we can safely shovel all
     * of known mediators and active intercepts to it.
     */

    pthread_mutex_lock(&(state->interceptconf.safelock));

    if (HASH_CNT(hh, state->mediators) +
            HASH_CNT(hh, state->interceptconf.radiusservers) +
            HASH_CNT(hh, state->interceptconf.gtpservers) +
            HASH_CNT(hh, state->interceptconf.sipservers) +
            HASH_CNT(hh, state->interceptconf.imapservers) +
            HASH_CNT(hh, state->interceptconf.pop3servers) +
            HASH_CNT(hh, state->interceptconf.smtpservers) +
            HASH_CNT(hh_liid, state->interceptconf.ipintercepts) +
            HASH_CNT(hh_liid, state->interceptconf.emailintercepts) +
            HASH_CNT(hh_liid, state->interceptconf.voipintercepts) == 0) {
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return 0;
    }

    /* No need to wrap our log messages with checks for log_allowed, as
     * we should have just set log_allowed to 1 before calling this function
     */
    if (push_all_mediators(state->mediators, outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue mediators to be sent to new collector on fd %d",
                pev->fd);
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    if (push_all_default_radius(state->interceptconf.defradusers,
            outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue default RADIUS usernames to be sent to new collector on fd %d",
                pev->fd);
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    if (push_default_email_compression(
            state->interceptconf.default_email_deliver_compress,
            outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue default email compression handling to be sent to new collector on fd %d", pev->fd);
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    if (push_coreservers(state->interceptconf.radiusservers,
            OPENLI_CORE_SERVER_RADIUS, outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue RADIUS server details to be sent to new collector on fd %d", pev->fd);
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    if (push_coreservers(state->interceptconf.gtpservers,
            OPENLI_CORE_SERVER_GTP, outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue GTP server details to be sent to new collector on fd %d", pev->fd);
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    if (push_coreservers(state->interceptconf.sipservers,
            OPENLI_CORE_SERVER_SIP, outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue SIP server details to be sent to new collector on fd %d", pev->fd);
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    if (push_coreservers(state->interceptconf.smtpservers,
            OPENLI_CORE_SERVER_SMTP, outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue SMTP server details to be sent to new collector on fd %d", pev->fd);
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    if (push_coreservers(state->interceptconf.imapservers,
            OPENLI_CORE_SERVER_IMAP, outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue IMAP server details to be sent to new collector on fd %d", pev->fd);
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    if (push_coreservers(state->interceptconf.pop3servers,
            OPENLI_CORE_SERVER_POP3, outgoing) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue POP3 server details to be sent to new collector on fd %d", pev->fd);
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    if (push_all_ipintercepts(state->interceptconf.ipintercepts, outgoing,
                state->interceptconf.leas) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue IP intercepts to be sent to new collector on fd %d",
                pev->fd);
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    if (push_all_voipintercepts(state,
            state->interceptconf.voipintercepts, outgoing,
            state->interceptconf.leas) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue VOIP intercepts to be sent to new collector on fd %d",
                pev->fd);
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    if (push_all_emailintercepts(
            state->interceptconf.emailintercepts, outgoing,
            state->interceptconf.leas) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to queue Email intercepts to be sent to new collector on fd %d",
                pev->fd);
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    if (push_nomore_intercepts(outgoing) < 0) {
        logger(LOG_INFO,
                "OpenLI provisioner: error pushing end of intercepts onto buffer for writing to collector.");
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    if (enable_epoll_write(state, pev) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to enable epoll write event for newly authed collector on fd %d: %s",
                pev->fd, strerror(errno));
        pthread_mutex_unlock(&(state->interceptconf.safelock));
        return -1;
    }

    pthread_mutex_unlock(&(state->interceptconf.safelock));
    return 0;

}

static int respond_mediator_auth(provision_state_t *state,
        prov_epoll_ev_t *pev, net_buffer_t *outgoing) {

    liid_hash_t *h;
    prov_agency_t *ag, *tmp;

    pthread_mutex_lock(&(state->interceptconf.safelock));
    /* Mediator just authed successfully, so we can safely send it details
     * on any LEAs that we know about */
    /* No need to wrap our log messages with checks for log_allowed, as
     * we should have just set log_allowed to 1 before calling this function
     */
    HASH_ITER(hh, state->interceptconf.leas, ag, tmp) {
        if (push_lea_onto_net_buffer(outgoing, ag->ag) == -1) {
            logger(LOG_INFO,
                    "OpenLI: error while buffering LEA details to send from provisioner to mediator.");
            pthread_mutex_unlock(&(state->interceptconf.safelock));
            return -1;
        }
    }

    /* We also need to send any LIID -> LEA mappings that we know about */
    h = state->interceptconf.liid_map;
    while (h != NULL) {
        if (push_liid_mapping_onto_net_buffer(outgoing, h->agency, h->liid,
                h->encryptkey, h->encryptkey_len, h->encryptmethod,
                h->liid_format) == -1) {
            logger(LOG_INFO,
                    "OpenLI: error while buffering LIID mappings to send to mediator.");
            pthread_mutex_unlock(&(state->interceptconf.safelock));
            return -1;
        }
        h = h->hh.next;
    }
    pthread_mutex_unlock(&(state->interceptconf.safelock));

    /* Update our epoll event for this mediator to allow transmit. */
    if (enable_epoll_write(state, pev) == -1) {
        logger(LOG_INFO,
                "OpenLI: unable to enable epoll write event for newly authed mediator on fd %d: %s",
                pev->fd, strerror(errno));
        return -1;
    }

    return 0;
}

static int process_udp_sink_announcement(provision_state_t *state,
        prov_collector_t *col, uint8_t *msgbody, uint16_t msglen) {

    char *listenport = NULL;
    char *listenaddr = NULL;
    char *identifier = NULL;
    uint64_t ts = 0;

    if (decode_udp_sink(msgbody, msglen, &listenaddr, &listenport,
            &identifier, &ts) < 0) {
        logger(LOG_INFO, "OpenLI provisioner: error decoding UDP sink announcement from collector %s -- ignoring", col->identifier);
        return -1;
    }

    if (listenport != NULL && listenaddr != NULL && ts != 0 &&
            identifier != NULL) {

        if (update_udp_sink_row(state, col, listenaddr, listenport, identifier,
                ts) < 0) {
            logger(LOG_INFO, "OpenLI provisioner: error while updating UDP sink information for collector %s in client DB -- ignoring", col->identifier);
            return -1;
        }
    }

    if (listenport) {
        free(listenport);
    }
    if (listenaddr) {
        free(listenaddr);
    }
    if (identifier) {
        free(identifier);
    }

    return 0;
}

static int process_x2x3_listener_announcement(provision_state_t *state,
        prov_collector_t *col, uint8_t *msgbody, uint16_t msglen) {

    char *listenport = NULL;
    char *listenaddr = NULL;
    uint64_t ts = 0;

    if (decode_x2x3_listener(msgbody, msglen, &listenaddr, &listenport,
            &ts) < 0) {
        logger(LOG_INFO, "OpenLI provisioner: error decoding X2/X3 announcement from collector %s -- ignoring", col->identifier);
        return -1;
    }

    if (listenport != NULL && listenaddr != NULL && ts != 0) {
        if (update_x2x3_listener_row(state, col, listenaddr, listenport, ts) < 0) {
            logger(LOG_INFO, "OpenLI provisioner: error while updating X2/X3 information for collector %s in client DB -- ignoring", col->identifier);
            return -1;
        }
    }

    if (listenport) {
        free(listenport);
    }
    if (listenaddr) {
        free(listenaddr);
    }

    return 0;
}

static int receive_collector(provision_state_t *state, prov_epoll_ev_t *pev) {

    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->client->state);
    uint8_t *msgbody;
    uint16_t msglen;
    uint64_t internalid;
    openli_proto_msgtype_t msgtype;
    uint8_t justauthed = 0;

    do {
        msgtype = receive_net_buffer(cs->incoming, &msgbody, &msglen,
                &internalid);
        if (msgtype < 0) {
            if (cs->log_allowed) {
                nb_log_receive_error(msgtype);
                logger(LOG_INFO,
                        "OpenLI Provisioner: error receiving message from collector.");
            }
            return -1;
        }

        switch(msgtype) {
            case OPENLI_PROTO_DISCONNECT:
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_X2X3_LISTENER:
                process_x2x3_listener_announcement(state,
                        (prov_collector_t *)(cs->parent), msgbody, msglen);
                break;
            case OPENLI_PROTO_ADD_UDPSINK:
                process_udp_sink_announcement(state,
                        (prov_collector_t *)(cs->parent), msgbody, msglen);
                break;
            case OPENLI_PROTO_COLLECTOR_AUTH:
                if (internalid != OPENLI_COLLECTOR_MAGIC) {
                    if (cs->log_allowed) {
                        logger(LOG_INFO,
                                "OpenLI: invalid auth code from collector.");
                    }
                    return -1;
                }
                if (!cs->trusted) {
                    HASH_DELETE(hh, state->pendingclients, pev->client);
                }
                cs->trusted = 1;
                justauthed = 1;
                add_collector_to_hashmap(state, pev->client, cs, msgbody,
                        msglen);
                break;
            default:
                if (cs->log_allowed) {
                    logger(LOG_INFO,
                            "OpenLI: unexpected message type %d received from collector.",
                            msgtype);
                }
                return -1;
        }
    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    if (justauthed) {
        if (cs->log_allowed == 0) {
            cs->log_allowed = 1;
        }
        logger(LOG_DEBUG, "OpenLI: collector %s on fd %d auth success.",
                cs->ipaddr, pev->fd);
        halt_provisioner_client_authtimer(state->epoll_fd, pev->client,
                cs->ipaddr);
        update_collector_client_row(state, (prov_collector_t *)(cs->parent));
        return respond_collector_auth(state, pev, cs->outgoing);
   }

   return 0;
}

static int receive_mediator(provision_state_t *state, prov_epoll_ev_t *pev) {
    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->client->state);
    uint8_t *msgbody;
    uint16_t msglen;
    uint64_t internalid;
    openli_proto_msgtype_t msgtype;
    uint8_t justauthed = 0;

    if (pev->client->lastsslerror == 1) {
        return 0;
    }

    do {
        msgtype = receive_net_buffer(cs->incoming, &msgbody, &msglen,
                &internalid);
        if (msgtype < 0) {
            if (cs->log_allowed) {
                nb_log_receive_error(msgtype);
                logger(LOG_INFO, "OpenLI provisioner: error receiving message from mediator.");
            }
            return -1;
        }

        switch(msgtype) {
            case OPENLI_PROTO_DISCONNECT:
                return -1;
            case OPENLI_PROTO_NO_MESSAGE:
                break;
            case OPENLI_PROTO_MEDIATOR_AUTH:
                if (internalid != OPENLI_MEDIATOR_MAGIC) {
                    if (cs->log_allowed) {
                        logger(LOG_INFO,
                                "OpenLI: invalid auth code from mediator.");
                    }
                    return -1;
                }
                if (cs->trusted == 1) {
                    if (cs->log_allowed) {
                        logger(LOG_INFO,
                                "OpenLI: warning -- double auth from mediator.");
                    }
                    return -1;
                }
                cs->trusted = 1;
                justauthed = 1;
                break;
            case OPENLI_PROTO_ANNOUNCE_MEDIATOR:
                if (cs->trusted == 0) {
                    if (cs->log_allowed) {
                        logger(LOG_INFO,
                                "Received mediator announcement from unauthed mediator.");
                    }
                    return -1;
                }

                if (update_mediator_details(state, msgbody, msglen,
                        cs, cs->ipaddr) == -1) {
                    return -1;
                }
                break;
            case OPENLI_PROTO_INTEGRITY_SIGNATURE_REQUEST:
                if (prov_handle_ics_signing_request(state, msgbody, msglen,
                        cs, pev) == -1) {
                    return -1;
                }
                break;
            default:
                if (cs->log_allowed) {
                    logger(LOG_INFO,
                            "OpenLI: unexpected message type %d received from mediator.",
                            msgtype);
                }
                return -1;
        }
    } while (msgtype != OPENLI_PROTO_NO_MESSAGE);

    if (justauthed) {
        if (cs->log_allowed == 0) {
            cs->log_allowed = 1;
        }
        logger(LOG_INFO, "OpenLI: mediator %s on fd %d auth success.",
                cs->ipaddr, pev->fd);
        halt_provisioner_client_authtimer(state->epoll_fd, pev->client,
                cs->ipaddr);
        update_mediator_client_row(state, (prov_mediator_t *)(cs->parent));
        return respond_mediator_auth(state, pev, cs->outgoing);
    }

    return 0;
}

static int transmit_socket(provision_state_t *state, prov_epoll_ev_t *pev) {

    int ret;
    struct epoll_event ev;
    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->client->state);
    openli_proto_msgtype_t err = OPENLI_PROTO_NO_MESSAGE;

    ret = transmit_net_buffer(cs->outgoing, &err);
    if (ret == -1) {
        if (cs->log_allowed) {
            nb_log_transmit_error(err);
            logger(LOG_INFO,
                    "OpenLI: error sending message from provisioner to %s.",
                    get_event_description(pev));
        }
        return -1;
    }

    if (ret == 0) {
        /* No more outstanding data, remove EPOLLOUT event */
        ev.data.ptr = pev;
        ev.events = EPOLLIN | EPOLLRDHUP;

        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, pev->fd, &ev) == -1) {
            if (cs->log_allowed) {
                logger(LOG_INFO,
                        "OpenLI: error disabling EPOLLOUT for %s fd %d: %s.",
                        get_event_description(pev), pev->fd, strerror(errno));
            }
            return -1;
        }
    }

    return 1;
}

static inline int accept_client(int sock, char *identspace,
        int spacelen, char *justipspace) {

    int newfd;
    struct sockaddr_storage saddr;
    socklen_t socklen = sizeof(saddr);
    char portbuf[10];

    newfd = accept(sock, (struct sockaddr *)&saddr, &socklen);
    if (newfd < 0) {
        return newfd;
    }
    fd_set_nonblock(newfd);

    if (getnameinfo((struct sockaddr *)&saddr, socklen, justipspace,
                INET6_ADDRSTRLEN,
            portbuf, sizeof(portbuf), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        logger(LOG_INFO, "OpenLI: getnameinfo error in provisioner: %s.",
                strerror(errno));
        close(newfd);
        return -1;
    }

    snprintf(identspace, spacelen, "%s-%s", justipspace, portbuf);
    return newfd;
}


static int accept_collector(provision_state_t *state) {

    char identbuf[INET6_ADDRSTRLEN + 11];
    char ipbuf[INET6_ADDRSTRLEN + 1];
    prov_client_t *colclient;
    int newfd = -1;

    /* TODO check for EPOLLHUP or EPOLLERR */

    /* Accept, then add to list of collectors. Push all active intercepts
     * out to the collector. */

    if ((newfd = accept_client(state->clientfd->fd, identbuf,
            INET6_ADDRSTRLEN + 11, ipbuf)) < 0) {
        return -1;
    }

    /* See if this collector already exists */
    HASH_FIND(hh, state->pendingclients, identbuf, strlen(identbuf), colclient);

    if (!colclient) {
        colclient = calloc(1, sizeof(prov_client_t));
        colclient->identifier = strdup(identbuf);
        colclient->ipaddress = strdup(ipbuf);
        colclient->clientrole = PROV_EPOLL_COLLECTOR;
        init_provisioner_client(colclient);

        HASH_ADD_KEYPTR(hh, state->pendingclients, colclient->identifier,
                strlen(colclient->identifier), colclient);
    }

    halt_provisioner_client_idletimer(state->epoll_fd, colclient,
            colclient->identifier);

    return accept_provisioner_client(&(state->sslconf), state->epoll_fd,
            colclient->identifier, colclient, newfd, PROV_EPOLL_COLLECTOR,
            PROV_EPOLL_COLLECTOR_HANDSHAKE);

}

static int accept_mediator(provision_state_t *state) {

    char identbuf[10 + INET6_ADDRSTRLEN + 1];
    char ipbuf[INET6_ADDRSTRLEN + 1];
    prov_client_t *medclient;
    int newfd = -1;

    /* TODO check for EPOLLHUP or EPOLLERR */

    /* Accept, then add to list of mediators. Push all known LEAs to the
     * mediator, as well as any intercept->LEA mappings that we have.
     */
    /* See if this mediator already exists */
    if ((newfd = accept_client(state->mediatorfd->fd, identbuf,
            INET6_ADDRSTRLEN + 11, ipbuf)) < 0) {
        return -1;
    }

    HASH_FIND(hh, state->pendingclients, identbuf, strlen(identbuf), medclient);

    if (!medclient) {
        medclient = calloc(1, sizeof(prov_client_t));
        init_provisioner_client(medclient);
        medclient->identifier = strdup(identbuf);
        medclient->ipaddress = strdup(ipbuf);
        medclient->clientrole = PROV_EPOLL_MEDIATOR;
        HASH_ADD_KEYPTR(hh, state->pendingclients, medclient->identifier,
                strlen(medclient->identifier), medclient);
    }

    halt_provisioner_client_idletimer(state->epoll_fd, medclient,
            medclient->identifier);

    return accept_provisioner_client(&(state->sslconf), state->epoll_fd,
            medclient->identifier, medclient, newfd, PROV_EPOLL_MEDIATOR,
            PROV_EPOLL_MEDIATOR_HANDSHAKE);

}

int start_main_listener(provision_state_t *state) {

    struct epoll_event ev;
    int sockfd;

    state->clientfd = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

    sockfd  = create_listener(state->listenaddr, state->listenport,
            "provisioner");
    if (sockfd == -1) {
        return -1;
    }

    state->clientfd->fd = sockfd;
    state->clientfd->fdtype = PROV_EPOLL_COLL_CONN;
    state->clientfd->client = NULL;

    ev.data.ptr = state->clientfd;
    ev.events = EPOLLIN;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        logger(LOG_INFO,
                "OpenLI: Failed to register main listening socket: %s.",
                strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

int start_mediator_listener(provision_state_t *state) {
    struct epoll_event ev;
    int sockfd;

    state->mediatorfd = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

    if (state->mediateaddr == NULL) {
        state->mediateaddr = strdup("0.0.0.0");
        logger(LOG_INFO, "OpenLI provisioner: warning, no mediator listen address configured, listening on ALL addresses.");
        logger(LOG_INFO, "OpenLI provisioner: set 'mediationaddr' config option to resolve this.");
    }

    sockfd  = create_listener(state->mediateaddr, state->mediateport,
            "incoming mediator");
    if (sockfd == -1) {
        return -1;
    }

    state->mediatorfd->fd = sockfd;
    state->mediatorfd->fdtype = PROV_EPOLL_MEDIATE_CONN;
    state->mediatorfd->client = NULL;

    ev.data.ptr = state->mediatorfd;
    ev.events = EPOLLIN;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) == -1) {
        logger(LOG_INFO,
                "OpenLI: Failed to register push listening socket: %s.",
                strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

static int process_signal(int sigfd) {

    struct signalfd_siginfo si;
    int ret;

    ret = read(sigfd, &si, sizeof(si));
    if (ret < 0) {
        logger(LOG_INFO,
                "OpenLI provisioner: unable to read from signal fd: %s.",
                strerror(errno));
        return ret;
    }

    if (ret != sizeof(si)) {
        logger(LOG_INFO,
                "OpenLI provisioner: unexpected partial read from signal fd.");
        return -1;
    }

    if (si.ssi_signo == SIGTERM || si.ssi_signo == SIGINT) {
        halt_signal(si.ssi_signo);
    }
    if (si.ssi_signo == SIGHUP) {
        reload_signal(si.ssi_signo);
    }

    return 0;
}

static int send_intercept_hi1(provision_state_t *state, prov_epoll_ev_t *pev,
        hi1_notify_t hi1type) {
    ipintercept_t *ipint = NULL;
    emailintercept_t *mailint = NULL;
    voipintercept_t *vint = NULL;
    intercept_common_t *common;
    struct epoll_event ev;

    char *target_info = NULL;

    if (pev == NULL) {
        return -1;
    }

    epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, pev->fd, &ev);
    close(pev->fd);
    pev->fd = -1;
    if (pev->cept == NULL) {
        return 0;
    }

    if (pev->cept->intercept_type == OPENLI_INTERCEPT_TYPE_EMAIL) {
        mailint = (emailintercept_t *)(pev->cept->intercept_ref);
        target_info = list_email_targets(mailint, 256);
        common = &(mailint->common);
    } else if (pev->cept->intercept_type == OPENLI_INTERCEPT_TYPE_VOIP) {
        vint = (voipintercept_t *)(pev->cept->intercept_ref);
        target_info = list_sip_targets(vint, 256);
        common = &(vint->common);
    } else if (pev->cept->intercept_type == OPENLI_INTERCEPT_TYPE_IP) {
        ipint = (ipintercept_t *)(pev->cept->intercept_ref);
        if (ipint->username) {
            target_info = strdup(ipint->username);
        }
        common = &(ipint->common);
    } else {
        return -1;
    }

    if (announce_hi1_notification_to_mediators(state, common, target_info,
            hi1type) < 0) {
        logger(LOG_INFO, "OpenLI provisioner: unable to send HI1 notification for intercept %s (which has just %s).",
                common->liid,
                hi1type == HI1_LI_ACTIVATED ? "started" : "ended");
        free(target_info);
        return -1;
    }

    free(target_info);
    return 1;
}

static void remove_idle_client(provision_state_t *state, prov_epoll_ev_t *pev) {

    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->client->state);

    if (cs->parent == NULL) {
        prov_client_t *client;

        HASH_FIND(hh, state->pendingclients, cs->ipaddr, strlen(cs->ipaddr),
                client);
        if (client) {
            logger(LOG_DEBUG, "OpenLI: removed pending client %s from internal list", cs->ipaddr);
            HASH_DELETE(hh, state->pendingclients, client);
        }
        destroy_provisioner_client(state->epoll_fd, pev->client, cs->ipaddr);

    } else if (cs->clientrole == PROV_EPOLL_COLLECTOR) {
        prov_collector_t *col;

        col = (prov_collector_t *)(cs->parent);
        if (col) {
            logger(LOG_DEBUG, "OpenLI: removed collector %s from internal list",
                    col->identifier);
            HASH_DELETE(hh, state->collectors, col);
            free(col->identifier);
            if (col->jsonconfig) {
                free(col->jsonconfig);
            }
            free(col);
        }
        destroy_provisioner_client(state->epoll_fd, pev->client, cs->ipaddr);
    } else if (cs->clientrole == PROV_EPOLL_MEDIATOR) {
        prov_mediator_t *med;

        med = (prov_mediator_t *)(cs->parent);
        if (med) {
            logger(LOG_DEBUG, "OpenLI: removed mediator %u from internal list",
                    med->mediatorid);
            HASH_DELETE(hh, state->mediators, med);
            free_openli_mediator(med->details);
            free(med);
        }
        destroy_provisioner_client(state->epoll_fd, pev->client, cs->ipaddr);
    }
}

static void expire_unauthed(provision_state_t *state, prov_epoll_ev_t *pev) {

    prov_sock_state_t *cs = (prov_sock_state_t *)(pev->client->state);

    if (cs->clientrole == PROV_EPOLL_COLLECTOR) {
        if (cs->log_allowed) {
            logger(LOG_INFO,
                    "OpenLI Provisioner: dropping unauthed collector.");
        }
    }

    if (cs->clientrole == PROV_EPOLL_MEDIATOR) {
        if (cs->log_allowed) {
            logger(LOG_INFO,
                    "OpenLI Provisioner: dropping unauthed mediator.");
        }
    }

    if (cs->parent == NULL) {
        prov_client_t *client;

        HASH_FIND(hh, state->pendingclients, cs->ipaddr, strlen(cs->ipaddr),
                client);
        if (client) {
            logger(LOG_DEBUG, "OpenLI: removed pending client %s from internal list", cs->ipaddr);
            HASH_DELETE(hh, state->pendingclients, client);
        }
    }
    destroy_provisioner_client(state->epoll_fd, pev->client, cs->ipaddr);

}

static int check_epoll_fd(provision_state_t *state, struct epoll_event *ev) {

    int ret = 0;
    prov_epoll_ev_t *pev = (prov_epoll_ev_t *)(ev->data.ptr);
    prov_sock_state_t *cs = NULL;

    if (pev->client) {
        cs = (prov_sock_state_t *)(pev->client->state);
    }

    switch(pev->fdtype) {
        case PROV_EPOLL_COLL_CONN:
            ret = accept_collector(state);
            break;
        case PROV_EPOLL_MEDIATE_CONN:
            ret = accept_mediator(state);
            break;
        case PROV_EPOLL_INTERCEPT_START:
            ret = send_intercept_hi1(state, pev, HI1_LI_ACTIVATED);
            break;
        case PROV_EPOLL_INTERCEPT_HALT:
            ret = send_intercept_hi1(state, pev, HI1_LI_DEACTIVATED);
            break;
        case PROV_EPOLL_MAIN_TIMER:
            if (ev->events & EPOLLIN) {
                return 1;
            }
            logger(LOG_INFO,
                    "OpenLI Provisioner: main epoll timer has failed.");
            return -1;
        case PROV_EPOLL_SIGNAL:
            ret = process_signal(pev->fd);
            break;
        case PROV_EPOLL_COLLECTOR:
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLIN) {
                ret = receive_collector(state, pev);
            }
            else if (ev->events & EPOLLOUT) {
                ret = transmit_socket(state, pev);
            } else {
                ret = -1;
            }

            if (ret == -1) {
                if (cs->log_allowed) {
                    logger(LOG_DEBUG,
                        "OpenLI Provisioner: disconnecting collector %s.",
                        cs->ipaddr);
                }
                cs->log_allowed = 0;
                disconnect_provisioner_client(state->epoll_fd, pev->client,
                        cs->ipaddr);
            }
            break;
        case PROV_EPOLL_FD_TIMER:
            if (ev->events & EPOLLIN) {
                expire_unauthed(state, pev);
            } else {
                if (cs->log_allowed) {
                    logger(LOG_INFO,
                        "OpenLI Provisioner: client auth timer has failed.");
                }
                return -1;
            }
            break;

        case PROV_EPOLL_FD_IDLETIMER:
            if (ev->events & EPOLLIN) {
                remove_idle_client(state, pev);
            } else {
                if (cs->log_allowed) {
                    logger(LOG_INFO,
                        "OpenLI Provisioner: client idle timer has failed.");
                }
                return -1;
            }
            break;

        case PROV_EPOLL_COLLECTOR_HANDSHAKE:
        case PROV_EPOLL_MEDIATOR_HANDSHAKE:
            //continue handshake process
            ret = continue_provisioner_client_handshake(state->epoll_fd,
                    pev->client, cs);
            if (ret == -1) {
                /* don't disconnect, instead enable writing on our socket
                 * so we can send the "SSL required" message
                 */
                if (enable_epoll_write(state, pev) == -1) {
                    logger(LOG_INFO,
                            "OpenLI: unable to enable epoll write event for SSL-requiring mediator on fd %d: %s",
                            pev->fd, strerror(errno));
                    disconnect_provisioner_client(state->epoll_fd, pev->client,
                            cs->ipaddr);
                }
            }
            break;

        case PROV_EPOLL_MEDIATOR:
            if (ev->events & EPOLLRDHUP) {
                ret = -1;
            } else if (ev->events & EPOLLOUT) {
                ret = transmit_socket(state, pev);
            } else if (ev->events & EPOLLIN) {
                ret = receive_mediator(state, pev);
            } else {
                ret = -1;
            }
            if (ret == -1) {
                if (cs->log_allowed) {
                    logger(LOG_DEBUG,
                        "OpenLI Provisioner: disconnecting mediator %s.",
                        cs->ipaddr);
                }
                cs->log_allowed = 0;
                disconnect_provisioner_client(state->epoll_fd, pev->client,
                        cs->ipaddr);
            }
            break;
        case PROV_EPOLL_UPDATE:
            /* TODO */
            break;
        case PROV_EPOLL_CLIENTDB_TIMER:
            update_all_client_rows(state);
            close(pev->fd);
            pev->fd = -1;

            pev->fd = epoll_add_timer(state->epoll_fd, 300, pev);
            break;
        default:
            logger(LOG_INFO,
                    "OpenLI Provisioner: invalid fd triggering epoll event,");
            return -1;
    }

    return ret;

}

static void run(provision_state_t *state) {

    int i, nfds;
    int timerfd;
    int timerexpired = 0;
    struct epoll_event evs[64];
    struct epoll_event ev;

    prov_epoll_ev_t clientdb_timer;

    ev.data.ptr = state->signalfd;
    ev.events = EPOLLIN;

    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, state->signalfd->fd, &ev)
                == -1) {
        logger(LOG_INFO,
                "OpenLI: Failed to register signal socket: %s.",
                strerror(errno));
        return;
    }

    state->timerfd = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

    timerfd = epoll_add_timer(state->epoll_fd, 300, &clientdb_timer);
    clientdb_timer.fd = timerfd;
    clientdb_timer.fdtype = PROV_EPOLL_CLIENTDB_TIMER;
    clientdb_timer.client = NULL;

    while (!provisioner_halt) {
        if (reload_config) {
            if (reload_provisioner_config(state) == -1) {
                break;
            }
            reload_config = 0;
        }

        timerfd = epoll_add_timer(state->epoll_fd, 1, state->timerfd);
        if (timerfd == -1) {
            logger(LOG_INFO,
                "OpenLI: Failed to add timer to epoll in provisioner.");
            break;
        }
        state->timerfd->fd = timerfd;
        state->timerfd->fdtype = PROV_EPOLL_MAIN_TIMER;
        state->timerfd->client = NULL;
        timerexpired = 0;

        while (!timerexpired) {
            nfds = epoll_wait(state->epoll_fd, evs, 64, -1);
            if (nfds < 0) {
                logger(LOG_INFO, "OpenLI: error while checking for incoming connections on the provisioner: %s.",
                        strerror(errno));
                return;
            }

            for (i = 0; i < nfds; i++) {
                timerexpired = check_epoll_fd(state, &(evs[i]));
                if (timerexpired == -1) {
                    break;
                }
            }
        }

        if (epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, timerfd, &ev) == -1) {
            logger(LOG_INFO,
                "OpenLI: unable to remove provisioner timer from epoll set: %s",
                strerror(errno));
            return;
        }

        close(state->timerfd->fd);
        state->timerfd->fd = -1;
    }

    if (state->updatedaemon) {
        MHD_stop_daemon(state->updatedaemon);
    }

    if (clientdb_timer.fd != -1) {
        close(clientdb_timer.fd);
    }
}

static void usage(char *prog) {
    fprintf(stderr, "Usage: %s [ -d ] -c configfile [ -K keyfile ]\n", prog);
    fprintf(stderr, "\nSet the -d flag to run this program as a daemon.\n");
}

int main(int argc, char *argv[]) {
    char *configfile = NULL;
    const char *encpassfile = NULL;
    sigset_t sigblock;
    int daemonmode = 0;
    char *pidfile = NULL;
    int ret;

    provision_state_t provstate;

    while (1) {
        int optind;
        struct option long_options[] = {
            { "help", 0, 0, 'h' },
            { "config", 1, 0, 'c'},
            { "daemonise", 0, 0, 'd'},
            { "pidfile", 1, 0, 'p'},
            { "encpassfile", 1, 0, 'K'},
            { NULL, 0, 0, 0},
        };

        int c = getopt_long(argc, argv, "c:p:dK:h", long_options, &optind);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'K':
                encpassfile = (const char *)optarg;
                break;
            case 'c':
                configfile = optarg;
                break;
            case 'd':
                daemonmode = 1;
                break;
            case 'h':
                usage(argv[0]);
                return 1;
            case 'p':
                pidfile = optarg;
                break;
            default:
                logger(LOG_INFO, "OpenLI: unsupported option: %c",
                        c);
                usage(argv[0]);
                return 1;
        }
    }

    if (configfile == NULL) {
        logger(LOG_INFO,
                "OpenLI: no config file specified. Use -c to specify one.");
        usage(argv[0]);
        return 1;
    }

    if (daemonmode) {
        daemonise(argv[0], pidfile);
    }

    sigemptyset(&sigblock);
    sigaddset(&sigblock, SIGHUP);
    sigaddset(&sigblock, SIGTERM);
    sigaddset(&sigblock, SIGINT);
    sigprocmask(SIG_BLOCK, &sigblock, NULL);

    if (encpassfile && strcmp(encpassfile, "default") == 0) {
        encpassfile = DEFAULT_ENCPASSFILE_LOCATION;
    }

    if (init_prov_state(&provstate, configfile, encpassfile) == -1) {
        logger(LOG_INFO, "OpenLI: Error initialising provisioner.");
        ret = -1;
        goto endprovisioner;
    }

    if (provstate.clientdbfile && provstate.clientdbkey) {
#ifdef HAVE_SQLCIPHER
        if (init_clientdb(&provstate) <= 0) {
            logger(LOG_INFO, "OpenLI provisioner: error while opening client tracker database");
            ret = -1;
            goto endprovisioner;
        }
#else
        logger(LOG_INFO, "OpenLI provisioner: Client tracking database options are set, but you have not built OpenLI with sqlcipher support.");
        logger(LOG_INFO, "OpenLI provisioner: Client tracking database is not available.");
#endif
    } else {
        logger(LOG_INFO, "OpenLI provisioner: client tracking database has NOT been enabled");
    }


    if (provstate.restauthdbfile && provstate.restauthkey) {
#ifdef HAVE_SQLCIPHER
        if ((ret = init_restauth_db(&provstate)) < 0) {
            logger(LOG_INFO, "OpenLI provisioner: error while opening REST authentication database");
            goto endprovisioner;
        }
#else
        logger(LOG_INFO, "OpenLI provisioner: REST Auth DB options are set, but your system does not support using an Auth DB.");
        logger(LOG_INFO, "OpenLI provisioner: Auth DB options ignored.");
#endif
    } else {
        logger(LOG_INFO, "OpenLI provisioner: REST API does NOT require authentication");
    }

    if (provstate.ignorertpcomfort) {
        logger(LOG_INFO, "OpenLI: provisioner ignoring RTP comfort noise for all VOIP intercepts");
    } else {
        logger(LOG_INFO, "OpenLI: provisioner intercepting RTP comfort noise for all VOIP intercepts");
    }

    if (provstate.interceptconffile == NULL) {
        provstate.interceptconffile = strdup(DEFAULT_INTERCEPT_CONFIG_FILE);
    }

    init_intercept_config(&(provstate.interceptconf));

    if ((ret = parse_intercept_config(provstate.interceptconffile,
            &(provstate.interceptconf), provstate.encpassfile)) < 0) {
        /* -2 means the config file was empty, but this is allowed for
         * the intercept config.
         */
        if (ret == -1) {
            logger(LOG_INFO, "OpenLI provisioner: error while parsing intercept config file '%s'", provstate.interceptconffile);
            goto endprovisioner;
        }
    }

    if ((ret = check_for_duplicate_xids(&(provstate.interceptconf), 0, NULL,
            NULL)) == -1) {
        goto endprovisioner;
    }

    if ((ret = add_all_intercept_timers(provstate.epoll_fd,
            &(provstate.interceptconf))) != 0) {
        logger(LOG_INFO, "OpenLI: failed to create all start and end timers for configured intercepts. Exiting.");
        goto endprovisioner;
    }

    /*
     * XXX could also sanity check intercept->mediator mappings too...
     */
    if ((ret = map_intercepts_to_leas(&(provstate.interceptconf))) != 0) {
        logger(LOG_INFO,
                "OpenLI: failed to map %d intercepts to agencies. Exiting.",
                ret);
        goto endprovisioner;
    }

    /* No mediators connected yet, so clear the announce flag for each LIID
     * mapping -- they'll get forcibly announced to each mediator when it
     * connects, so this avoids duplicate / unnecessary announcements later
     * on if some of the mappings change.
     */
    clear_liid_announce_flags(&(provstate.interceptconf));

    if (start_main_listener(&provstate) == -1) {
        logger(LOG_INFO, "OpenLI: Error, could not start listening socket.");
        return 1;
    }

    if (start_mediator_listener(&provstate) == -1) {
        logger(LOG_INFO, "OpenLI: Warning, mediation socket did not start. Will not be able to control mediators.");
    }

    if (strcmp(provstate.pushport, "0") != 0) {
        provstate.updatesockfd = create_listener(provstate.pushaddr,
                provstate.pushport, "update socket");
        if (provstate.updatesockfd == -1) {
            logger(LOG_INFO, "OpenLI: warning, update microhttpd server did not start. Will not be able to receive live updates via REST API.");
        } else {
            start_mhd_daemon(&provstate);
            if (provstate.updatedaemon == NULL) {
                logger(LOG_INFO, "OpenLI: warning, update microhttpd server did not start. Will not be able to receive live updates via REST API.");
            }
        }
    } else {
        provstate.updatesockfd = -1;
        provstate.updatedaemon = NULL;
        logger(LOG_INFO, "OpenLI: warning, update microhttpd server is disabled. Will not be able to receive live updates via REST API.");
    }

    run(&provstate);
    ret = 0;

endprovisioner:
    remove_all_intercept_timers(provstate.epoll_fd, &(provstate.interceptconf));
    clear_prov_state(&provstate);

    if (daemonmode && pidfile) {
        remove_pidfile(pidfile);
    }
    logger(LOG_INFO, "OpenLI: Provisioner has exited.");
}




// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
