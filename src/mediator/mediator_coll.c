/*
 *
 * Copyright (c) 2018-2020 The University of Waikato, Hamilton, New Zealand.
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

#include "openli_tls.h"
#include "mediator_coll.h"
#include "util.h"
#include "logger.h"
#include <unistd.h>


/** Initialises the state for the collectors managed by a mediator.
 *
 *  @param medcol       The global state for the collectors that is to be
 *                      initialised.
 *  @param usetls       A pointer to the global flag that indicates whether
 *                      new collector connections must use TLS.
 *  @param sslconf      A pointer to the SSL configuration for this mediator.
 */
void init_med_collector_state(mediator_collector_t *medcol, uint8_t *usetls,
        openli_ssl_config_t *sslconf) {

    medcol->usingtls = usetls;
    medcol->sslconf = sslconf;
    medcol->lastsslerror = 0;
    medcol->disabledcols = NULL;
    medcol->collectors = NULL;
    medcol->epoll_fd = -1;
}

/** Destroys the state for the collectors managed by mediator, including
 *  dropping any remaining collector connections.
 *
 *  @param medcol       The global state for the collectors that is to be
 *                      destroyed.
 */
void destroy_med_collector_state(mediator_collector_t *medcol) {

    unsigned char index[1024];
    disabled_collector_t *discol, *dtmp;

    /* Purge the disabled collector list */
    index[0] = '\0';
    HASH_ITER(hh, medcol->disabledcols, discol, dtmp) {
        HASH_DELETE(hh, medcol->disabledcols, discol);
        free(discol->ipaddr);
        free(discol);
    }

    /* Dump all connected collectors */
    drop_all_collectors(medcol);

}

/** Accepts a connection from a collector and prepares to receive encoded
 *  ETSI records from that collector.
 *
 *  @param medcol        The global state for the collectors seen by this
 *                       mediator.
 *  @param listenfd      The file descriptor that the connection attempt
 *                       was seen on.
 *
 *  @return -1 if an error occurs, otherwise the file descriptor for the
 *          collector connection.
 */
int mediator_accept_collector(mediator_collector_t *medcol, int listenfd) {

    int newfd;
    struct sockaddr_storage saddr;
    socklen_t socklen = sizeof(saddr);
    char strbuf[INET6_ADDRSTRLEN];
    active_collector_t col;
    single_coll_state_t *mstate;
    disabled_collector_t *discol = NULL;
    int fdtype;
    int r = OPENLI_SSL_CONNECT_NOSSL;

    /* TODO check for EPOLLHUP or EPOLLERR */

    /* Accept, then add to list of collectors. Push all active intercepts
     * out to the collector. */
    newfd = accept(listenfd, (struct sockaddr *)&saddr, &socklen);
    fd_set_nonblock(newfd);

    if (getnameinfo((struct sockaddr *)&saddr, socklen, strbuf, sizeof(strbuf),
                0, 0, NI_NUMERICHOST) != 0) {
        logger(LOG_INFO, "OpenLI Mediator: getnameinfo error in mediator: %s.",
                strerror(errno));
    }

    if (newfd < 0) {
        return newfd;
    }

    col.ssl = NULL;

    if (*(medcol->usingtls)) {
        /* We're using TLS so create an OpenSSL socket */
        r = listen_ssl_socket(medcol->sslconf, &(col.ssl), newfd);

        if (r == OPENLI_SSL_CONNECT_FAILED) {
            close(newfd);
            SSL_free(col.ssl);

            if (r != medcol->lastsslerror) {
                logger(LOG_INFO,
                        "OpenLI: SSL Handshake failed for collector %s",
                        strbuf);
            }
            medcol->lastsslerror = r;
            return -1;
        }

        if (r == OPENLI_SSL_CONNECT_WAITING) {
            /* Handshake is not yet complete, so we need to wait for that */
            fdtype = MED_EPOLL_COLLECTOR_HANDSHAKE;
        } else {
            /* Handshake completed, go straight to "Ready" mode */
            fdtype = MED_EPOLL_COLLECTOR;
            medcol->lastsslerror = 0;
        }
    } else {
        /* Not using TLS, we're good to go right away */
        fdtype = MED_EPOLL_COLLECTOR;
    }

    mstate = (single_coll_state_t *)malloc(sizeof(single_coll_state_t));
    /* Add fd to epoll */
    col.colev = create_mediator_fdevent(medcol->epoll_fd, mstate, fdtype,
            newfd, EPOLLIN | EPOLLRDHUP);
    if (col.colev == NULL) {
        logger(LOG_INFO,
                "OpenLI Mediator: unable to add collector fd to epoll: %s.",
                strerror(errno));
        return -1;
    }
    mstate->ssl = col.ssl;
    mstate->incoming = create_net_buffer(NETBUF_RECV, newfd, col.ssl);
    mstate->ipaddr = strdup(strbuf);

    /* Check if this is a reconnection case */
    HASH_FIND(hh, medcol->disabledcols, mstate->ipaddr,
            strlen(mstate->ipaddr), discol);

    if (discol) {
        mstate->disabled_log = 1;
    } else {
        logger(LOG_INFO,
                "OpenLI Mediator: accepted connection from collector %s.",
                strbuf);
        mstate->disabled_log = 0;
    }

    /* Add this collector to the set of active collectors */
    libtrace_list_push_back(medcol->collectors, &col);

    return newfd;
}

/** Attempts to complete an ongoing TLS handshake with a collector.
 *
 *  @param medcol       The global state for the collectors seen by the mediator
 *  @param mev          The epoll event for the collector socket
 *
 *  @return -1 if an error occurs, 0 if the handshake is not yet complete,
 *          1 if the handshake has now completed.
 */
int continue_collector_handshake(mediator_collector_t *medcol,
        med_epoll_ev_t *mev) {

    single_coll_state_t *cs = (single_coll_state_t *)(mev->state);

    //either keep running handshake or return when error
    int ret = SSL_accept(cs->ssl);

    if (ret <= 0){
        ret = SSL_get_error(cs->ssl, ret);
        if(ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE){
            //keep trying
            return 0;
        }
        else {
            //fail out
            logger(LOG_INFO,
                    "OpenLI: Pending SSL Handshake for collector failed");
            return -1;
        }
    }
    logger(LOG_INFO, "OpenLI: Pending SSL Handshake for collector accepted");
    medcol->lastsslerror = 0;

    //handshake has finished
    mev->fdtype = MED_EPOLL_COLLECTOR;
    return 1;
}


/** Drops the connection to a collector and moves the collector to the
 *  disabled collector list.
 *
 *  @param medcol       The global state for collectors seen by the mediator
 *  @param colev        The epoll event for this collection connection
 *  @param disablelog   A flag that indicates whether we should log about
 *                      this incident
 */
void drop_collector(mediator_collector_t *medcol,
        med_epoll_ev_t *colev, int disablelog) {
    single_coll_state_t *mstate;

    if (!colev) {
        return;
    }

    mstate = (single_coll_state_t *)(colev->state);
    if (mstate->disabled_log == 0 && colev->fd != -1) {
        logger(LOG_INFO,
                "OpenLI Mediator: disconnecting from collector %d.",
                colev->fd);
    }

    if (mstate && disablelog) {
        disabled_collector_t *discol;

        /* Add this collector to the disabled collectors list. */
        HASH_FIND(hh, medcol->disabledcols, mstate->ipaddr,
                strlen(mstate->ipaddr), discol);
        if (discol == NULL) {
            discol = (disabled_collector_t *)calloc(1,
                    sizeof(disabled_collector_t));
            discol->ipaddr = mstate->ipaddr;
            mstate->ipaddr = NULL;

            HASH_ADD_KEYPTR(hh, medcol->disabledcols, discol->ipaddr,
                    strlen(discol->ipaddr), discol);
        }
    }

    if (mstate && mstate->incoming) {
        destroy_net_buffer(mstate->incoming);
        mstate->incoming = NULL;
    }

    if (mstate->ipaddr) {
        free(mstate->ipaddr);
        mstate->ipaddr = NULL;
    }

    if (colev->fd != -1) {
        close(colev->fd);
        colev->fd = -1;
    }
}

/** Drops *all* currently connected collectors.
 *
 *  @param medcol       The set of collectors for this mediator
 */
void drop_all_collectors(mediator_collector_t *medcol) {

    /* TODO send disconnect messages to all collectors? */
    libtrace_list_node_t *n;
    active_collector_t *col;

    n = medcol->collectors->head;
    while (n) {
        col = (active_collector_t *)n->data;

        /* No need to log every collector we're dropping, so we pass in 0
         * as the last parameter */
        drop_collector(medcol, col->colev, 0);
        free(col->colev->state);
        free(col->colev);
        if (col->ssl){
            SSL_free(col->ssl);
        }
        n = n->next;
    }

    libtrace_list_deinit(medcol->collectors);
}

/** Re-enables log messages for a collector that has re-connected.
 *
 *  @param medcol       The global state for collectors seen by this mediator
 *  @param cs           The collector that has re-connected
 *
 */
void reenable_collector_logging(mediator_collector_t *medcol,
        single_coll_state_t *cs) {

    disabled_collector_t *discol = NULL;

    cs->disabled_log = 0;
    HASH_FIND(hh, medcol->disabledcols, cs->ipaddr, strlen(cs->ipaddr), discol);
    if (discol) {
        HASH_DELETE(hh, medcol->disabledcols, discol);
        free(discol->ipaddr);
        free(discol);
        logger(LOG_INFO, "collector %s has successfully re-connected",
                cs->ipaddr);
    }
}



// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

