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

#include <unistd.h>
#include <sys/epoll.h>

#include "med_epoll.h"
#include "mediator_prov.h"
#include "netcomms.h"
#include "logger.h"
#include "util.h"

/** This file implements the methods used by the communication channel between
 *  an OpenLI mediator and an OpenLI provisioner (on the mediator side).
 */

/** Initialises the state for a provisioner instance
 *
 *  @param prov             The provisioner instance
 *  @param ctx              The SSL context object for the mediator
 */
void init_provisioner_instance(mediator_prov_t *prov, SSL_CTX **ctx) {
	prov->provreconnect = NULL;
	prov->provev = NULL;
	prov->incoming = NULL;
	prov->outgoing = NULL;
	prov->disable_log = 0;
	prov->tryconnect = 1;
    prov->just_connected = 0;
	prov->ssl = NULL;
	prov->epoll_fd = -1;
	prov->sslctxt = ctx;
	prov->lastsslerror = 0;
    prov->provport = NULL;
    prov->provaddr = NULL;
}

/** Create an epoll timer event for the next attempt to reconnect to the
 *  provisioner.
 *
 *  Should only be called when the provisioner connection has broken down
 *  for some reason, obviously.
 *
 *  @param prov    The provisioner instance to be reconnected
 */
static inline void setup_provisioner_reconnect_timer(mediator_prov_t *prov) {

	if (prov->provreconnect == NULL) {
		prov->provreconnect = create_mediator_timer(prov->epoll_fd,
				NULL, MED_EPOLL_PROVRECONNECT, 0);
	}
    prov->tryconnect = 0;
    start_mediator_timer(prov->provreconnect, 1);
}

/** Disconnects the TCP session to a provisioner and resets any state
 *  associated with that communication channel.
 *
 *  @param prov                 The provisioner instance to disconnect
 *  @param enable_reconnect     If not zero, we will set a timer to try and
 *                              reconnect to the provisioner in 1 second.
 */
void disconnect_provisioner(mediator_prov_t *prov, int enable_reconnect) {

	if (prov->disable_log == 0) {
		logger(LOG_INFO,
				"OpenLI Mediator: Disconnecting from provisioner.");
	}

    /* If we were using SSL to communicate, tidy up the SSL context */
    if (prov->ssl) {
        SSL_free(prov->ssl);
        prov->ssl = NULL;
    }

    /* Remove the provisioner socket from our epoll event set */
    if (remove_mediator_fdevent(prov->provev) == -1) {
        logger(LOG_INFO,
                "OpenLI Mediator: problem removing provisioner fd from epoll: %s.",
                strerror(errno));
    }
    prov->provev = NULL;

	/* Halt the provisioner reconnection timer, if it is running */
	if (prov->provreconnect) {
		if (prov->provreconnect->fd != -1) {
			close(prov->provreconnect->fd);
		}
		free(prov->provreconnect);
		prov->provreconnect = NULL;
	}

    /* Release the buffers used to store messages sent to and received from
     * the provisioner.
     */
    if (prov->outgoing) {
        destroy_net_buffer(prov->outgoing, NULL);
        prov->outgoing = NULL;
    }
    if (prov->incoming) {
        destroy_net_buffer(prov->incoming, NULL);
        prov->incoming = NULL;
    }

    /* Set the reconnection timer, if requested */
	if (enable_reconnect) {
		setup_provisioner_reconnect_timer(prov);
	}
	prov->disable_log = 1;

}

/** Releases all memory associated with a provisioner that this mediator
 *  was connected to.
 *
 *  @param prov         The provisioner to be released.
 */
void free_provisioner(mediator_prov_t *prov) {

	disconnect_provisioner(prov, 0);

	if (prov->provaddr) {
		free(prov->provaddr);
	}
	if (prov->provport) {
		free(prov->provport);
	}
}

/** Sends an integrity check signing request to a connected provisioner.
 *
 *  @param prov         The provisioner that needs to receive the request
 *  @param req          The request that needs to be sent
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int send_ics_signing_request_to_provisioner(mediator_prov_t *prov,
        struct ics_sign_request_message *req) {

    int ret = 0;

    if (prov->outgoing == NULL) {
        return 0;
    }
    if (req == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: passed a null request into send_ics_signing_request_to_provisioner");
        return -1;
    }

    if (push_ics_signing_request_onto_net_buffer(prov->outgoing, req) == -1) {
        logger(LOG_INFO, "OpenLI Mediator: unable to push signing request to provisioner.");
        ret = -1;
        goto tidyup;
    }

    /* Otherwise, we may have disabled writing when we last emptied the
     * outgoing buffer so make sure it is enabled again to send this queued
     * message.
     */
    if (modify_mediator_fdevent(prov->provev,
            EPOLLIN | EPOLLOUT | EPOLLRDHUP) < 0) {
        logger(LOG_INFO,
                "OpenLI Mediator: failed to re-enable transmit on provisioner socket: %s.",
                strerror(errno));
        ret = -1;
        goto tidyup;
    }

tidyup:
    if (req->digest) free(req->digest);
    if (req->ics_key) free(req->ics_key);
    if (req->requestedby) free(req->requestedby);
    free(req);

    return ret;
}

/** Sends the mediator details message to a connected provisioner.
 *  Mediator details include the port and IP that it is listening on for
 *  collector connections.
 *
 *  @param prov         The provisioner that is to receive the message.
 *  @param meddeets     The details to be included in the message.
 *  @param justcreated  A flag indicating whether the socket for the
 *                      provisioner connection has just been created.
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
int send_mediator_details_to_provisioner(mediator_prov_t *prov,
		openli_mediator_t *meddeets, int justcreated) {

    if (prov->outgoing == NULL) {
        return 0;
    }

    /* Add the mediator details message to the outgoing buffer for the
     * provisioner socket.
     */
    if (push_mediator_onto_net_buffer(prov->outgoing, meddeets) == -1) {
        logger(LOG_INFO, "OpenLI Mediator: unable to push mediator details to provisioner.");
        return -1;
    }

    /* If the socket was just created, then we've already configured the
     * corresponding epoll event for writing.
     */
    if (justcreated) {
        return 0;
    }


    /* Otherwise, we may have disabled writing when we last emptied the
     * outgoing buffer so make sure it is enabled again to send this queued
     * message.
     */
    if (modify_mediator_fdevent(prov->provev,
            EPOLLIN | EPOLLOUT | EPOLLRDHUP) < 0) {
        logger(LOG_INFO,
                "OpenLI Mediator: failed to re-enable transmit on provisioner socket: %s.",
                strerror(errno));
        return -1;
    }

    return 0;
}

/** Initialises local state for a successful connection to the provisioner
 *
 *  @param prov             The provisioner that is to be initialised
 *  @param sock             The file descriptor of the provisioner connection
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int init_provisioner_connection(mediator_prov_t *prov, int sock) {

    if (sock == 0) {
        return 0;
    }

    if (*(prov->sslctxt) != NULL) {
        /* We're using TLS, so attempt an SSL connection */

        /* mediator can't do anything until it has instructions from
         * provisioner so blocking is fine */
        fd_set_block(sock);

        int errr;
        prov->ssl = SSL_new(*(prov->sslctxt));
        SSL_set_fd(prov->ssl, sock);

        errr = SSL_connect(prov->ssl);
        fd_set_nonblock(sock);

        if (errr <= 0){
            errr = SSL_get_error(prov->ssl, errr);
            if (errr != SSL_ERROR_WANT_WRITE && errr != SSL_ERROR_WANT_READ){ //handshake failed badly
                SSL_free(prov->ssl);
                prov->ssl = NULL;
                if (prov->lastsslerror == 0) {
                    logger(LOG_INFO, "OpenLI: SSL Handshake failed when connecting to provisioner");
                    prov->lastsslerror = 1;
                }
                return -1;
            }
        }
        logger(LOG_INFO,
                "OpenLI mediator: SSL Handshake complete for connection to provisioner");
		prov->lastsslerror = 0;
    } else {
        prov->ssl = NULL;
    }

    /* Create buffers for both receiving and sending messages on this socket */
    prov->outgoing = create_net_buffer(NETBUF_SEND, sock, prov->ssl);
    prov->incoming = create_net_buffer(NETBUF_RECV, sock, prov->ssl);

    /* The AUTH message indicates to the provisioner that we are an OpenLI
     * mediator and they can safely start sending us intercept information.
     */
    if (push_auth_onto_net_buffer(prov->outgoing,
                OPENLI_PROTO_MEDIATOR_AUTH, NULL, NULL) == -1) {
        if (prov->disable_log == 0) {
            logger(LOG_INFO, "OpenLI Mediator: unable to push auth message for provisioner.");
        }
        return -1;
    }

    /* We're about to enqueue our "auth" message, so immediately configure
     * this socket for an epoll write event (as well as read, of course).
     */
    if (prov->provev == NULL) {
        prov->provev = create_mediator_fdevent(prov->epoll_fd,
                prov, MED_EPOLL_PROVISIONER, sock,
                EPOLLIN | EPOLLOUT | EPOLLRDHUP);

    }

    if (!prov->provev) {
        if (prov->disable_log == 0) {
            logger(LOG_INFO, "OpenLI Mediator: unable to create epoll event for provisioner socket.");
        }
        return -1;
    }

	return 0;
}

/** Attempts to connect to the provisioner.
 *
 *  @param prov             The provisioner to connect to
 *  @param provfail         Set to 1 if the most recent connection attempt
 *                          failed, 0 otherwise.
 *
 *  @return 1 if the connection attempt fails for non-fatal reason, 0 if
 *            the attempt succeeded (or we were already connected), -1
 *            if the connection attempt failed for an unresolvable reason.
 */
int attempt_provisioner_connect(mediator_prov_t *prov, int provfail) {

    /* If provfail is 1, this function won't log any failures to connect.
     * This prevents log spam in cases where we repeatedly fail to connect,
     * e.g. because the provisioner is down.
     */
    int s;

	/* Only attempt a connection if we don't already have one AND we're due
     * to try a connection attempt.
     */
	if (prov->provev != NULL || prov->tryconnect == 0) {
		return 0;
	}

	s = connect_socket(prov->provaddr, prov->provport, provfail, 1);

    provfail = 0;
    if (s == -1) {
        if (prov->disable_log == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: Error - Unable to connect to provisioner.");
        }
        setup_provisioner_reconnect_timer(prov);
        provfail = 1;
    } else if (s == 0) {
        setup_provisioner_reconnect_timer(prov);
        provfail = 1;
    }

    if (!provfail) {
        int ret = init_provisioner_connection(prov, s);

        if (ret != 0) {
            /* Something went wrong (probably an SSL error), so clear any
             * initialised state and make sure we halt the mediator.
             */
            disconnect_provisioner(prov, 0);
            provfail = -1;
        } else {
            if (prov->disable_log == 0) {
                logger(LOG_INFO,
                        "OpenLI mediator has connected to provisioner at %s:%s",
                        prov->provaddr, prov->provport);
            }
            prov->just_connected = 1;
        }
    }
    return provfail;
}



/** Sends any pending messages to the provisioner.
 *
 *  @param prov             The reference to the provisioner.
 *
 *  @return -1 if an error occurs, 1 otherwise.
 */
int transmit_provisioner(mediator_prov_t *prov) {

    int ret;
    openli_proto_msgtype_t err = OPENLI_PROTO_NO_MESSAGE;

    /* Try to send whatever we've got in the netcomms buffer */
    ret = transmit_net_buffer(prov->outgoing, &err);
    if (ret == -1) {
        if (prov->disable_log == 0) {
            nb_log_transmit_error(err);
            logger(LOG_INFO, "OpenLI Mediator: failed to transmit message to provisioner.");
        }
        return -1;
    }

    if (ret == 0) {
        /* No more outstanding data, remove EPOLLOUT event */
        if (modify_mediator_fdevent(prov->provev, EPOLLIN | EPOLLRDHUP) < 0) {
            if (prov->disable_log == 0) {
                logger(LOG_INFO,
                        "OpenLI Mediator: error disabling EPOLLOUT for provisioner fd: %s.",
                        strerror(errno));
            }
            return -1;
        }
    }

    return 1;
}

/** Applies any changes to the provisioner socket configuration following
 *  a user-triggered config reload.
 *
 *  @param currstate            The pre-reload provisioner state
 *  @param newstate             A provisioner instance containing the updated
 *                              configuration.
 *  @return 0 if the configuration is unchanged, 1 if it has changed.
 */
int reload_provisioner_socket_config(mediator_prov_t *currstate,
        mediator_prov_t *newstate) {

    int changed = 0;

    if (strcmp(newstate->provaddr, currstate->provaddr) != 0 ||
            strcmp(newstate->provport, currstate->provport) != 0) {

        /* Replace existing IP and port strings */
        free(currstate->provaddr);
        free(currstate->provport);
        currstate->provaddr = strdup(newstate->provaddr);
        currstate->provport = strdup(newstate->provport);

        /* Don't bother connecting right now, the run() loop will do this
         * as soon as we return.
         */
        changed = 1;
    }

    if (!changed) {
        logger(LOG_INFO,
                "OpenLI Mediator: provisioner socket configuration is unchanged.");
    }

    free(newstate->provaddr);
    free(newstate->provport);
    newstate->provaddr = NULL;
    newstate->provport = NULL;

	return changed;
}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
