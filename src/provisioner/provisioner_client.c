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

#include <unistd.h>

#include "provisioner.h"
#include "provisioner_client.h"
#include "openli_tls.h"
#include "logger.h"

/* Generic functions for managing clients which connect to the OpenLI
 * provisioner, either mediators or collectors.
 */

/** Initialise the client structure
 *
 *  @param client       The client to be initialised
 */
void init_provisioner_client(prov_client_t *client) {
    client->commev = NULL;
    client->authev = NULL;
    client->idletimer = NULL;
    client->lastsslerror = 0;
    client->lastothererror = 0;
    client->ssl = NULL;
}

/** Destroys the state associated with a client socket */
static void destroy_client_state(prov_sock_state_t *cs) {

	if (cs == NULL) {
		return;
	}

	destroy_net_buffer(cs->incoming);
	destroy_net_buffer(cs->outgoing);
	if (cs->ipaddr) {
		free(cs->ipaddr);
		cs->ipaddr = NULL;
	}
	free(cs);

}

/** Closes the main communication channel for a client and frees the
 *  state for that socket.
 */
static void halt_provisioner_client_mainfd(int epollfd, prov_client_t *client,
		char *identifier) {

	prov_sock_state_t *cs = client->state;
	const char *label;
    struct epoll_event ev;

	if (cs == NULL) {
		return;
	}

	if (cs->clientrole == PROV_EPOLL_COLLECTOR) {
		label = "collector";
	} else {
		label = "mediator";
	}

	if (client->commev) {
		if (epoll_ctl(epollfd, EPOLL_CTL_DEL, client->commev->fd, &ev) < 0) {
			if (cs->log_allowed) {
				logger(LOG_INFO,
            	        "OpenLI: unable to remove %s %s from epoll: %s.",
                	    label, identifier, strerror(errno));
        	}
    	}
		if (client->commev->fdtype == PROV_EPOLL_COLLECTOR ||
				client->commev->fdtype == PROV_EPOLL_MEDIATOR) {
			if (cs->log_allowed) {
				logger(LOG_INFO,
						"OpenLI: disconnected %s %s", label, identifier);
			}
		}
		close(client->commev->fd);
		free(client->commev);
	}

	/* Destroy the buffers allocated for storing incoming and outgoing data */
	if (cs->incoming) {
		destroy_net_buffer(cs->incoming);
		cs->incoming = NULL;
	}
	if (cs->outgoing) {
		destroy_net_buffer(cs->outgoing);
		cs->outgoing = NULL;
	}
	cs->halted = 1;
	cs->trusted = 0;

	client->commev = NULL;
}

/** Closes the communication channel between the provisioner and a client.
 *  Will also start the inactivity timer for the client and delete any
 *  buffered data both for and from the client.
 *
 *  @param epollfd      The file descriptor used by the provisioner for
 *                      polling.
 *  @param client       The client to be disconnected.
 *  @param identifier   The name of the client, used for logging.
 */
void disconnect_provisioner_client(int epollfd, prov_client_t *client,
		char *identifier) {

	prov_sock_state_t *cs = client->state;
	/* If we were waiting on auth, make sure to remove the timer */
	halt_provisioner_client_authtimer(epollfd, client, identifier);
	halt_provisioner_client_mainfd(epollfd, client, identifier);

    if (cs->clientrole == PROV_EPOLL_MEDIATOR) {
        /* Don't expire and withdraw idle mediators -- we want the
         * collectors to keep buffering for them in case they come back.
         */
        halt_provisioner_client_idletimer(epollfd, client, identifier);
    } else {
    	/* Start the idle timer, so we can remove this client if it is no
         * longer being used.
        */
	    start_provisioner_client_idletimer(epollfd, client, identifier,
	    		PROVISIONER_IDLE_TIMEOUT_SECS);
    }

	if (client->ssl) {
		SSL_free(client->ssl);
		client->ssl = NULL;
	}
}

/** Terminates the communication channel and destroys all state associated
 *  with a given client, immediately.
 *
 *  @param epollfd      The file descriptor used by the provisioner for
 *                      polling.
 *  @param client       The client to be destroyed.
 *  @param identifier   The name of the client, used for logging.
 */
void destroy_provisioner_client(int epollfd, prov_client_t *client,
		char *identifier) {

	/* Make sure the client has disconnected cleanly */
	disconnect_provisioner_client(epollfd, client, identifier);
	halt_provisioner_client_idletimer(epollfd, client, identifier);

    if (client->identifier) {
        free(client->identifier);
    }
	destroy_client_state(client->state);
    free(client);
}

/** Create fresh socket state for a newly connected client */
static void create_prov_socket_state(prov_client_t *client, int authtimerfd,
        char *ipaddrstr, int isbad, int fd, int fdtype) {

    prov_sock_state_t *cs = (prov_sock_state_t *)malloc(
            sizeof(prov_sock_state_t));

	/* If the client is known to have been troublesome in the past, i.e.
     * failing to connect properly, don't print any error logs until it
     * manages to connect successfully. This is just to reduce log spam.
     */
    if (isbad) {
        cs->log_allowed = 0;
    } else {
        cs->log_allowed = 1;
    }

	cs->ipaddr = strdup(ipaddrstr);
    cs->incoming = create_net_buffer(NETBUF_RECV, fd, client->ssl);
    cs->outgoing = create_net_buffer(NETBUF_SEND, fd, client->ssl);
    cs->trusted = 0;
    cs->halted = 0;
    cs->clientrole = fdtype;
    cs->parent = NULL;

    client->state = cs;
}

/** Attempts to complete an incoming connection from a client. If the
 *  provisioner is using SSL, an SSL handshake will be attempted.
 *
 *  @note an SSL handshake may not immediately succeed, in which case
 *        the client is marked as pending and the handshake can be later
 *        resolved by observed a 'waitfdtype' epoll event for the client
 *        file descriptor.
 *
 *  @param sslconf      The SSL configuration used by the provisioner.
 *  @param epollfd      The file descriptor used by the provisioner for
 *                      polling.
 *  @param identifier   The name of the client, used for logging.
 *  @param client       The client that is attempting to connect.
 *  @param newfd        The file descriptor which the client connection
 *                      has been accepted on.
 *  @param successfdtype    The epoll event type to associate with this
 *                          client once it has successfully connected.
 *  @param waitfdtype       The epoll event type to associate with this
 *                          client if the connection is still pending.
 *
 *  @return -1 if an error occurs, 0 if the connection is pending, 1 if
 *          the connection completes successfully.
 */
int accept_provisioner_client(openli_ssl_config_t *sslconf, int epollfd,
        char *identifier, prov_client_t *client, int newfd,
		int successfdtype, int waitfdtype) {

	int r, sslreqmessage = 0;
	const char *label;
    struct epoll_event ev;

	if (successfdtype == PROV_EPOLL_COLLECTOR) {
		label = "collector";
	} else {
		label = "mediator";
	}

    /* Hopefully this never happens... */
	if (client->commev) {
		 logger(LOG_INFO, "OpenLI: received new connection from %s %s, but we already have an active connection from them?", label, identifier);
		return 1;
	}

	/* If client->ssl is NULL, this will complete a non-TLS connection */
    r = listen_ssl_socket(sslconf, &(client->ssl), newfd);

    if (r == OPENLI_SSL_CONNECT_FAILED) {
		/* SSL handshake failed -- drop the client */
        SSL_free(client->ssl);
        client->ssl = NULL;

        if (client->lastsslerror == 0) {
            logger(LOG_INFO, "OpenLI: SSL Handshake failed for %s %s", label,
					identifier);
        }
        client->lastsslerror = 1;
        sslreqmessage = 1;
    }

	if (!client->state) {
    	create_prov_socket_state(client, -1, identifier, 0, newfd,
				successfdtype);
	} else {
		client->state->incoming = create_net_buffer(NETBUF_RECV, newfd,
				client->ssl);
		client->state->outgoing = create_net_buffer(NETBUF_SEND, newfd,
				client->ssl);
	}

    if (sslreqmessage && push_ssl_required(client->state->outgoing) < 0) {
        close(newfd);
        goto colconnfail;
    }

    client->commev = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));
    client->commev->fd = newfd;
    client->commev->client = client;

    if (r == OPENLI_SSL_CONNECT_WAITING) {
        client->commev->fdtype = waitfdtype;
    } else {
        client->commev->fdtype = successfdtype;
    }

    /* Add fd to epoll */
    ev.data.ptr = (void *)client->commev;
    ev.events = EPOLLIN | EPOLLRDHUP;

    if (sslreqmessage) {
        ev.events |= EPOLLOUT;
    }

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client->commev->fd, &ev) < 0) {
        if (client->lastothererror == 0) {
            logger(LOG_INFO,
                    "OpenLI: unable to add %s %s fd to epoll: %s.",
                    label, identifier, strerror(errno));
        }
        client->lastothererror = 1;
        goto colconnfail;
    }

    if (r == OPENLI_SSL_CONNECT_WAITING) {
        /* SSL Handshake is not yet complete */
		if (client->lastsslerror == 0) {
			logger(LOG_INFO, "OpenLI: SSL handshake for %s %s is pending...",
					label, identifier);
		}
        return 0;
    }

	if (client->state->log_allowed) {
		if (r == OPENLI_SSL_CONNECT_SUCCESS) {
			logger(LOG_INFO, "OpenLI: SSL handshake for %s %s has succeeded",
					label, identifier);
		} else if (r == OPENLI_SSL_CONNECT_NOSSL) {
			logger(LOG_INFO, "OpenLI: connection accepted from %s %s",
					label, identifier);
		}
	}

	/* Now the client needs to authenticate with us before we can send it
     * any intercept instructions. If it doesn't auth soon, we assume it is
 	 * not a valid OpenLI collector or mediator and want to drop it asap.
	 */
	start_provisioner_client_authtimer(epollfd, client, identifier,
			PROVISIONER_AUTH_TIMEOUT_SECS);
    client->state->halted = 0;
	return client->commev->fd;

colconnfail:
	disconnect_provisioner_client(epollfd, client, identifier);
	return -1;

}

/** Continues a pending SSL handshake for a client which is attempting to
 *  connect to the provisioner.
 *
 *  @param epollfd      The file descriptor used by the provisioner for
 *                      polling.
 *  @param client       The client that is attempting to connect.
 *  @param cs           The socket state associated with this client.
 *
 *  @return -1 if the handshake fails, 0 if it is still incomplete, 1 if
 *          the handshake has now completed successfully.
 */
int continue_provisioner_client_handshake(int epollfd, prov_client_t *client,
		prov_sock_state_t *cs) {

	int ret;
	const char *label;

	if (cs->clientrole == PROV_EPOLL_COLLECTOR) {
		label = "collector";
	} else {
		label = "mediator";
	}

	ret = SSL_accept(client->ssl);

	if (ret > 0) {
        logger(LOG_INFO, "OpenLI: Pending SSL handshake for %s %s accepted",
				label, cs->ipaddr);
        client->lastsslerror = 0;
        client->lastothererror = 0;
        start_provisioner_client_authtimer(epollfd, client, cs->ipaddr,
			PROVISIONER_AUTH_TIMEOUT_SECS);

		/* Change our epoll event type so the epoll loop knows that we are
         * now a connected client.
	     */
		client->commev->fdtype = cs->clientrole;
        client->state->halted = 0;
    } else {
        ret = SSL_get_error(client->ssl, ret);
        if(ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE){
            //keep trying
            return 0;
        } else {
            //fail out
            if (client->lastsslerror == 0) {
                logger(LOG_INFO,
						"OpenLI: Pending SSL Handshake for %s %s failed",
                        label, cs->ipaddr);
            }
            client->lastsslerror = 1;

            destroy_net_buffer(cs->incoming);
            cs->incoming = NULL;
            destroy_net_buffer(cs->outgoing);
            cs->outgoing = create_net_buffer(NETBUF_SEND, client->commev->fd,
                    NULL);

            push_ssl_required(client->state->outgoing);
		    client->commev->fdtype = cs->clientrole;
            return -1;
        }
    }
    return 1;
}

/** Stops the inactivity timer for a given client.
 *
 *  @param epollfd      The file descriptor used by the provisioner for
 *                      polling.
 *  @param client       The client that is no longer inactive.
 *  @param identifier   The name of the client, used for logging.
 *
 *  @return -1 if the timer couldn't be stopped for some reason. 0 otherwise.
 */
int halt_provisioner_client_idletimer(int epollfd, prov_client_t *client,
        char *identifier) {

    struct epoll_event ev;
    int ret = 0;

	if (client->idletimer == NULL) {
		return 0;
	}

    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, client->idletimer->fd,
                &ev) < 0) {

        logger(LOG_INFO,
                "OpenLI provisioner: Failed to remove idle timer fd for %s from epoll: %s.",
                identifier, strerror(errno));
        ret =  -1;
    }

    close(client->idletimer->fd);
    free(client->idletimer);
    client->idletimer = NULL;
    return ret;
}

/** Stops the authentication timer for a given client.
 *
 *  @param epollfd      The file descriptor used by the provisioner for
 *                      polling.
 *  @param client       The client that no longer has auth pending.
 *  @param identifier   The name of the client, used for logging.
 *
 *  @return -1 if the timer couldn't be stopped for some reason. 0 otherwise.
 */
int halt_provisioner_client_authtimer(int epollfd, prov_client_t *client,
        char *identifier) {

    struct epoll_event ev;
    int ret = 0;

	if (client->authev == NULL) {
		return 0;
	}

    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, client->authev->fd,
                &ev) < 0) {

        logger(LOG_INFO,
                "OpenLI provisioner: Failed to remove auth timer fd for %s from epoll: %s.",
                identifier, strerror(errno));
        ret = -1;
    }

    close(client->authev->fd);
    free(client->authev);
    client->authev = NULL;
    return ret;
}

/** Starts the authentication timer for a given client.
 *  @param epollfd      The file descriptor used by the provisioner for
 *                      polling.
 *  @param client       The client that needs to authenticate.
 *  @param identifier   The name of the client, used for logging.
 */
void start_provisioner_client_authtimer(int epollfd, prov_client_t *client,
        char *identifier, int timeoutsecs) {

    if (client->authev != NULL) {
        return;
    }

    client->authev = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

    client->authev->fdtype = PROV_EPOLL_FD_TIMER;
    client->authev->fd = epoll_add_timer(epollfd, timeoutsecs,
            client->authev);
    client->authev->client = client;
}

/** Starts the inactivity timer for a given client.
 *  @param epollfd      The file descriptor used by the provisioner for
 *                      polling.
 *  @param client       The client that has become inactive.
 *  @param identifier   The name of the client, used for logging.
 */
void start_provisioner_client_idletimer(int epollfd, prov_client_t *client,
        char *identifier, int timeoutsecs) {

    if (client->idletimer != NULL) {
        return;
    }

    client->idletimer = (prov_epoll_ev_t *)malloc(sizeof(prov_epoll_ev_t));

    client->idletimer->fdtype = PROV_EPOLL_FD_IDLETIMER;
    client->idletimer->fd = epoll_add_timer(epollfd, timeoutsecs,
            client->idletimer);
    client->idletimer->client = client;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
