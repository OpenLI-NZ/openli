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

#ifndef OPENLI_PROVISIONER_CLIENT_H_
#define OPENLI_PROVISIONER_CLIENT_H_

#include "provisioner.h"

/** Delete any saved state for a client if it has been inactive for this
 *  many seconds.
 */
#define PROVISIONER_IDLE_TIMEOUT_SECS 300

/** Disconnect a client if it does not successfully authenticate within
 *  this number of seconds after a successful connection attempt.
 */
#define PROVISIONER_AUTH_TIMEOUT_SECS 5

/** Initialise the client structure
 *
 *  @param client       The client to be initialised
 */
void init_provisioner_client(prov_client_t *client);

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
        char *identifier);

/** Terminates the communication channel and destroys all state associated
 *  with a given client, immediately.
 *
 *  @param epollfd      The file descriptor used by the provisioner for
 *                      polling.
 *  @param client       The client to be destroyed.
 *  @param identifier   The name of the client, used for logging.
 */
void destroy_provisioner_client(int epollfd, prov_client_t *client,
        char *identifier);

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
                int successfdtype, int waitfdtype);

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
        prov_sock_state_t *cs);

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
        char *identifier);

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
        char *identifier);

/** Starts the authentication timer for a given client.
 *  @param epollfd      The file descriptor used by the provisioner for
 *                      polling.
 *  @param client       The client that needs to authenticate.
 *  @param timeoutsecs  The number of seconds before timing out.
 */
void start_provisioner_client_authtimer(int epollfd, prov_client_t *client,
        int timeoutsecs);

/** Starts the inactivity timer for a given client.
 *  @param epollfd      The file descriptor used by the provisioner for
 *                      polling.
 *  @param client       The client that has become inactive.
 *  @param timeoutsecs  The number of seconds before timing out.
 */
void start_provisioner_client_idletimer(int epollfd, prov_client_t *client,
        int timeoutsecs);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
