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

#define PROVISIONER_IDLE_TIMEOUT_SECS 300
#define PROVISIONER_AUTH_TIMEOUT_SECS 5

void init_provisioner_client(prov_client_t *client);
void halt_provisioner_client_mainfd(int epollfd, prov_client_t *client,
        char *identifier);
void disconnect_provisioner_client(int epollfd, prov_client_t *client,
        char *identifier);
void destroy_provisioner_client(int epollfd, prov_client_t *client,
        char *identifier);
int accept_provisioner_client(openli_ssl_config_t *sslconf, int epollfd,
                char *identifier, prov_client_t *client, int newfd,
                int successfdtype, int waitfdtype);

int continue_provisioner_client_handshake(int epollfd, prov_client_t *client,
        prov_sock_state_t *cs);
int halt_provisioner_client_idletimer(int epollfd, prov_client_t *client,
        char *identifier);
int halt_provisioner_client_authtimer(int epollfd, prov_client_t *client,
        char *identifier);
void start_provisioner_client_authtimer(int epollfd, prov_client_t *client,
        char *identifier, int timeoutsecs);
void start_provisioner_client_idletimer(int epollfd, prov_client_t *client,
        char *identifier, int timeoutsecs);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
