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

#ifndef OPENLI_TLS_H_
#define OPENLI_TLS_H_

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <amqp_tcp_socket.h>

typedef struct openli_ssl_config {
    char *keyfile;
    char *cacertfile;
    char *certfile;
    SSL_CTX *ctx;
} openli_ssl_config_t;

enum {
    OPENLI_SSL_CONNECT_FAILED,
    OPENLI_SSL_CONNECT_SUCCESS,
    OPENLI_SSL_CONNECT_WAITING,
    OPENLI_SSL_CONNECT_NOSSL
};

typedef struct openli_RMQ_config {
    char *name;
    char *pass;
    char *hostname;
    int port;
    int heartbeatFreq;
    int enabled;
    int SSLenabled;
} openli_RMQ_config_t;

int create_ssl_context(openli_ssl_config_t *sslconf);
void free_ssl_config(openli_ssl_config_t *sslconf);
int reload_ssl_config(openli_ssl_config_t *current,
        openli_ssl_config_t *newconf);
int listen_ssl_socket(openli_ssl_config_t *sslconf, SSL **ssl, int newfd);

int load_pem_into_memory(char *pemfile, char **memspace);
#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

