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

#include <sys/timerfd.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "logger.h"
#include "util.h"

int connect_socket(char *ipstr, char *portstr, uint8_t isretry) {

    struct addrinfo hints, *res;
    int sockfd;

    if (ipstr == NULL || portstr == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: Error trying to connect to remote host -- host IP or port is not set.");
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(ipstr, portstr, &hints, &res) == -1) {
        logger(LOG_DAEMON, "OpenLI: Error while trying to look up %s:%s -- %s.",
                ipstr, portstr, strerror(errno));
        return -1;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (sockfd == -1) {
        logger(LOG_DAEMON, "OpenLI: Error while creating connecting socket: %s.",
                strerror(errno));
        goto endconnect;
    }

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
        if (!isretry) {
            logger(LOG_DAEMON,
                    "OpenLI: Failed to connect to %s:%s -- %s.",
                    ipstr, portstr, strerror(errno));
            logger(LOG_DAEMON, "OpenLI: Will retry connection periodically.");
        }

        close(sockfd);
        sockfd = 0;     // a bit naughty to use 0 like this
        goto endconnect;
    }

    logger(LOG_DAEMON, "OpenLI: connected to %s:%s successfully.",
            ipstr, portstr);
endconnect:
    freeaddrinfo(res);
    return sockfd;
}

int create_listener(char *addr, char *port, char *name) {
    struct addrinfo hints, *res;
    int sockfd;
    int yes = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (addr == NULL) {
        hints.ai_flags = AI_PASSIVE;
    }

    if (getaddrinfo(addr, port, &hints, &res) == -1)
    {
        logger(LOG_DAEMON, "OpenLI: Error while trying to getaddrinfo for %s listening socket.", name);
        return -1;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (sockfd == -1) {
        logger(LOG_DAEMON,
                "OpenLI: Error while creating %s listening socket: %s.",
                name, strerror(errno));
        goto endlistener;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: Error while setting options on %s listening socket: %s",
				name, strerror(errno));
        close(sockfd);
        sockfd = -1;
        goto endlistener;
    }


    if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: Error while trying to bind %s listening socket: %s.",
                name, strerror(errno));
        close(sockfd);
        sockfd = -1;
        goto endlistener;
    }

    if (listen(sockfd, 10) == -1) {
        logger(LOG_DAEMON,
                "OpenLI: Error while listening on %s socket: %s.",
                name, strerror(errno));
        close(sockfd);
        sockfd = -1;
        goto endlistener;
    }
    logger(LOG_DAEMON, "OpenLI: %s listening on %s:%s successfully.",
            name, addr, port);
endlistener:
    freeaddrinfo(res);
    return sockfd;
}

char *sockaddr_to_string(struct sockaddr *sa, char *str, int len) {

    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), str,
                    len);
            break;
        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), str,
                    len);
            break;
        default:
            snprintf(str, len, "(unprintable)");
            break;
    }
    return str;
}

int epoll_add_timer(int epoll_fd, uint32_t secs, void *ptr) {
    int timerfd;
    struct epoll_event ev;
    struct itimerspec its;

    ev.data.ptr = ptr;
    ev.events = EPOLLIN;

    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = secs;
    its.it_value.tv_nsec = 0;

    timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
    timerfd_settime(timerfd, 0, &its, NULL);

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timerfd, &ev) == -1) {
        return -1;
    }

    return timerfd;
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

