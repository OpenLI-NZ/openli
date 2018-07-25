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
#include <netinet/tcp.h>
#include <stdio.h>

#include "logger.h"
#include "util.h"

int connect_socket(char *ipstr, char *portstr, uint8_t isretry,
        uint8_t setkeepalive) {

    struct addrinfo hints, *res;
    int sockfd;
    int optval;
    socklen_t optlen;

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

    if (setkeepalive) {
        optval = 1;
        optlen = sizeof(optval);

        if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
            logger(LOG_DAEMON, "OpenLI: Unable to set keep alive SO for socket: %s.",
                    strerror(errno));
            goto endconnect;
        }

        optval = 30;
        if (setsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
            logger(LOG_DAEMON, "OpenLI: Unable to set keep alive idle SO for socket: %s.",
                    strerror(errno));
            goto endconnect;
        }

        if (setsockopt(sockfd, SOL_TCP, TCP_KEEPINTVL, &optval, optlen) < 0) {
            logger(LOG_DAEMON, "OpenLI: Unable to set keep alive interval SO for socket: %s.",
                    strerror(errno));
            goto endconnect;
        }

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

uint8_t *sockaddr_to_key(struct sockaddr *sa, int *socklen) {

    switch(sa->sa_family) {
        case AF_INET:
            *socklen = sizeof(struct in_addr);
            return (uint8_t *)(&(((struct sockaddr_in *)sa)->sin_addr));
        case AF_INET6:
            *socklen = sizeof(struct in6_addr);
            return (uint8_t *)(&(((struct sockaddr_in6 *)sa)->sin6_addr));
        default:
            return NULL;
    }
    return NULL;
}

void convert_ipstr_to_sockaddr(char *knownip,
        struct sockaddr_storage **saddr, int *family) {

    struct addrinfo *res = NULL;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(knownip, NULL, &hints, &res) != 0) {
        logger(LOG_DAEMON, "OpenLI: getaddrinfo cannot parse IP address %s: %s",
                knownip, gai_strerror(errno));
    }

    *family = res->ai_family;
    *saddr = (struct sockaddr_storage *)malloc(
            sizeof(struct sockaddr_storage));
    memcpy(*saddr, res->ai_addr, res->ai_addrlen);

    freeaddrinfo(res);
}

int sockaddr_match(int family, struct sockaddr *a, struct sockaddr *b) {

    if (family == AF_INET) {
        struct sockaddr_in *sa, *sb;
        sa = (struct sockaddr_in *)a;
        sb = (struct sockaddr_in *)b;

        if (sa->sin_addr.s_addr == sb->sin_addr.s_addr) {
            return 1;
        }
        return 0;
    }

    if (family == AF_INET) {
        struct sockaddr_in6 *s6a, *s6b;
        s6a = (struct sockaddr_in6 *)a;
        s6b = (struct sockaddr_in6 *)b;

        if (memcmp(s6a->sin6_addr.s6_addr, s6b->sin6_addr.s6_addr, 16) == 0) {
            return 1;
        }
        return 0;
    }

    return 0;
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

int extract_ip_addresses(libtrace_packet_t *pkt, uint8_t *srcip,
        uint8_t *destip, int *ipfamily) {

    void *ipheader;
    uint16_t ethertype;
    uint32_t  rem;
    /* Pre-requisite: srcip and destip point to at least 16 bytes of
     * usable memory.
     */
    if (srcip == NULL || destip == NULL) {
        return -1;
    }

    *ipfamily = 0;

    ipheader = trace_get_layer3(pkt, &ethertype, &rem);
    if (!ipheader || rem == 0) {
        return -1;
    }

    if (ethertype == TRACE_ETHERTYPE_IP) {
        libtrace_ip_t *ip4 = (libtrace_ip_t *)ipheader;

        if (rem < sizeof(libtrace_ip_t)) {
            return -1;
        }

        *ipfamily = AF_INET;
        memcpy(srcip, &(ip4->ip_src.s_addr), sizeof(uint32_t));
        memcpy(destip, &(ip4->ip_dst.s_addr), sizeof(uint32_t));
    } else {
        libtrace_ip6_t *ip6 = (libtrace_ip6_t *)ipheader;

        if (rem < sizeof(libtrace_ip6_t)) {
            return -1;
        }

        *ipfamily = AF_INET;
        memcpy(srcip, &(ip6->ip_src.s6_addr), sizeof(struct in6_addr));
        memcpy(destip, &(ip6->ip_dst.s6_addr), sizeof(struct in6_addr));
    }

    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

