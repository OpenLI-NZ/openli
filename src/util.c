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
#include <fcntl.h>
#include <pthread.h>
#include <assert.h>
#include <ctype.h>

#include "logger.h"
#include "util.h"

char *load_file_into_string(const char *filename, size_t limit) {
    FILE *fp = fopen(filename, "rb");
    size_t filelen = 0;
    char *buf;
    size_t res;

    if (!fp) {
        logger(LOG_INFO, "OpenLI: failed to open file '%s' for reading: %s",
                filename, strerror(errno));
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    filelen = ftell(fp);
    rewind(fp);

    if (limit != 0 && filelen > limit) {
        logger(LOG_INFO, "OpenLI: could not load file '%s' into memory -- file size %ld exceeds maximum allowed file size %zu",
                filename, filelen, limit);
        fclose(fp);
        return NULL;
    }

    buf = malloc(filelen + 1);
    if (!buf) {
        logger(LOG_INFO, "OpenLI: could not load file '%s' into memory -- file size %ld exceeds available memory",
                filename, filelen);
        fclose(fp);
        return NULL;
    }

    res = fread(buf, 1, filelen, fp);
    if (res < filelen) {
        if (feof(fp)) {
            logger(LOG_INFO, "OpenLI: unexpected end of file reached when loading '%s' into memory", filename);
        } else if (ferror(fp)) {
            logger(LOG_INFO, "OpenLI: error while loading file '%s' into memory", filename, strerror(errno));
            free(buf);
            fclose(fp);
            return NULL;
        }
    }
    buf[res] = '\0';
    fclose(fp);
    return buf;
}

void openli_copy_ipcontent(libtrace_packet_t *pkt, uint8_t **ipc,
        uint16_t *iplen) {

    void *l3;
    uint16_t ethertype;
    uint32_t rem;

    *ipc = NULL;
    *iplen = 0;

    l3 = trace_get_layer3(pkt, &ethertype, &rem);

    if (l3 == NULL || rem == 0) {
        return;
    }

	*ipc = malloc(rem);
	memcpy(*ipc, l3, rem);
	*iplen = rem;
}

int add_to_string_set(string_set_t **set, char *term) {

    string_set_t *toadd, *found;
    int termlen;

    if (set == NULL || term == NULL) {
        return -1;
    }

    termlen = strlen(term);
    HASH_FIND(hh, *set, term, termlen, found);
    if (found) {
        return 0;
    }

    toadd = calloc(1, sizeof(string_set_t));
    toadd->term = strdup(term);
    toadd->termlen = termlen;

    HASH_ADD_KEYPTR(hh, *set, toadd->term, toadd->termlen, toadd);
    return 1;
}

int search_string_set(string_set_t *set, char *term) {

    string_set_t *found;

    if (term == NULL) {
        return 0;
    }

    HASH_FIND(hh, set, term, strlen(term), found);
    if (found) {
        return 1;
    }
    return 0;
}

int remove_from_string_set(string_set_t **set, char *term) {

    string_set_t *found;
    if (term == NULL) {
        return 0;
    }

    HASH_FIND(hh, *set, term, strlen(term), found);
    if (found) {
        HASH_DELETE(hh, *set, found);
        free(found->term);
        free(found);
        return 1;
    }
    return 0;
}

void purge_string_set(string_set_t **set) {

    string_set_t *iter, *tmp;

    HASH_ITER(hh, *set, iter, tmp) {
        HASH_DELETE(hh, *set, iter);
        free(iter->term);
        free(iter);
    }

}

int connect_socket(char *ipstr, char *portstr, uint8_t isretry,
        uint8_t setkeepalive) {

    struct addrinfo hints, *res;
    int sockfd;
    int optval;
    int flags;
    int success = 0;
    fd_set fdset;
    socklen_t optlen;
    struct timeval tv;
    int so_error = 0;

    if (ipstr == NULL || portstr == NULL) {
        logger(LOG_INFO,
                "OpenLI: Error trying to connect to remote host -- host IP or port is not set.");
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(ipstr, portstr, &hints, &res) == -1) {
        logger(LOG_INFO, "OpenLI: Error while trying to look up %s:%s -- %s.",
                ipstr, portstr, strerror(errno));
        return -1;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (sockfd == -1) {
        logger(LOG_INFO, "OpenLI: Error while creating connecting socket: %s.",
                strerror(errno));
        goto failconnect;
    }

    if (setkeepalive) {
        optval = 1;
        optlen = sizeof(optval);

        if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
            logger(LOG_INFO, "OpenLI: Unable to set keep alive SO for socket: %s.",
                    strerror(errno));
            goto failconnect;
        }

        optval = 30;
        if (setsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
            logger(LOG_INFO, "OpenLI: Unable to set keep alive idle SO for socket: %s.",
                    strerror(errno));
            goto failconnect;
        }

        if (setsockopt(sockfd, SOL_TCP, TCP_KEEPINTVL, &optval, optlen) < 0) {
            logger(LOG_INFO, "OpenLI: Unable to set keep alive interval SO for socket: %s.",
                    strerror(errno));
            goto failconnect;
        }

    }

    if ((flags = fcntl(sockfd, F_GETFL, 0)) < 0) {
        logger(LOG_INFO, "OpenLI: unable to get socket flags for new socket.");
        goto failconnect;
    }


    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        logger(LOG_INFO, "OpenLI: unable to set non-blocking socket flags for new socket.");
        goto failconnect;
    }

    connect(sockfd, res->ai_addr, res->ai_addrlen);

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);

    if (select(sockfd + 1, NULL, &fdset, NULL, &tv) == 1) {
        socklen_t len = sizeof(so_error);

        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);

        if (so_error == 0) {
            success = 1;
        } else {
            success = 0;
        }
    } else {
        so_error = ETIMEDOUT;
        success = 0;
    }

    if (!success) {
        if (!isretry) {
            logger(LOG_INFO,
                    "OpenLI: Failed to connect to %s:%s -- %s.",
                    ipstr, portstr, strerror(so_error));
            logger(LOG_INFO, "OpenLI: Will retry connection periodically.");
        }

        close(sockfd);
        sockfd = 0;     // a bit naughty to use 0 like this
        goto endconnect;
    }


    if (fcntl(sockfd, F_SETFL, flags) < 0) {
        logger(LOG_INFO, "OpenLI: unable to reset socket flags for new socket.");
        goto failconnect;
    }

    goto endconnect;

failconnect:
    if (sockfd >= 0) {
        close(sockfd);
        sockfd = -1;
    }

endconnect:
    freeaddrinfo(res);
    return sockfd;
}

int create_listener(char *addr, char *port, const char *name) {
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
        logger(LOG_INFO, "OpenLI: Error while trying to getaddrinfo for %s listening socket.", name);
        return -1;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (sockfd == -1) {
        logger(LOG_INFO,
                "OpenLI: Error while creating %s listening socket: %s.",
                name, strerror(errno));
        goto endlistener;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
        logger(LOG_INFO,
                "OpenLI: Error while setting options on %s listening socket: %s",
				name, strerror(errno));
        close(sockfd);
        sockfd = -1;
        goto endlistener;
    }


    if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
        logger(LOG_INFO,
                "OpenLI: Error while trying to bind %s listening socket: %s.",
                name, strerror(errno));
        close(sockfd);
        sockfd = -1;
        goto endlistener;
    }

    if (listen(sockfd, 10) == -1) {
        logger(LOG_INFO,
                "OpenLI: Error while listening on %s socket: %s.",
                name, strerror(errno));
        close(sockfd);
        sockfd = -1;
        goto endlistener;
    }
    logger(LOG_INFO, "OpenLI: %s listening on %s:%s successfully.",
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
        logger(LOG_INFO, "OpenLI: getaddrinfo cannot parse IP address %s: %s",
                knownip, gai_strerror(errno));
    }

    *family = res->ai_family;
    *saddr = (struct sockaddr_storage *)calloc(1,
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

int epoll_add_ms_timer(int epoll_fd, uint32_t msecs, void *ptr) {
    int timerfd;
    struct epoll_event ev;
    struct itimerspec its;

    ev.data.ptr = ptr;
    ev.events = EPOLLIN;

    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = msecs / 1000;
    its.it_value.tv_nsec = (msecs % 1000) * 1000000;

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

        *ipfamily = AF_INET6;
        memcpy(srcip, &(ip6->ip_src.s6_addr), sizeof(struct in6_addr));
        memcpy(destip, &(ip6->ip_dst.s6_addr), sizeof(struct in6_addr));
    }

    return 0;
}

struct addrinfo *populate_addrinfo(char *ipstr, char *portstr,
        int socktype) {
    struct addrinfo hints, *res;
    int s;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    hints.ai_flags = AI_PASSIVE;

    s = getaddrinfo(ipstr, portstr, &hints, &res);
    if (s != 0) {
        logger(LOG_INFO,
                "OpenLI: error calling getaddrinfo on %s:%s: %s",
                ipstr, portstr, gai_strerror(s));
        return NULL;
    }

    return res;
}

uint32_t hash_liid(char *liid) {
    return hashlittle(liid, strlen(liid), 1572869);
}

void *get_udp_payload(libtrace_packet_t *packet, uint32_t *rem,
        uint16_t *sourceport, uint16_t *destport) {

    uint8_t proto;
    void *transport, *udppayload;
    libtrace_udp_t *udp;

    transport = trace_get_transport(packet, &proto, rem);
    if (*rem < sizeof(libtrace_udp_t) || transport == NULL) {
        return NULL;
    }
    if (proto != TRACE_IPPROTO_UDP) {
        return NULL;
    }

    udp = (libtrace_udp_t *)transport;
    if (sourceport) {
        *sourceport = ntohs(udp->source);
    }
    if (destport) {
        *destport = ntohs(udp->dest);
    }
    udppayload = trace_get_payload_from_udp((libtrace_udp_t *)transport,
            rem);
	return udppayload;
}

char *parse_iprange_string(char *ipr_str) {
	    int family = 0;

	char *parsed = NULL;

    if (ipr_str == NULL) {
        return NULL;
    }

    if (strchr(ipr_str, ':') != NULL) {
        family = AF_INET6;
    } else if (strchr(ipr_str, '.') != NULL) {
        family = AF_INET;
    } else {
        logger(LOG_INFO,
                "OpenLI: '%s' is not a valid prefix or IP address",
                ipr_str);
        return NULL;
    }
    if (strchr(ipr_str, '/') == NULL) {
        /* No slash, so assume /32 or /128 */
        int rlen = strlen(ipr_str) + 5;   /* '/128' + nul */
        parsed = (char *)calloc(1, rlen);
        snprintf(parsed, rlen - 1, "%s/%u", ipr_str,
                family == AF_INET ? 32 : 128);

    } else {
        parsed = strdup(ipr_str);
    }
    return parsed;

}

/** Decodes the LIID field that is prepended to each exported ETSI
 *  message by the collector.
 *
 *  Although the LIID is already present in the encoded ETSI, finding
 *  and decoding it from within an ETSI record is slow. Since we need
 *  it to know which agency to forward the record to, it is faster and
 *  easier to just have the collector put a copy of it in front of
 *  the record and read it straight from there.
 *
 *  @param etsimsg      A pointer to the start of the received ETSI
 *                      record.
 *  @param msglen       The length of the received ETSI record.
 *  @param space        A string buffer to copy the extracted LIID into.
 *  @param maxspace     The size of the 'space' buffer.
 *  @param liidlen[out] Set to contain the number of bytes to skip to reach
 *                      the start of the actual ETSI record.
 *
 *  @return a pointer to the first character of the extracted LIID.
 */
char *extract_liid_from_exported_msg(uint8_t *etsimsg,
        uint64_t msglen, unsigned char *space, int maxspace,
        uint16_t *liidlen) {

    uint16_t l;

    /* Format of the record with prepended LIID
     *
     * [ Length of LIID (2 bytes) ] | [ LIID ] | [ Actual ETSI record ]
     */

    /* LIID length is stored in network byte order */
    l = *(uint16_t *)(etsimsg);
    *liidlen = ntohs(l);

    /* Bounds checking, both on the message and available storage space */
    if (*liidlen > msglen - 2) {
        *liidlen = msglen - 2;
    }

    if (*liidlen > maxspace - 1) {
        *liidlen = maxspace - 1;
    }

    /* Copy the LIID into the storage space */
    memcpy(space, etsimsg + 2, *liidlen);
    space[*liidlen] = '\0';     // null-terminate!

    /* Update LIID length to include the 2 bytes of length. */
    *liidlen += sizeof(l);
    return (char *)space;
}

int hash_packet_info_fivetuple(packet_info_t *pinfo, int modulo) {

    char buf[300];
    int used = 0;
    char *ptr = buf;

    memcpy(ptr, &(pinfo->trans_proto), sizeof(pinfo->trans_proto));
    used += sizeof(pinfo->trans_proto);
    ptr = buf + used;
    assert(used < 256);

    if (pinfo->srcport < pinfo->destport) {
        memcpy(ptr, &(pinfo->srcport), sizeof(pinfo->srcport));
        used += sizeof(pinfo->srcport);
        ptr = buf + used;
        assert(used < 256);

        memcpy(ptr, &(pinfo->destport), sizeof(pinfo->destport));
        used += sizeof(pinfo->destport);
        ptr = buf + used;
        assert(used < 256);
    } else {
        memcpy(ptr, &(pinfo->destport), sizeof(pinfo->destport));
        used += sizeof(pinfo->destport);
        ptr = buf + used;
        assert(used < 256);

        memcpy(ptr, &(pinfo->srcport), sizeof(pinfo->srcport));
        used += sizeof(pinfo->srcport);
        ptr = buf + used;
        assert(used < 256);
    }


    if (pinfo->family == AF_INET) {
        struct sockaddr_in *in_src = (struct sockaddr_in *)&(pinfo->srcip);
        struct sockaddr_in *in_dst = (struct sockaddr_in *)&(pinfo->destip);

        if (memcmp(&(in_src->sin_addr), &(in_dst->sin_addr),
                    sizeof(struct in_addr)) < 0) {
            memcpy(ptr, &(in_src->sin_addr), sizeof(struct in_addr));
            used += sizeof(struct in_addr);
            ptr = buf+used;
            assert(used < 256);

            memcpy(ptr, &(in_dst->sin_addr), sizeof(struct in_addr));
            used += sizeof(struct in_addr);
            assert(used < 256);
        } else {
            memcpy(ptr, &(in_dst->sin_addr), sizeof(struct in_addr));
            used += sizeof(struct in_addr);
            ptr = buf+used;
            assert(used < 256);

            memcpy(ptr, &(in_src->sin_addr), sizeof(struct in_addr));
            used += sizeof(struct in_addr);
            assert(used < 256);
        }
    } else if (pinfo->family == AF_INET6) {
        struct sockaddr_in6 *in6_src = (struct sockaddr_in6 *)&(pinfo->srcip);
        struct sockaddr_in6 *in6_dst = (struct sockaddr_in6 *)&(pinfo->destip);

        if (memcmp(&(in6_src->sin6_addr), &(in6_dst->sin6_addr),
                    sizeof(struct in6_addr)) < 0) {

            memcpy(ptr, &(in6_src->sin6_addr), sizeof(struct in6_addr));
            used += sizeof(struct in6_addr);
            ptr = buf+used;
            assert(used < 256);

            memcpy(ptr, &(in6_dst->sin6_addr), sizeof(struct in6_addr));
            used += sizeof(struct in6_addr);
            ptr = buf+used;
            assert(used < 256);
        } else {
            memcpy(ptr, &(in6_dst->sin6_addr), sizeof(struct in6_addr));
            used += sizeof(struct in6_addr);
            ptr = buf+used;
            assert(used < 256);

            memcpy(ptr, &(in6_src->sin6_addr), sizeof(struct in6_addr));
            used += sizeof(struct in6_addr);
            ptr = buf+used;
            assert(used < 256);
        }
    }

    return hashlittle(buf, used, 12582917) % modulo;
}

libtrace_packet_t *openli_copy_packet(libtrace_packet_t *pkt) {
    libtrace_packet_t *copy;
    int caplen = trace_get_capture_length(pkt);
    int framelen = trace_get_framing_length(pkt);

    if (caplen == -1 || framelen == -1) {
        return NULL;
    }

    copy = (libtrace_packet_t *)malloc(sizeof(libtrace_packet_t));
    if (!copy) {
        logger(LOG_INFO, "OpenLI: out of memory while copying libtrace packet");
        exit(1);
    }

    copy->trace = pkt->trace;
    copy->buf_control = TRACE_CTRL_PACKET;
    copy->buffer = malloc(framelen + caplen);
    copy->type = pkt->type;
    copy->header = copy->buffer;
    copy->payload = ((char *)copy->buffer) + framelen;
    copy->order = pkt->order;
    copy->hash = pkt->hash;
    copy->error = pkt->error;
    copy->srcbucket = NULL;
    copy->fmtdata = NULL;
    copy->refcount = 0;
    copy->internalid = 0;
    copy->which_trace_start = pkt->which_trace_start;
    memset(&(copy->cached), 0, sizeof(libtrace_packet_cache_t));
    copy->cached.capture_length = caplen;
    copy->cached.framing_length = framelen;
    copy->cached.wire_length = -1;
    copy->cached.payload_length = -1;
    /* everything else in cached should be zero or NULL */

    pthread_mutex_init(&copy->ref_lock, NULL);
    memcpy(copy->header, pkt->header, framelen);
    memcpy(copy->payload, pkt->payload, caplen);

    return copy;
}

size_t openli_convert_hexstring_to_binary(const char *src, uint8_t *space,
        size_t maxspace) {

    const char *p = src;
    size_t i;
    if (space == NULL || src == NULL || maxspace == 0) {
        return 0;
    }

    for (i = 0; i < maxspace; i++) {
        int hi, lo;
        unsigned char c1 = (unsigned char)p[2*i];
        unsigned char c2;

        if (c1 == '\0') {
            break;
        }
        if (2 * i + 1 >= maxspace) {
            break;
        }
        c2 = (unsigned char)p[2*i + 1];
        if (c2 == '\0') {
            // uneven number of hex characters??
            break;
        }
        if (c1 >= '0' && c1 <= '9') hi = c1 - '0';
        else if (c1 >= 'a' && c1 <= 'f') hi = 10 + (c1 - 'a');
        else if (c1 >= 'A' && c1 <= 'F') hi = 10 + (c1 - 'A');
        else return 0;
        if (c2 >= '0' && c2 <= '9') lo = c2 - '0';
        else if (c2 >= 'a' && c2 <= 'f') lo = 10 + (c2 - 'a');
        else if (c2 >= 'A' && c2 <= 'F') lo = 10 + (c2 - 'A');
        else return 0;
        space[i] = (uint8_t)((hi << 4) | lo);
    }

    return i;
}

char *ltrim(char *s) {
    if (!s) {
        return NULL;
    }
    while (isspace((unsigned char)*s)) {
        s++;
    }
    return s;
}

char *rtrim(char *s) {
    char *end;
    if (!s) {
        return NULL;
    }
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        end --;
    }
    *(end + 1) = '\0';
    return s;
}
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

