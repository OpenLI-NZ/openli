/*
 *
 * Copyright (c) 2024, 2025 SearchLight Ltd, New Zealand.
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

#include "util.h"
#include "logger.h"
#include "collector.h"
#include "intercept.h"
#include "collector_sync.h"
#include "ipiri.h"
#include "alushim_parser.h"
#include "jmirror_parser.h"
#include "cisco_parser.h"

#include <zmq.h>
#include <unistd.h>
#include <arpa/inet.h>

typedef struct udp_sink_local {

    void *zmq_control;
    void *zmq_publish;

    char *listenaddr;
    char *listenport;
    int sockfd;
    int listen_family;

    char *expectedliid;
    openli_export_recv_t *cept;
    uint32_t dest_mediator;

    char *sourcehost;
    uint16_t sourceport;

    uint8_t direction;
    uint8_t encapfmt;
    uint32_t cin;

    uint8_t sourcereset;
    struct sockaddr_storage allowed_src;
    int allowed_family;

    uint8_t outformat;

} udp_sink_local_t;

static udp_sink_local_t *init_local_state(udp_sink_worker_args_t *args) {

    udp_sink_local_t *local = calloc(1, sizeof(udp_sink_local_t));
    char sockname[1024];
    int zero = 0, hwm = 1000, timeout=1000;

    local->zmq_publish = NULL;
    local->sockfd = -1;

    local->cept = NULL;
    local->dest_mediator = 0;
    local->outformat = OPENLI_EXPORT_IPCC;

    local->zmq_control = zmq_socket(args->zmq_ctxt, ZMQ_PULL);
    snprintf(sockname, 1024, "inproc://openliudpsink_sync-%s", args->key);

    if (zmq_connect(local->zmq_control, sockname) < 0) {
        logger(LOG_INFO,
                "OpenLI: UDP Sink worker %s failed to connect to control ZMQ: %s",
                args->key, strerror(errno));
        zmq_close(local->zmq_control);
        free(local);
        return NULL;
    }

    if (zmq_setsockopt(local->zmq_control, ZMQ_LINGER, &zero,
            sizeof(zero)) != 0) {
        logger(LOG_INFO,
                "OpenLI: UDP Sink worker %s failed to configure control ZMQ: %s",
                args->key, strerror(errno));
        zmq_close(local->zmq_control);
        free(local);
        return NULL;
    }

    local->zmq_publish = zmq_socket(args->zmq_ctxt, ZMQ_PUSH);
    snprintf(sockname, 1024, "inproc://openlipub-%d", args->trackerid);
    if (zmq_connect(local->zmq_publish, sockname) < 0) {
        logger(LOG_INFO,
                "OpenLI: UDP Sink worker %s failed to connect to publishing ZMQ %d: %s",
                args->key, args->trackerid, strerror(errno));
        zmq_close(local->zmq_control);
        zmq_close(local->zmq_publish);
        free(local);
        return NULL;
    }

    if (zmq_setsockopt(local->zmq_publish, ZMQ_LINGER, &zero,
            sizeof(zero)) != 0) {
        logger(LOG_INFO,
                "OpenLI: UDP Sink worker %s failed to configure publish ZMQ: %s",
                args->key, strerror(errno));
        zmq_close(local->zmq_publish);
        zmq_close(local->zmq_control);
        free(local);
        return NULL;
    }

    if (zmq_setsockopt(local->zmq_publish, ZMQ_SNDHWM, &hwm,
            sizeof(hwm)) != 0) {
        logger(LOG_INFO,
                "OpenLI: UDP Sink worker %s failed to configure publish ZMQ: %s",
                args->key, strerror(errno));
        zmq_close(local->zmq_publish);
        zmq_close(local->zmq_control);
        free(local);
        return NULL;
    }

    if (zmq_setsockopt(local->zmq_publish, ZMQ_SNDTIMEO, &timeout,
            sizeof(timeout)) != 0) {
        logger(LOG_INFO,
                "OpenLI: UDP Sink worker %s failed to configure publish ZMQ: %s",
                args->key, strerror(errno));
        zmq_close(local->zmq_publish);
        zmq_close(local->zmq_control);
        free(local);
        return NULL;
    }


    local->listenaddr = args->listenaddr;
    args->listenaddr = NULL;

    local->listenport = args->listenport;
    args->listenport = NULL;

    local->expectedliid = args->liid;
    args->liid = NULL;

    local->encapfmt = args->encapfmt;
    local->direction = args->direction;
    local->cin = args->cin;

    local->sourcehost = args->sourcehost;
    args->sourcehost = NULL;
    if (args->sourceport) {
        local->sourceport = strtoul(args->sourceport, NULL, 10);
    } else {
        local->sourceport = 0;
    }
    local->sourcereset = 1;
    return local;
}

static void cleanup_local_udp_sink(udp_sink_local_t *local) {
    if (local->sockfd != -1) {
        close(local->sockfd);
    }
    if (local->listenaddr) {
        free(local->listenaddr);
    }
    if (local->listenport) {
        free(local->listenport);
    }
    if (local->sourcehost) {
        free(local->sourcehost);
    }
    if (local->expectedliid) {
        free(local->expectedliid);
    }
    if (local->zmq_control) {
        zmq_close(local->zmq_control);
    }
    if (local->zmq_publish) {
        zmq_close(local->zmq_publish);
    }
    if (local->cept) {
        free_published_message(local->cept);
    }
    free(local);

}

static int bind_udp_sink_listener(udp_sink_local_t *local, char *key) {

    int sockfd, rv, lasterr;
    struct addrinfo hints, *res, *rp;
    int zero=0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    local->sockfd = -1;
    lasterr = 0;

    rv = getaddrinfo(local->listenaddr, local->listenport, &hints, &res);
    if (rv != 0) {
        logger(LOG_INFO, "OpenLI: error trying to call getaddrinfo in UDP sink worker: %s:%s -- %s", local->listenaddr, local->listenport, gai_strerror(rv));
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) {
            continue;
        }
        if (rp->ai_family == AF_INET6) {
            setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
        }
        if (bind(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            local->sockfd = sockfd;
            local->listen_family = rp->ai_family;
            break;
        }
        lasterr = errno;
        close(sockfd);
    }

    freeaddrinfo(res);
    if (lasterr != 0 && local->sockfd < 0) {
        logger(LOG_INFO, "OpenLI: UDP sink worker '%s' was unable to bind to its local address: %s\n", key, strerror(lasterr));
    }

    return local->sockfd;

}

static int apply_source_filter(udp_sink_local_t *local,
        struct sockaddr_storage *src) {

    if (local->sourcehost) {
        if (src->ss_family == AF_INET) {
            if (local->allowed_family != AF_INET) {
                return 0;
            }
            struct sockaddr_in *src4 = (struct sockaddr_in *)src;
            struct sockaddr_in *allow4 =
                    (struct sockaddr_in *)&(local->allowed_src);
            if (src4->sin_addr.s_addr != allow4->sin_addr.s_addr) {
                return 0;
            }
        } else {
            if (local->allowed_family != AF_INET6) {
                return 0;
            }
            struct sockaddr_in6 *src6 = (struct sockaddr_in6 *)src;
            struct sockaddr_in6 *allow6 =
                    (struct sockaddr_in6 *)&(local->allowed_src);
            if (memcmp(&(src6->sin6_addr), &(allow6->sin6_addr),
                    sizeof(struct in6_addr)) != 0) {
                return 0;
            }
        }
    }

    if (local->sourceport != 0) {
        if (src->ss_family == AF_INET) {
            struct sockaddr_in *src4 = (struct sockaddr_in *)src;
            if (src4->sin_port != htons(local->sourceport)) {
                return 0;
            }
        } else {
            struct sockaddr_in6 *src6 = (struct sockaddr_in6 *)src;
            if (src6->sin6_port != htons(local->sourceport)) {
                return 0;
            }
        }
    }

    return 1;
}

static int process_udp_datagram(udp_sink_local_t *local, char *key) {

    uint8_t recvbuf[65536];
    uint8_t *skipptr = NULL;
    ssize_t got = 0;
    uint32_t iplen;
    uint32_t cin;
    uint8_t dir;
    struct sockaddr_storage src;
    socklen_t srclen = sizeof(src);

    openli_export_recv_t *job;

    got = recvfrom(local->sockfd, recvbuf, 65536, 0, (struct sockaddr *)&src,
            &srclen);
    if (got < 0) {
        logger(LOG_INFO,
                "OpenLI: error while receiving UDP datagram in sink thread '%s': %s", key, strerror(errno));
        return -1;
    }

    if (got > 65535) {
        logger(LOG_INFO,
                "OpenLI: UDP sink thread '%s' received excessively large datagram, skipping because it is probably invalid", key);
        return 0;
    }

    if (local->sourcereset && local->sourcehost) {
        if (strchr(local->sourcehost, ':')) {
            struct sockaddr_in6 *in6 =
                    (struct sockaddr_in6 *)&(local->allowed_src);
            in6->sin6_family = AF_INET6;
            inet_pton(AF_INET6, local->sourcehost, &in6->sin6_addr);
            in6->sin6_port = htons(local->sourceport);
            local->allowed_family = AF_INET6;
        } else {
            struct sockaddr_in *in4 =
                    (struct sockaddr_in *)&(local->allowed_src);
            in4->sin_family = AF_INET;
            inet_pton(AF_INET, local->sourcehost, &in4->sin_addr);
            in4->sin_port = htons(local->sourceport);
            local->allowed_family = AF_INET;
        }
        local->sourcereset = 0;
    }

    if (!local->zmq_publish) {
        return 0;
    }

    if (local->dest_mediator == 0 || local->cept == NULL) {
        /* Haven't received details about the intercept yet */
        return 0;
    }

    /*
     * Not the fastest option, as all packets received still end up
     * hitting userspace, but still the most flexible (i.e. allows us
     * to make either the host or port optional)
     *
     * Alternatives:
     *   eBPF -- complex, tricky to support flexibility programatically
     *   connect() -- must always limit to a single source port
     *   firewall -- not something we should touch from within OpenLI but
     *               we should strongly recommend to deployers
     */
    if (apply_source_filter(local, &src) == 0) {
        return 0;
    }

    if (local->encapfmt == INTERCEPT_UDP_ENCAP_FORMAT_RAW) {
        // no encapsulation header
        skipptr = recvbuf;
        iplen = (uint32_t)got;
        cin = local->cin;
        dir = local->direction;
    } else if (local->encapfmt == INTERCEPT_UDP_ENCAP_FORMAT_NOKIA) {
        uint32_t shimintid = 0;
        skipptr = decode_alushim_from_udp_payload(recvbuf, got, &cin, &dir,
                &shimintid, &iplen, 0);
        if (skipptr == NULL) {
            return 0;
        }
    } else if (local->encapfmt == INTERCEPT_UDP_ENCAP_FORMAT_NOKIA_L3) {
        uint32_t shimintid = 0;
        skipptr = decode_alushim_from_udp_payload(recvbuf, got, &cin, &dir,
                &shimintid, &iplen, 1);
        if (skipptr == NULL) {
            return 0;
        }

    } else if (local->encapfmt == INTERCEPT_UDP_ENCAP_FORMAT_JMIRROR) {
        uint32_t shimintid = 0;
        skipptr = decode_jmirror_from_udp_payload(recvbuf, got, &cin,
                &shimintid, &iplen);
        if (skipptr == NULL) {
            return 0;
        }
        dir = local->direction;
    } else if (local->encapfmt == INTERCEPT_UDP_ENCAP_FORMAT_CISCO) {
        uint32_t shimintid = 0;
        skipptr = decode_cisco_from_udp_payload(recvbuf, got, &shimintid,
                &iplen);
        if (skipptr == NULL) {
            return 0;
        }
        dir = local->direction;
        cin = local->cin;
    } else {
        return 0;
    }

    if (local->outformat == OPENLI_EXPORT_RAW_CC) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        job = create_rawip_job_from_ip(local->expectedliid,
                local->dest_mediator, skipptr, iplen, tv,
                OPENLI_EXPORT_RAW_CC);
    } else {
        if (cin == 0) {
            // no useful CIN was configured, just use '1' in its place
            cin = 1;
        }
        job = create_ipcc_job_from_ipcontent(skipptr, iplen,
                local->expectedliid, cin, dir, local->dest_mediator);
    }

    if (!job) {
        return -1;
    }

    publish_openli_msg(local->zmq_publish, job);
    return 0;
}

static int process_control_message(udp_sink_local_t *local, char *key) {
    openli_export_recv_t *msg;
    int x;

    do {
        x = zmq_recv(local->zmq_control, &msg, sizeof(msg), ZMQ_DONTWAIT);
        if (x < 0 && errno != EAGAIN) {
            logger(LOG_INFO,
                    "OpenLI: error receiving message on control socket in UDP sink worker '%s': %s", key, strerror(errno));
            return -1;
        }
        if (x <= 0) {
            break;
        }

        if (msg->type == OPENLI_EXPORT_HALT) {
            free_published_message(msg);
            return -1;
        }

        if (msg->type == OPENLI_EXPORT_INTERCEPT_DETAILS ||
                msg->type == OPENLI_EXPORT_INTERCEPT_CHANGED) {
            if (strcmp(local->expectedliid, msg->data.cept.liid) != 0) {
                logger(LOG_INFO,
                        "OpenLI: UDP sink worker '%s' was expecting to be responsible for intercept '%s', but it was provided details for '%s'?",
                        key, local->expectedliid, msg->data.cept.liid);
                free_published_message(msg);
                return -1;
            }
            if (local->cept != NULL &&
                    msg->type == OPENLI_EXPORT_INTERCEPT_DETAILS) {
                logger(LOG_INFO,
                        "OpenLI: UDP sink worker '%s' has received multiple intercept announcements -- this is not supported behaviour!");
                logger(LOG_INFO,
                        "OpenLI: the offending LIID is %s", msg->data.cept.liid);
                free_published_message(msg);
                continue;
            }
            if (local->cept) {
                free_published_message(local->cept);
            }
            local->dest_mediator = msg->destid;
            local->cept = msg;
            if (local->cept && local->cept->data.cept.targetagency &&
                    strcmp(local->cept->data.cept.targetagency, "pcapdisk")
                            == 0) {
                local->outformat = OPENLI_EXPORT_RAW_CC;
            } else {
                local->outformat = OPENLI_EXPORT_IPCC;
            }

            if (msg->type == OPENLI_EXPORT_INTERCEPT_DETAILS) {
                logger(LOG_INFO,
                        "OpenLI: UDP sink worker '%s' is now intercepting traffic for LIID %s", key, msg->data.cept.liid);
            }

        } else if (msg->type == OPENLI_EXPORT_UDP_SINK_ARGS) {
            // configuration change from the provisioner
            local->direction = msg->data.udpargs.direction;
            local->encapfmt = msg->data.udpargs.encapfmt;
            local->cin = msg->data.udpargs.cin;
            if (msg->data.udpargs.sourceport) {
                local->sourceport = strtoul(msg->data.udpargs.sourceport,
                        NULL, 10);
            } else {
                local->sourceport = 0;
            }
            local->sourcereset = 1;
            if (msg->data.udpargs.sourcehost &&
                    strcmp(msg->data.udpargs.sourcehost, "any") == 0) {
                if (local->sourcehost) {
                    free(local->sourcehost);
                }
                local->sourcehost = NULL;
            } else {
                if (local->sourcehost) {
                    free(local->sourcehost);
                }
                local->sourcehost = msg->data.udpargs.sourcehost;
                msg->data.udpargs.sourcehost = NULL;
            }
            free_published_message(msg);
        } else if (msg->type == OPENLI_EXPORT_INTERCEPT_CHANGED) {

            if (local->cept) {
                free_published_message(local->cept);
            }
            local->cept = msg;
            local->dest_mediator = msg->destid;
        } else if (msg->type == OPENLI_EXPORT_INTERCEPT_OVER) {
            if (strcmp(local->expectedliid, msg->data.cept.liid) != 0) {
                logger(LOG_INFO,
                        "OpenLI: UDP sink worker '%s' is responsible for intercept '%s', but it was told to cease interception for '%s'?",
                        key, local->expectedliid, msg->data.cept.liid);
                free_published_message(msg);
                continue;
            }

            free_published_message(msg);
            return -1;

        } else {
            // not a message we care about
            free_published_message(msg);
        }
    } while (x > 0);

    return 1;
}

static int udp_sink_main_loop(udp_sink_local_t *local, char *key) {

    int x, topoll_len;
    zmq_pollitem_t topoll[2];

    if (local->sockfd < 0) {
        if (bind_udp_sink_listener(local, key) < 0) {
            logger(LOG_INFO,
                    "OpenLI: error while binding listening socket in UDP sink worker '%s'", key);
            return -1;
        }
    }

    topoll[0].socket = local->zmq_control;
    topoll[0].events = ZMQ_POLLIN;

    if (local->sockfd >= 0) {
        topoll[1].socket = NULL;
        topoll[1].fd = local->sockfd;
        topoll[1].events = ZMQ_POLLIN;
        topoll_len = 2;
    } else {
        topoll_len = 1;
    }

    x = zmq_poll(topoll, topoll_len, 100);
    if (x < 0) {
        logger(LOG_INFO,
                "OpenLI: error in zmq_poll in UDP sink worker '%s': %s",
                key, strerror(errno));
        return -1;
    }

    if (topoll[0].revents & ZMQ_POLLIN) {
        x = process_control_message(local, key);
        if (x < 0) {
            return -1;
        }
    }

    if (topoll_len > 1 && topoll[1].revents & ZMQ_POLLIN) {
        x = process_udp_datagram(local, key);
        if (x < 0) {
            close(local->sockfd);
            local->sockfd = -1;
            return 0;
        }
    }

    return 1;
}

void *start_udp_sink_worker(void *arg) {

    udp_sink_worker_args_t *start = (udp_sink_worker_args_t *)arg;
    udp_sink_local_t *local;

    if (start == NULL) {
        pthread_exit(NULL);
    }

    local = init_local_state(start);
    if (local == NULL) {
        goto exitthread;
    }

    logger(LOG_INFO, "OpenLI: started UDP sink worker for '%s'", start->key);
    while (1) {
        if (udp_sink_main_loop(local, start->key) <= 0) {
            break;
        }
    }

exitthread:
    if (local) {
        cleanup_local_udp_sink(local);
    }

    logger(LOG_INFO, "OpenLI: halting UDP sink worker for '%s'", start->key);
    if (start->listenaddr) {
        free(start->listenaddr);
    }
    if (start->listenport) {
        free(start->listenport);
    }
    if (start->liid) {
        free(start->liid);
    }
    if (start->key) {
        free(start->key);
    }
    if (start->sourceport) {
        free(start->sourceport);
    }
    if (start->sourcehost) {
        free(start->sourcehost);
    }
    free(start);
    pthread_exit(NULL);
}
