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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <libwandder_etsili.h>

#include "logger.h"
#include "export_buffer.h"
#include "netcomms.h"

#define BUFFER_ALLOC_SIZE (1024 * 1024 * 50)
#define BUFFER_WARNING_THRESH (1024 * 1024 * 1024)

void init_export_buffer(export_buffer_t *buf) {
    buf->bufhead = NULL;
    buf->buftail = NULL;
    buf->alloced = 0;
    buf->partialfront = 0;
    buf->deadfront = 0;
    buf->nextwarn = BUFFER_WARNING_THRESH;
    buf->record_offsets = NULL;
}

void release_export_buffer(export_buffer_t *buf) {
    Word_t rc;
    J1FA(rc, buf->record_offsets);
    free(buf->bufhead);
}

uint64_t get_buffered_amount(export_buffer_t *buf) {
    return (buf->buftail - (buf->bufhead + buf->deadfront));
}


static inline void dump_buffer_offsets(export_buffer_t *buf) {

    Word_t index = 0;
    int rcint;

    J1F(rcint, buf->record_offsets, index);
    fprintf(stderr, "Offsets: ");
    while(rcint) {
        fprintf(stderr, "%lu ", index);
        J1N(rcint, buf->record_offsets, index);
    }
    fprintf(stderr, "\n");
}

static inline int slide_buffer(export_buffer_t *buf, uint8_t *start,
        uint64_t amount) {

    uint64_t slide = start - buf->bufhead;
    Word_t index = 0;
    int rcint, x;

    if (amount == 0) {
        J1FA(rcint, buf->record_offsets);
        return 0;
    }

    memmove(buf->bufhead, start, amount);

    J1F(rcint, buf->record_offsets, index);
    while (rcint) {
        J1U(x, buf->record_offsets, index);
        if (index >= slide) {
            J1S(x, buf->record_offsets, index - slide);
        }
        J1N(rcint, buf->record_offsets, index);
    }
    return 0;
}

static inline uint64_t extend_buffer(export_buffer_t *buf) {

    /* Add some space to the buffer */
    uint8_t *space = NULL;
    uint64_t bufused = buf->buftail - (buf->bufhead + buf->deadfront);

    if (buf->deadfront > 0) {
        slide_buffer(buf, buf->bufhead + buf->deadfront, bufused);
    }

    space = (uint8_t *)realloc(buf->bufhead, buf->alloced + BUFFER_ALLOC_SIZE);

    if (space == NULL) {
        /* OOM -- bad! */
        /* TODO: maybe dump to disk at this point? */
        logger(LOG_INFO, "OpenLI: no more free memory to use as buffer space!");
        logger(LOG_INFO, "OpenLI: fix the connection between your collector and your mediator.");
        return 0;
    }


    buf->deadfront = 0;
    buf->bufhead = space;
    buf->buftail = space + bufused;
    buf->alloced = buf->alloced + BUFFER_ALLOC_SIZE;

    if (buf->alloced - BUFFER_ALLOC_SIZE < buf->nextwarn &&
            buf->alloced >= buf->nextwarn) {
        /* TODO add email alerts */
        logger(LOG_INFO, "OpenLI: buffer space for missing mediator has exceeded warning threshold %lu.", buf->nextwarn);
        buf->nextwarn += BUFFER_WARNING_THRESH;
    }

    return buf->alloced - bufused;
}

uint64_t append_etsipdu_to_buffer(export_buffer_t *buf,
        uint8_t *pdustart, uint32_t pdulen, uint32_t beensent) {

    uint64_t bufused = buf->buftail - (buf->bufhead);
    uint64_t spaceleft = buf->alloced - bufused;
    int rcint;

    if (bufused == 0) {
        buf->partialfront = beensent;
    }

    while (spaceleft < pdulen) {
        spaceleft = extend_buffer(buf);
        if (spaceleft == 0) {
            return 0;
        }
    }

    memcpy(buf->buftail, (void *)pdustart, pdulen);
    J1S(rcint, buf->record_offsets, bufused);

    buf->buftail += pdulen;
    return (buf->buftail - buf->bufhead);

}

uint64_t append_message_to_buffer(export_buffer_t *buf,
        openli_encoded_result_t *res, uint32_t beensent) {

    uint32_t enclen = res->msgbody->len - res->ipclen;
    uint64_t bufused = buf->buftail - buf->bufhead;
    uint64_t spaceleft = buf->alloced - bufused;

    int liidlen;

    if (res->liid == NULL) {
        return 0;
    }

    liidlen = strlen(res->liid);

    if (bufused == 0) {
        buf->partialfront = beensent;
    }

    while (spaceleft < res->msgbody->len + sizeof(res->header) + liidlen + 2) {
        /* Add some space to the buffer */
        spaceleft = extend_buffer(buf);
        if (spaceleft == 0) {
            return 0;
        }
    }

    memcpy(buf->buftail, &res->header, sizeof(res->header));
    buf->buftail += sizeof(res->header);

    if (res->liid) {
        uint16_t l = htons(liidlen);
        memcpy(buf->buftail, &l, sizeof(uint16_t));
        memcpy(buf->buftail + 2, res->liid, liidlen);
        buf->buftail += (liidlen + 2);
    }

    if (res->isDer){
        if (enclen > 0) {
            memcpy(buf->buftail, res->msgbody->encoded, enclen);
            buf->buftail += enclen;
        }

        if (res->ipclen > 0) {
            memcpy(buf->buftail, res->ipcontents, res->ipclen);
            buf->buftail += res->ipclen;
        }
    }
    else {
        memcpy(buf->buftail, res->msgbody->encoded, res->msgbody->len);
        buf->buftail += res->msgbody->len;
        //BER has the payload already encoded into the result, DER leaves the payload out untill now
        //BER has a set of trailing ending octets (number varies by msg type)
    }

    return (buf->buftail - buf->bufhead);
}

int transmit_heartbeat(int fd, SSL *ssl) {
    ii_header_t hbeat;
    char *ptr;
    int ret;
    int tosend = sizeof(hbeat);

    hbeat.magic = htonl(OPENLI_PROTO_MAGIC);
    hbeat.bodylen = 0;
    hbeat.intercepttype = htons((uint16_t)OPENLI_PROTO_HEARTBEAT);
    hbeat.internalid = 0;

    ptr = (char *)(&hbeat);
    while (tosend > 0) {
        if (ssl) {
            ret = SSL_write(ssl, ptr, tosend);
            if (ret <= 0 ) {
                char errstring[128];
                int errr = SSL_get_error(ssl, ret);
                if (errr == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                logger(LOG_INFO,
                        "OpenLI: ssl_write error (%d) when sending heartbeat: %s",
                        errr, ERR_error_string(ERR_get_error(), errstring));
                return -1;
            }
        } else {
            ret = send(fd, ptr, tosend, MSG_DONTWAIT);
            if (ret < 0) {
                if (errno != EAGAIN) {
                    logger(LOG_INFO,
                            "OpenLI: error while sending heartbeat: %s",
                            strerror(errno));
                    return -1;
                }
                continue;
            }
        }

        tosend -= ret;
        ptr += ret;
    }
    return (int)(sizeof(hbeat));
}

static inline void post_transmit(export_buffer_t *buf) {

    uint64_t rem = 0;
    uint8_t *newbuf = NULL;
    uint64_t resize = 0;

    assert(buf->buftail >= buf->bufhead + buf->deadfront);
    rem = (buf->buftail - (buf->bufhead + buf->deadfront));

    /* Consider shrinking buffer if it is now way too large */
    if (rem < buf->alloced / 2 && buf->alloced > 10 * BUFFER_ALLOC_SIZE) {

        resize = ((rem / BUFFER_ALLOC_SIZE) + 1) * BUFFER_ALLOC_SIZE;
        slide_buffer(buf, buf->bufhead + buf->deadfront + buf->partialfront,
                rem);
        newbuf = (uint8_t *)realloc(buf->bufhead, resize);
        buf->buftail = newbuf + rem;
        buf->bufhead = newbuf;
        buf->alloced = resize;
        buf->deadfront = 0;
    } else if (buf->alloced - (buf->buftail - buf->bufhead) <
            0.25 * buf->alloced && buf->deadfront >= 0.25 * buf->alloced) {
        slide_buffer(buf, buf->bufhead + buf->deadfront + buf->partialfront,
                rem);
        buf->buftail = buf->bufhead + rem;
        assert(buf->buftail < buf->bufhead + buf->alloced);
        buf->deadfront = 0;
    }

    buf->partialfront = 0;
}

int transmit_buffered_records(export_buffer_t *buf, int fd,
        uint64_t bytelimit, SSL *ssl) {

    uint64_t sent = 0;
    uint8_t *bhead = buf->bufhead + buf->deadfront;
    uint64_t offset = buf->partialfront;
    int ret, rcint;
    Word_t index;

    sent = (buf->buftail - (bhead + offset));

    if (sent > bytelimit) {
        index = bytelimit + 1;
        J1P(rcint, buf->record_offsets, index);
        if (rcint == 0) {
            return 0;
        }
        sent = index;
    }

    if (sent != 0) {

        if (ssl != NULL) {
            while (1) {
                ret = SSL_write(ssl, bhead + offset, (int)sent);

                if ((ret) <= 0 ) {
                    char errstring[128];
                    int errr = SSL_get_error(ssl, ret);
                    if (errr == SSL_ERROR_WANT_WRITE) {
                        continue;
                    }
                    logger(LOG_INFO,
                            "OpenLI: ssl_write error (%d) in export_buffer: %s",
                            errr, ERR_error_string(ERR_get_error(), errstring));
                    return -1;
                }
                break;
            }
        }
        else {
            ret = send(fd, bhead + offset, (int)sent, MSG_DONTWAIT);
        }

        if (ret < 0) {
            if (errno != EAGAIN) {
                return -1;
            }
            return 0;
        } else if (ret < sent) {
            /* Partial send, move partialfront ahead by whatever we did send. */
            buf->partialfront += (uint32_t)ret;
            return ret;
        }
        buf->deadfront += ((uint32_t)ret + buf->partialfront);
    }

    post_transmit(buf);
    return sent;
}

int transmit_buffered_records_RMQ(export_buffer_t *buf, 
        amqp_connection_state_t amqp_state, amqp_channel_t channel, 
        amqp_bytes_t exchange, amqp_bytes_t routing_key,
        uint64_t bytelimit) {

    uint64_t sent = 0;
    uint64_t rem = 0;
    uint8_t *bhead = buf->bufhead + buf->deadfront;
    uint64_t offset = buf->partialfront;
    int ret;
    ii_header_t *header = NULL;

    sent = (buf->buftail - (bhead + offset));

    if (sent > bytelimit) {
        sent = bytelimit;
    }

    if (sent != 0) {
        amqp_bytes_t message_bytes;
        amqp_basic_properties_t props;
        message_bytes.len = sent;
        message_bytes.bytes = bhead + offset;

        props._flags = AMQP_BASIC_DELIVERY_MODE_FLAG;
        props.delivery_mode = 2;        /* persistent mode */

        int pub_ret = amqp_basic_publish(
                amqp_state,
                channel,
                exchange,
                routing_key,
                0,
                0,
                &props,
                message_bytes);

        if ( pub_ret != 0 ){
            logger(LOG_INFO,
                    "OpenLI: RMQ publish error %d", pub_ret);
        } else {
            ret = sent;
        }

        buf->deadfront += ((uint32_t)ret + buf->partialfront);
    }

    post_transmit(buf);
    return sent;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
