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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <libwandder_etsili.h>

#include "logger.h"
#include "export_buffer.h"
#include "netcomms.h"

#define BUFFER_ALLOC_SIZE (UINT64_C(1024) * 1024 * 50)
#define BUFFER_WARNING_THRESH (UINT64_C(1024) * 1024 * 1024)
#define BUF_OFFSET_FREQUENCY (UINT64_C(1024) * 256)


static export_block_t *create_export_block(void) {
    export_block_t *block;
    int rcint;

    block = calloc(1, sizeof(export_block_t));
    if (block == NULL) {
        logger(LOG_INFO, "OpenLI: OOM when allocating new export buffer block");
        return NULL;
    }

    block->data = malloc(EXPORT_BLOCK_SIZE);
    if (block->data == NULL) {
        logger(LOG_INFO, "OpenLI: OOM while allocating new export buffer block");
        free(block);
        return NULL;
    }
    J1S(rcint, block->record_offsets, 0);

    return block;
}

static void free_export_block(export_block_t *block) {
    int rcint;

    if (!block) return;

    if (block->data) {
        free(block->data);
    }

    J1FA(rcint, block->record_offsets);
    free(block);
}

void init_export_buffer(export_buffer_t *buf) {
    buf->head = NULL;
    buf->tail = NULL;
    buf->reader = NULL;

    buf->total_alloced = 0;
    buf->total_buffered = 0;
    buf->max_total_bytes = 0;
    buf->deadwindow = 0;
    buf->nextwarn = BUFFER_WARNING_THRESH;
}

void set_export_buffer_max_bytes(export_buffer_t *buf, uint64_t size_limit) {
    buf->max_total_bytes = size_limit;
}

void set_export_buffer_ack_window(export_buffer_t *buf, uint64_t window) {
    buf->deadwindow = window;
}

void release_export_buffer(export_buffer_t *buf) {
    export_block_t *block = buf->head;
    export_block_t *tmp;

    while (block) {
        tmp = block;
        block = block->next;
        free_export_block(tmp);
    }

    init_export_buffer(buf);
}

uint64_t get_buffered_amount(export_buffer_t *buf) {
    return buf->total_buffered;
}

uint8_t *get_buffered_head(export_buffer_t *buf, uint64_t *rem) {

    while (buf->reader != NULL &&
            buf->reader->read_pos == buf->reader->write_pos &&
            buf->reader != buf->tail) {
        buf->reader = buf->reader->next;
    }

    if (buf->reader == NULL) {
        return NULL;
    }
    *rem = (buf->reader->write_pos - buf->reader->read_pos);
    if (*rem == 0) {
        return NULL;
    }
    return (buf->reader->data + buf->reader->read_pos);
}

void reset_export_buffer(export_buffer_t *buf) {
    export_block_t *blk;
    uint64_t rem = 0;

    if (buf == NULL || buf->head == NULL) {
        return;
    }

    buf->reader = buf->head;

    for (blk = buf->head; blk != NULL; blk = blk->next) {
        blk->read_pos = blk->dead_pos;
        rem += (blk->write_pos - blk->read_pos);
    }
    buf->total_buffered = rem;
    buf->retained_sent_bytes = 0;

}

void rewind_export_buffer(export_buffer_t *buf) {
    int rcint;
    Word_t index;
    uint32_t amount = 0;

    if (buf == NULL || buf->reader == NULL ||
            buf->reader->read_pos == buf->reader->write_pos) {
        return;
    }

    index = (Word_t)buf->reader->read_pos;
    J1T(rcint, buf->reader->record_offsets, index);
    if (rcint == 0) {
        J1P(rcint, buf->reader->record_offsets, index);

        if (rcint != 0) {
            amount = buf->reader->read_pos - (uint32_t)index;
            buf->reader->read_pos = (uint32_t)index;
            buf->total_buffered += amount;
        }
    }
}

static inline int add_new_block_to_export_buffer(export_buffer_t *buf) {
    export_block_t *blk = create_export_block();
    if (blk == NULL) {
        return 0;
    }

    if (buf->tail) {
        buf->tail->next = blk;
    } else {
        buf->head = blk;
        buf->reader = blk;
    }
    buf->tail = blk;
    buf->total_alloced += EXPORT_BLOCK_SIZE;
    return 1;
}

uint64_t append_etsipdu_to_buffer(export_buffer_t *buf,
        uint8_t *pdustart, uint32_t pdulen, uint64_t beensent UNUSED) {

    int rcint;
    if (buf->tail == NULL ||
            (EXPORT_BLOCK_SIZE - buf->tail->write_pos < pdulen)) {
        if (add_new_block_to_export_buffer(buf) == 0) {
            return 0;
        }
    }

    memcpy(buf->tail->data + buf->tail->write_pos, (void *)pdustart, pdulen);

    J1S(rcint, buf->tail->record_offsets, buf->tail->write_pos);
    buf->tail->write_pos += pdulen;
    buf->total_buffered += pdulen;
    return (buf->total_buffered);

}

uint64_t append_message_to_buffer(export_buffer_t *buf,
        openli_encoded_result_t *res, uint64_t beensent UNUSED) {

    uint32_t enclen = res->msgbody->len - res->ipclen;
    uint64_t added = 0, start;
    int rcint;

    if (buf->tail == NULL ||
            (EXPORT_BLOCK_SIZE - buf->tail->write_pos < res->msgbody->len + sizeof(res->header))) {
        if (add_new_block_to_export_buffer(buf) == 0) {
            return 0;
        }
    }

    start = buf->tail->write_pos;

    memcpy(buf->tail->data + buf->tail->write_pos, &res->header,
            sizeof(res->header));
    buf->tail->write_pos += sizeof(res->header);
    added += sizeof(res->header);

    if (enclen > 0) {
        memcpy(buf->tail->data + buf->tail->write_pos, res->msgbody->encoded,
                enclen);
        buf->tail->write_pos += enclen;
    }

    if (res->ipclen > 0) {
        memcpy(buf->tail->data + buf->tail->write_pos, res->ipcontents,
                res->ipclen);
        buf->tail->write_pos += res->ipclen;
    }
    added += res->msgbody->len;

    J1S(rcint, buf->tail->record_offsets, start);
    buf->total_buffered += added;
    return (buf->total_buffered);
}

uint64_t append_heartbeat_to_buffer(export_buffer_t *buf) {
    ii_header_t hbeat;
    int rcint;

    hbeat.magic = htonl(OPENLI_PROTO_MAGIC);
    hbeat.bodylen = 0;
    hbeat.intercepttype = htons((uint16_t)OPENLI_PROTO_HEARTBEAT);
    hbeat.internalid = 0;

    if (buf->tail == NULL ||
            (EXPORT_BLOCK_SIZE - buf->tail->write_pos < sizeof(hbeat))) {
        if (add_new_block_to_export_buffer(buf) == 0) {
            return 0;
        }
    }

    memcpy(buf->tail->data + buf->tail->write_pos, &hbeat, sizeof(hbeat));

    J1S(rcint, buf->tail->record_offsets, buf->tail->write_pos);
    buf->total_buffered += sizeof(hbeat);
    buf->tail->write_pos += sizeof(hbeat);

    return (buf->total_buffered);
}

static inline void post_transmit(export_buffer_t *buf) {
    uint64_t excess;
    uint32_t in_head;

    while (buf->head != NULL && buf->head != buf->tail &&
            buf->retained_sent_bytes > buf->deadwindow) {

        excess = buf->retained_sent_bytes - buf->deadwindow;
        in_head = buf->head->write_pos - buf->head->dead_pos;

        if (excess >= in_head) {
            export_block_t *blk = buf->head;
            buf->head = buf->head->next;
            buf->total_alloced -= EXPORT_BLOCK_SIZE;
            buf->retained_sent_bytes -= in_head;
            free_export_block(blk);
        } else {
            buf->head->dead_pos += (uint32_t) excess;
            buf->retained_sent_bytes -= excess;
            break;
        }
    }

    if (buf->head && buf->head == buf->tail) {
        if (buf->deadwindow == 0) {
            buf->head->dead_pos = buf->head->read_pos;
            buf->retained_sent_bytes = 0;
        } else if (buf->retained_sent_bytes > buf->deadwindow) {
            excess = buf->retained_sent_bytes - buf->deadwindow;
            buf->head->dead_pos += (uint32_t)excess;
            buf->retained_sent_bytes -= excess;
        }
    }

}

int transmit_buffered_records(export_buffer_t *buf, int fd,
        uint64_t bytelimit, SSL *ssl) {

    uint64_t total_sent = 0;
    uint64_t remaining_limit = bytelimit;

    while (get_buffered_amount(buf) > 0) {
        uint64_t sent = 0;
        uint8_t *bhead = buf->reader->data + buf->reader->read_pos;
        int ret, rcint;
        Word_t index = 0;

        sent = buf->reader->write_pos - buf->reader->read_pos;

        if (sent == 0 && buf->reader == buf->tail) {
            break;
        }

        if (sent == 0) {
            buf->reader = buf->reader->next;
            continue;
        }

        remaining_limit = bytelimit - total_sent;
        if (sent > remaining_limit) {
            index = buf->reader->read_pos + remaining_limit;
            J1P(rcint, buf->reader->record_offsets, index);
            if (rcint != 0 && index > buf->reader->read_pos) {
                sent = (uint64_t) index - buf->reader->read_pos;
            } else {
                sent = remaining_limit;
            }
        }

        if (ssl != NULL) {
            ret = SSL_write(ssl, bhead, (int)sent);

            if (ret <= 0) {
                char errstring[128];
                int errr = SSL_get_error(ssl, ret);
                if (errr == SSL_ERROR_WANT_WRITE ||
                        errr == SSL_ERROR_WANT_READ) {
                    return (int)total_sent;
                }
                logger(LOG_INFO,
                        "OpenLI: ssl_write error (%d) in export_buffer: %s",
                        errr, ERR_error_string(ERR_get_error(), errstring));
                return -1;
            }
        } else {
            ret = send(fd, bhead, (int)sent, MSG_DONTWAIT);

            if (ret < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    return -1;
                }
                return (int)total_sent;
            }
        }

        buf->reader->read_pos += (uint64_t)ret;
        total_sent += (uint64_t)ret;
        buf->total_buffered -= (uint64_t) ret;

        if ((uint64_t)ret < sent) {
            /* Partial send, something must have filled up */
        }

        buf->retained_sent_bytes += (uint64_t)ret;

        if (buf->reader->read_pos == buf->reader->write_pos &&
                buf->reader != buf->tail) {
            buf->reader = buf->reader->next;
        }

        post_transmit(buf);
        if (total_sent >= bytelimit) {
            break;
        }
    }

    return (int)total_sent;
}

int check_rmq_connection_block_status(amqp_connection_state_t amqp_state,
        uint8_t *is_blocked) {

    amqp_frame_t frame;
    struct timeval tv;
    int x, ret;

    tv.tv_sec = tv.tv_usec = 0;
    x = amqp_simple_wait_frame_noblock(amqp_state, &frame, &tv);

    if (x != AMQP_STATUS_OK && x != AMQP_STATUS_TIMEOUT) {
        logger(LOG_INFO,
                "OpenLI: unable to check status of collector RMQ publishing socket");
        return -1;
    }

    if (*is_blocked) {
        ret = 0;
    } else {
        ret = 1;
    }

    if (x == AMQP_STATUS_TIMEOUT) {
        return ret;
    }

    if (AMQP_FRAME_METHOD == frame.frame_type) {
        switch(frame.payload.method.id) {
            case AMQP_CONNECTION_BLOCKED_METHOD:
                if ((*is_blocked) == 0) {
                    logger(LOG_INFO,
                            "OpenLI: collector RMQ is unable to handle any more published ETSI records!");
                    logger(LOG_INFO,
                            "OpenLI: this is a SERIOUS problem -- OpenLI will buffer in memory for now, but this will only buy you a little time");
                }
                *is_blocked = 1;
                ret = 0;
                break;
            case AMQP_CONNECTION_UNBLOCKED_METHOD:
                if ((*is_blocked) == 1) {
                    logger(LOG_INFO,
                            "OpenLI: collector RMQ has become unblocked and will resume publishing ETSI records.");
                    ret = 0;
                } else {
                    ret = 1;
                }
                *is_blocked = 0;
                break;
            case AMQP_CONNECTION_CLOSE_METHOD:
                logger(LOG_INFO,
                        "OpenLI: 'close' exception occurred on the collector RMQ connection -- must restart connection");
                return -1;
            case AMQP_CHANNEL_CLOSE_METHOD:
                logger(LOG_INFO,
                        "OpenLI: channel exception occurred on the collector RMQ connection -- going to reset connection");
                return -1;
        }
    }
    return ret;
}


int transmit_buffered_records_RMQ(export_buffer_t *buf, 
        amqp_connection_state_t amqp_state, amqp_channel_t channel, 
        amqp_bytes_t exchange, amqp_bytes_t routing_key,
        uint64_t bytelimit, uint8_t *is_blocked) {

    uint64_t sent = 0;
    int pub_ret, ret, x, elapsed = 0, timeout = 3;
    amqp_frame_t frame;
    amqp_bytes_t message_bytes;
    amqp_basic_properties_t props;
    uint32_t unsent;
    struct timeval tv;

    while (buf->reader != NULL &&
            buf->reader->read_pos == buf->reader->write_pos &&
            buf->reader != buf->tail) {
        buf->reader = buf->reader->next;
    }


    if (buf->reader == NULL || buf->reader->read_pos >= buf->reader->write_pos)
    {
        return 0;
    }

    unsent = buf->reader->write_pos - buf->reader->read_pos;
    if (unsent > bytelimit) {
        sent = bytelimit;
    } else {
        sent = unsent;
    }

    if (sent == 0) {
        return sent;
    }

    message_bytes.len = sent;
    message_bytes.bytes = buf->reader->data + buf->reader->read_pos;

    props._flags = AMQP_BASIC_DELIVERY_MODE_FLAG;
    props.delivery_mode = 2;        /* persistent mode */
    ret = 0;

    if ((x = check_rmq_connection_block_status(amqp_state, is_blocked)) < 0) {
        return -1;
    }

    if (*is_blocked) {
        return 0;
    }

    pub_ret = amqp_basic_publish(
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
        return -1;
    }

    while (1) {
        tv.tv_sec = 1; tv.tv_usec = 0;
        ret = amqp_simple_wait_frame_noblock(amqp_state, &frame, &tv);
        if (ret == AMQP_STATUS_OK) {
            if (frame.frame_type == AMQP_FRAME_METHOD) {
                if (frame.payload.method.id == AMQP_BASIC_ACK_METHOD) {
                    break;
                }
                if (frame.payload.method.id == AMQP_BASIC_NACK_METHOD) {
                    return 0;
                }
                if (frame.payload.method.id == AMQP_CONNECTION_BLOCKED_METHOD) {
                    *is_blocked = 1;
                }
                if (frame.payload.method.id ==
                        AMQP_CONNECTION_UNBLOCKED_METHOD) {
                    *is_blocked = 0;
                }
                if (frame.payload.method.id ==
                        AMQP_CONNECTION_CLOSE_METHOD) {
                    return -1;
                }
                if (frame.payload.method.id ==
                        AMQP_CHANNEL_CLOSE_METHOD) {
                    return -1;
                }
            }
        } else if (ret == AMQP_STATUS_TIMEOUT) {
            elapsed ++;
        } else {
            logger(LOG_INFO,
                    "OpenLI collector: RMQ error while waiting for publisher confirm");
            return -1;
        }
        if (elapsed >= timeout) {
            /* Didn't see an ACK in a reasonable time frame, normally it
             * would make sense to assume that message wasn't published but
             * there are certain situations (usually after the RMQ broker
             * has been restarted) where RMQ won't produce acks for
             * re-published messages.
             * At this stage, we can't tell if what we are sending is a
             * republication. It is most likely, however,
             * that if 3 seconds have passed without an ACK or CLOSE result
             * then we are probably dealing with a broker that is not going
             * to acknowledge this message.
             */
            break;
        }
    }

    /* if we get here, the publish was successful and confirmed by the
     * broker (or we got no feedback from the broker and have to assume
     * a successful publication...)
     */
    buf->reader->read_pos += sent;
    buf->total_buffered -= sent;
    buf->retained_sent_bytes += sent;

    if (buf->reader->read_pos == buf->reader->write_pos &&
            buf->reader != buf->tail) {
        buf->reader = buf->reader->next;
    }

    post_transmit(buf);
    return 1;
}

int advance_export_buffer_head(export_buffer_t *buf, uint64_t amount) {

    uint64_t avail = 0;

    if (buf->reader == NULL) {
        return 0;
    }

    avail = buf->reader->write_pos - buf->reader->read_pos;

    if (amount > avail) {
        amount = avail;
    }

    /* This is only used in the pcap output context, so there's no real
     * need to maintain a retransmit window, so just set deadfront to
     * match the write offset.
     */
    buf->reader->read_pos += amount;
    buf->reader->dead_pos = buf->reader->read_pos;
    buf->total_buffered -= amount;

    if (buf->reader->read_pos == buf->reader->write_pos &&
            buf->reader != buf->tail) {
        buf->reader = buf->reader->next;
    }
    post_transmit(buf);
    return 0;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
