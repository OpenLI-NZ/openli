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
#include "collector.h"
#include "collector_export.h"
#include "export_buffer.h"
#include "netcomms.h"

#define BUFFER_ALLOC_SIZE (1024 * 1024 * 10)
#define BUFFER_WARNING_THRESH (1024 * 1024 * 1024)

void init_export_buffer(export_buffer_t *buf, uint8_t hasnetcomm) {
    buf->bufhead = NULL;
    buf->buftail = NULL;
    buf->alloced = 0;
    buf->partialfront = 0;
    buf->hasnetcomm = hasnetcomm;
}

void release_export_buffer(export_buffer_t *buf) {
    free(buf->bufhead);
}

uint64_t get_buffered_amount(export_buffer_t *buf) {
    return (buf->buftail - buf->bufhead);
}


static void validate_buffer(export_buffer_t *buf) {
    uint64_t sent = 0;
    uint64_t tocheck = buf->buftail - buf->bufhead;
    wandder_etsispec_t *dec = wandder_create_etsili_decoder();
    int ret;

    printf("\nVALIDATING %lu\n\n", tocheck);

    while (buf->bufhead + sent < buf->buftail) {
        uint32_t attachlen = 0;
        uint32_t pdulen = 0;

        if (buf->buftail - (buf->bufhead + sent) < 10000) {
            attachlen = buf->buftail - (buf->bufhead + sent);
        } else {
            attachlen = 10000;
        }

        printf("%lu ", sent);

        for (ret = 0; ret < 4; ret ++) {
            printf("%02x ", *(buf->bufhead + sent + ret));
        }
        wandder_attach_etsili_buffer(dec, buf->bufhead + sent, attachlen, 0);
        pdulen = wandder_etsili_get_pdu_length(dec);

        printf("%u\n", pdulen);

        if (pdulen == 0) {
            logger(LOG_DAEMON, "OpenLI: failed to decode buffered ETSI record.");
            assert(0);
            break;
        }
        sent += pdulen;
    }

    printf("\n");
}

static inline uint64_t extend_buffer(export_buffer_t *buf) {

    /* Add some space to the buffer */
    uint8_t *space = NULL;
    uint64_t bufused = buf->buftail - buf->bufhead;

    space = (uint8_t *)realloc(buf->bufhead, buf->alloced + BUFFER_ALLOC_SIZE);
    if (space == NULL) {
        /* OOM -- bad! */
        /* TODO: maybe dump to disk at this point? */
        logger(LOG_DAEMON, "OpenLI: no more free memory to use as buffer space!");
        logger(LOG_DAEMON, "OpenLI: fix the connection between your collector and your mediator.");
        return 0;
    }

    buf->bufhead = space;
    buf->buftail = space + bufused;
    buf->alloced = buf->alloced + BUFFER_ALLOC_SIZE;

    if (buf->alloced - BUFFER_ALLOC_SIZE < BUFFER_WARNING_THRESH &&
            buf->alloced >= BUFFER_WARNING_THRESH) {
        /* TODO add email alerts */
        logger(LOG_DAEMON, "OpenLI: buffer space for missing mediator has exceeded warning threshold.");
    }
    return buf->alloced - bufused;
}

uint64_t append_etsipdu_to_buffer(export_buffer_t *buf,
        uint8_t *pdustart, uint32_t pdulen, uint32_t beensent) {

    uint64_t bufused = buf->buftail - buf->bufhead;
    uint64_t spaceleft = buf->alloced - bufused;

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

    buf->buftail += pdulen;

    //validate_buffer(buf);
    return (buf->buftail - buf->bufhead);

}

uint64_t append_message_to_buffer(export_buffer_t *buf,
        openli_exportmsg_t *msg, uint32_t beensent) {

    uint32_t enclen = msg->msgbody->len - msg->ipclen;
    uint64_t bufused = buf->buftail - buf->bufhead;
    uint64_t spaceleft = buf->alloced - bufused;

    if (bufused == 0) {
        buf->partialfront = beensent;
    }

    while (spaceleft < msg->msgbody->len + msg->hdrlen) {
        spaceleft = extend_buffer(buf);
        if (spaceleft == 0) {
            return 0;
        }
        /* Add some space to the buffer */
    }

    if (msg->header) {
        ii_header_t *ii = (ii_header_t *)(msg->header);
        memcpy(buf->buftail, msg->header, msg->hdrlen);
        buf->buftail += msg->hdrlen;
    }
    memcpy(buf->buftail, msg->msgbody->encoded, enclen);

    buf->buftail += enclen;
    if (msg->ipclen > 0) {
        memcpy(buf->buftail, msg->ipcontents, msg->ipclen);
        buf->buftail += msg->ipclen;
    }

    //validate_buffer(buf);
    return (buf->buftail - buf->bufhead);
}

int transmit_buffered_records(export_buffer_t *buf, int fd,
        uint64_t bytelimit) {

    uint64_t sent = 0;
    uint64_t rem = 0;
    uint64_t offset = buf->partialfront;
    wandder_etsispec_t *dec;
    int ret;
    ii_header_t *header = NULL;

    if (!buf->hasnetcomm) {
        dec = wandder_create_etsili_decoder();
    }

    /* Try to maintain record alignment */
    while (buf->bufhead + sent < buf->buftail) {
        uint32_t attachlen = 0;
        uint32_t pdulen = 0;

        if (buf->buftail - (buf->bufhead + sent) < 10000) {
            attachlen = buf->buftail - (buf->bufhead + sent);
        } else {
            attachlen = 10000;
        }

        if (buf->hasnetcomm) {
            header = (ii_header_t *)(buf->bufhead + sent);
            pdulen = ntohs(header->bodylen) + sizeof(ii_header_t);
        } else {
            wandder_attach_etsili_buffer(dec, buf->bufhead + sent,
                    attachlen, 0);
            pdulen = wandder_etsili_get_pdu_length(dec);
            if (pdulen == 0) {
                logger(LOG_DAEMON, "OpenLI: failed to decode buffered ETSI record.");
                assert(0);
                break;
            }
        }

        if (sent + pdulen > bytelimit) {
            break;
        }

        sent += pdulen;
    }

    if (!buf->hasnetcomm) {
        wandder_free_etsili_decoder(dec);
    }

    sent -= offset;
    if (sent != 0) {
        ret = send(fd, buf->bufhead + offset, (int)sent, MSG_DONTWAIT);
        if (ret < 0) {
            if (errno != EAGAIN) {
                logger(LOG_DAEMON,
                        "OpenLI: Error exporting to target from buffer: %s.",
                        strerror(errno));
                return -1;
            }
            return 0;
        } else if (ret < sent) {
            /* Partial send, move partialfront ahead by whatever we did send. */
            buf->partialfront += (uint32_t)ret;
            return ret;
        }
    }

    rem = (buf->buftail - (buf->bufhead + sent + offset));

    /* Consider shrinking buffer if it is now way too large */
    if (rem < buf->alloced / 2 && buf->alloced > 10 * BUFFER_ALLOC_SIZE) {

        uint8_t *newbuf = NULL;
        uint64_t resize = 0;
        resize = ((rem / BUFFER_ALLOC_SIZE) + 1) * BUFFER_ALLOC_SIZE;

        memmove(buf->bufhead, buf->bufhead + sent + offset, rem);
        newbuf = (uint8_t *)realloc(buf->bufhead, resize);
        buf->buftail = newbuf + rem;
        buf->bufhead = newbuf;
        buf->alloced = resize;
    } else {
        memmove(buf->bufhead, buf->bufhead + sent + offset, rem);
        buf->buftail = buf->bufhead + rem;
    }

    buf->partialfront = 0;
    return sent;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
