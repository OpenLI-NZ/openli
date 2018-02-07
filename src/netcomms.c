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
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#include <sys/types.h>
#include <sys/socket.h>

#include "netcomms.h"
#include "logger.h"
#include "byteswap.h"

net_buffer_t *create_net_buffer(net_buffer_type_t buftype, int fd) {

    net_buffer_t *nb = (net_buffer_t *)malloc(sizeof(net_buffer_t));
    nb->buf = (char *)malloc(NETBUF_ALLOC_SIZE);
    nb->appendptr = nb->buf;
    nb->actptr = nb->buf;
    nb->alloced = NETBUF_ALLOC_SIZE;
    nb->fd = fd;
    nb->buftype = buftype;
    return nb;
}

void destroy_net_buffer(net_buffer_t *nb) {
    free(nb->buf);
    free(nb);
}


#if 0
static char *extend_xmit_buffer(xmit_buffer_t *xmit) {

    int usedsofar = (xmit->writeptr - xmit->buf);

    xmit->buf = (char *)realloc(xmit->buf, xmit->alloced + XMIT_ALLOC_SIZE);
    if (xmit->buf == NULL) {
        logger(LOG_DAEMON, "OpenLI: OOM while forming IP Intercept Instruction.");
        return NULL;
    }

    xmit->alloced += XMIT_ALLOC_SIZE;
    xmit->writeptr = xmit->buf + usedsofar;

    return xmit->buf;

}

static inline char *populate_header(xmit_buffer_t *xmit, uint16_t inttype,
        uint64_t idnum) {
    ii_header_t *hdr = (ii_header_t *)p;

    if (WRITE_BUF_REM(xmit) < sizeof(ii_header_t)) {
        if (extend_xmit_buffer(xmit) == NULL) {
            return NULL;
        }
    }

    ii->magic = htonl(OPENLI_II_MAGIC);
    ii->bodylen = 0;        /* Placeholder */
    ii->intercepttype = htons(inttype);
    ii->internalid = byteswap_host_to_be(idnum);

    xmit->writeptr = (p + sizeof(ii_header_t));
    return xmit->writeptr;
}


static inline char *add_ii_field(xmit_buffer_t *xmit, uint16_t fieldtype,
        void *fieldval, uint16_t vallen) {

    uint16_t *ptr;

    while (WRITE_BUF_REM(xmit) < vallen + 4) {
        if (extend_xmit_buffer(xmit) == NULL) {
            return NULL;
        }
    }

    ptr = (uint16_t *)(xmit->writeptr);
    *ptr = htons(fieldtype);
    ptr ++;
    *ptr = htons(vallen);
    ptr ++;

    memcpy((char *)ptr, (char *)fieldval, vallen);

    xmit->writeptr += (vallen + 4);
    return xmit->writeptr;
}

int xmit_ipintercept(int fd, ipintercept_t *ipint) {

    xmit_buffer_t xmit;
    ii_header_t *hdr;
    int ret = 0;

    xmit.buf = (char *)malloc(4096);
    xmit.writeptr = buf;
    xmit.alloced = 4096;

    if (populate_header(&xmit, OPENLI_II_IPINTERCEPT, ipint->internalid)
                == NULL) {
        logger(LOG_DAEMON, "OpenLI: failed to populate IP intercept header.");
        ret = -1;
        goto xmitend;
    }

    if (add_ii_field(xmit, OPENLI_IPII_FIELD_LIID, ipint->liid,
                ipint->liid_len) == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: failed to write LIID into IP intercept message.");
        ret = -1;
        goto xmitend;
    }

    if (add_ii_field(xmit, OPENLI_IPII_FIELD_AUTHCC, ipint->authcc,
                ipint->authcc_len) == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: failed to write AuthCC into IP intercept message.");
        ret = -1;
        goto xmitend;
    }

    if (add_ii_field(xmit, OPENLI_IPII_FIELD_DELIVCC, ipint->delivcc,
                ipint->delivcc_len) == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: failed to write DelivCC into IP intercept message.");
        ret = -1;
        goto xmitend;
    }

    if (add_ii_field(xmit, OPENLI_IPII_FIELD_TARGET, ipint->username,
                ipint->username_len) == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: failed to write target into IP intercept message.");
        ret = -1;
        goto xmitend;
    }

    if (add_ii_field(xmit, OPENLI_IPII_FIELD_DESTID, ipint->destid,
                sizeof(ipint->destid)) == NULL) {
        logger(LOG_DAEMON,
                "OpenLI: failed to write destid into IP intercept message.");
        ret = -1;
        goto xmitend;
    }

    /* Update the length in the header accordingly */
    hdr = (ii_header_t *)xmit.buf;
    hdr->bodylen = htons(xmit.writeptr - xmit.buf - sizeof(hdr));

    /* BLOCKING */
    ret = send(fd, xmit.buf, xmit.writeptr - xmit.buf, 0);
    if (ret < xmit.writeptr - xmit.buf) {
        logger(LOG_DAEMON,
                "OpenLI: provisioner failed to send intercept instruction to collector: %s.",
                strerror(errno));
    }

xmitend:
    if (xmit.buf) {
        free(xmit.buf);
    }
    return ret;

}
#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
