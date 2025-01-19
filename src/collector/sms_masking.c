/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * OpenLI was originally developed by the University of Waikato WAND
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

#include <assert.h>

#include "logger.h"
#include "sip_worker.h"

const uint8_t sms_masking_bytes[] = {
    0x20, 0x10, 0x08, 0x04, 0x02, 0x81, 0x40
};

enum {
    RP_MESSAGE_TYPE_DATA_MS_TO_N = 0,
    RP_MESSAGE_TYPE_DATA_N_TO_MS = 1,
    RP_MESSAGE_TYPE_ACK_MS_TO_N = 2,
    RP_MESSAGE_TYPE_ACK_N_TO_MS = 3,
    RP_MESSAGE_TYPE_ERROR_MS_TO_N = 4,
    RP_MESSAGE_TYPE_ERROR_N_TO_MS = 5,
    RP_MESSAGE_TYPE_SMMA_MS_TO_N = 6,
};

static int mask_sms_submit_tpdu(uint8_t *ptr, uint8_t len) {

    uint8_t tp_vp_fmt = 0;
    uint8_t da_len = 0;
    uint8_t *start = ptr;
    uint8_t ud_len = 0;
    uint8_t vp_len = 0;
    int i, ind;

    if (len < 4) {
        return 0;
    }

    /* first byte are flags, but we need to check if TP-VPF is set
     * as that will indicate whether a TP-VP field is included and,
     * if so, what format it is using */
    tp_vp_fmt = (((*ptr) & 0x18) >> 3);

    ptr ++;

    /* next byte is the TP-MR -- can just skip */
    ptr ++;

    /* TP-Destination-Address */
    /* length is expressed as "usable" half-octets */
    da_len = *ptr;
    ptr ++;

    /* bits 4-6 of the Type-of-Address field may indicate that the
     * number is being encoded as alphanumeric, in which case da_len
     * should be treated as 7-bit characters instead.
     *
     * XXX get an example for testing!
     */
    if (((*ptr) & 0x70) == 0x50) {
        /* alphanumeric */
        ptr += (1 + (int)(ceil((7 * len) / 8)));
    } else {
        ptr += (1 + (int)(ceil(((double)da_len) / 2)));
    }

    if (ptr - start >= len) {
        return 0;
    }

    /* TP-PID, can just skip */
    ptr ++;

    /* TP-DCS, for now just pray we don't get anything other than the
     * default GSM 7 bit alphabet using class 0 */
    if (*ptr != 0) {
        logger(LOG_INFO, "OpenLI: unsupported TP-DCS when parsing SMS TPDU: %u",
                *ptr);
        return 0;
    }
    ptr ++;

    if (tp_vp_fmt != 0) {
        /* A TP-VP header is present... */
        if (tp_vp_fmt == 1) {
            /* TP-VP with enhanced format, always 7 bytes */
            ptr += 7;
        } else if (tp_vp_fmt == 2) {
            /* TP-VP with relative format, 1 byte length field */
            vp_len = *ptr;
            ptr += (1 + vp_len);
        } else if (tp_vp_fmt == 3) {
            /* TP-VP with absolute format, always 7 bytes */
            ptr += 7;
        }
    }

    if (ptr - start >= len) {
        return 0;
    }
    /* TP-User-Data-Length */
    ud_len = *ptr;
    ptr ++;
    if (ptr - start >= len) {
        return 0;
    }

    /* Finally reached the TP-User-Data */
    for (i = 0; i < ud_len; i++) {
        ind = i % 7;
        if (i == ud_len - 1 && ind >= 5) {
            /* this is the last byte, so we need to make sure that the
             * unused bits are set to zero.
             */
            *ptr = (sms_masking_bytes[ind] & 0x0f);
        } else {
            *ptr = sms_masking_bytes[ind];
        }
        ptr ++;
        if (ptr - start >= len) {
            break;
        }
    }

    return 1;
}

int mask_sms_message_content(uint8_t *sipstart, uint16_t siplen) {

    uint8_t *bodystart;
    size_t bodylen = 0;
    uint8_t *ptr;
    uint8_t msgtype;
    uint8_t len;

    bodystart = (uint8_t *)(strstr((char *)sipstart, "\r\n\r\n"));
    if (bodystart == NULL) {
        return 0;
    }
    assert(bodystart > sipstart);

    bodylen = siplen - (bodystart - sipstart);
    if (bodylen <= 4 || bodylen > siplen) {
        return 0;
    }

    ptr = bodystart + 4;
    /* RP-Message Type */
    msgtype = *ptr;
    ptr ++;

    if (msgtype != RP_MESSAGE_TYPE_DATA_MS_TO_N &&
            msgtype != RP_MESSAGE_TYPE_DATA_N_TO_MS) {
        /* No content to mask */
        return 1;
    }

    /* Message reference */
    ptr ++;

    /* Originator Address -- should be a single byte 0x00 if MS-to-N,
     * otherwise 1 byte length field + contents.
     */
    if (msgtype == RP_MESSAGE_TYPE_DATA_MS_TO_N) {
        if (*ptr != 0x00) {
            /* log an error? */
            logger(LOG_INFO,
                "OpenLI: unexpected originator address when parsing SMS Data");
            return 0;
        }
        ptr ++;
    } else {
        len = *ptr;
        if (len >= bodylen - (ptr - bodystart)) {
            logger(LOG_INFO,
                "OpenLI: bogus length for originator address when parsing SMS Data: %u vs %u",
                len, bodylen - (ptr - bodystart));
            return 0;
        }
        ptr += (len + 1);
    }

    /* Destination Address -- should be a single byte 0x00 if N-to-MS (I think),
     * otherwise 1 byte length field + contents.
     */
    if (msgtype == RP_MESSAGE_TYPE_DATA_N_TO_MS) {
        if (*ptr != 0x00) {
            /* log an error? */
            logger(LOG_INFO,
                "OpenLI: unexpected destination address when parsing SMS Data");
            return 0;
        }
        ptr ++;
    } else {
        len = *ptr;
        if (len >= bodylen - (ptr - bodystart)) {
            logger(LOG_INFO,
                "OpenLI: bogus length for destination address when parsing SMS Data: %u vs %u",
                len, bodylen - (ptr - bodystart));
            return 0;
        }
        ptr += (len + 1);
    }

    /* RP-User Data */
    /* First byte is the length */
    len = *ptr;
    if (len > bodylen - (ptr - bodystart)) {
        logger(LOG_INFO,
                "OpenLI: bogus length for user data when parsing SMS Data: %u vs %u",
                len, bodylen - (ptr - bodystart));
        return 0;
    }
    ptr ++;

    /* TPDU Message Type Indicator is the bottom 2 bits */
    if (((*ptr) & 0x03) == 0x01) {
        /* SMS-SUBMIT */
        return mask_sms_submit_tpdu(ptr, len);
    }

    return 1;
}


