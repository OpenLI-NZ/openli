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

#include <uthash.h>
#include "x2x3_ingest.h"
#include "logger.h"

static x2x3_cond_attr_t *add_unparsed_conditional_attribute(
        x2x3_cond_attr_t **attrs,
        uint16_t attrtype, uint16_t attrlen, uint8_t *attrbody,
        uint32_t *nextattr_id, uint8_t allow_multiple) {

    x2x3_cond_attr_t *toadd;

    if (!allow_multiple && attrs[attrtype] != NULL) {
        /* already seen this attribute once and we are not allowed to
         * have multiple instances */
        return NULL;
    }

    toadd = calloc(1, sizeof(x2x3_cond_attr_t));
    if (!toadd) {
        return NULL;
    }
    toadd->type = attrtype;
    toadd->length = attrlen;
    toadd->body = attrbody;
    toadd->is_parsed = 0;
    toadd->parsed.as_octets = NULL;

    if (allow_multiple) {
        toadd->sub_id = *nextattr_id;
        (*nextattr_id) ++;
    } else {
        toadd->sub_id = 0;
    }
    HASH_ADD_KEYPTR(hh, attrs[attrtype], &(toadd->sub_id),
            sizeof(toadd->sub_id), toadd);
    return toadd;
}

static int add_u16_condition_attribute(x2x3_cond_attr_t **attrs,
        uint16_t attrtype, uint16_t attrlen, uint8_t *attrbody,
        uint32_t *nextattr_id) {

    x2x3_cond_attr_t *added;
    uint16_t *ptr;

    // no uint16_t attributes allow multiples
    added = add_unparsed_conditional_attribute(attrs, attrtype, attrlen,
            attrbody, nextattr_id, 0);
    if (!added) {
        return 0;
    }
    if (attrlen != sizeof(uint16_t)) {
        logger(LOG_INFO,
                "OpenLI: warning -- X2X3 attribute type %u should be %u octets in size but it is actually %u; possible parsing error?",
                attrtype, sizeof(uint16_t), attrlen);
        return 1;
    }
    ptr = (uint16_t *)(attrbody);
    added->parsed.as_u16 = ntohs(*ptr);
    added->is_parsed = 1;
    return 1;
}

static int add_timespec_condition_attribute(x2x3_cond_attr_t **attrs,
        uint16_t attrtype, uint16_t attrlen, uint8_t *attrbody,
        uint32_t *nextattr_id) {

    x2x3_cond_attr_t *added;
    uint32_t *ptr;
    uint64_t res = 0;

    // no uint32_t attributes allow multiples
    added = add_unparsed_conditional_attribute(attrs, attrtype, attrlen,
            attrbody, nextattr_id, 0);
    if (!added) {
        return 0;
    }
    if (attrlen != sizeof(uint64_t)) {
        logger(LOG_INFO,
                "OpenLI: warning -- X2X3 attribute type %u should be %u octets in size but it is actually %u; possible parsing error?",
                attrtype, sizeof(uint64_t), attrlen);
        return 1;
    }
    /* From 103 221-2: "The value shall be given as two successive 32-bit
     * unsigned integers, with the first giving the integral part in seconds
     * and the second giving the fractional part in nanoseconds
     */
    ptr = (uint32_t *)(attrbody);
    res = ntohl(*ptr);
    res = (res << 32);
    ptr ++;
    res += ntohl(*ptr);

    added->parsed.as_u64 = res;
    added->is_parsed = 1;
    return 1;
}

static int add_u32_condition_attribute(x2x3_cond_attr_t **attrs,
        uint16_t attrtype, uint16_t attrlen, uint8_t *attrbody,
        uint32_t *nextattr_id) {

    x2x3_cond_attr_t *added;
    uint32_t *ptr;

    // no uint32_t attributes allow multiples
    added = add_unparsed_conditional_attribute(attrs, attrtype, attrlen,
            attrbody, nextattr_id, 0);
    if (!added) {
        return 0;
    }
    if (attrlen != sizeof(uint32_t)) {
        logger(LOG_INFO,
                "OpenLI: warning -- X2X3 attribute type %u should be %u octets in size but it is actually %u; possible parsing error?",
                attrtype, sizeof(uint32_t), attrlen);
        return 1;
    }
    ptr = (uint32_t *)(attrbody);
    added->parsed.as_u32 = ntohl(*ptr);
    added->is_parsed = 1;
    return 1;
}

static int add_u8_condition_attribute(x2x3_cond_attr_t **attrs,
        uint16_t attrtype, uint16_t attrlen, uint8_t *attrbody,
        uint32_t *nextattr_id) {

    x2x3_cond_attr_t *added;

    // no uint8_t attributes allow multiples
    added = add_unparsed_conditional_attribute(attrs, attrtype, attrlen,
            attrbody, nextattr_id, 0);
    if (!added) {
        return 0;
    }
    if (attrlen != sizeof(uint8_t)) {
        logger(LOG_INFO,
                "OpenLI: warning -- X2X3 attribute type %u should be %u octets in size but it is actually %u; possible parsing error?",
                attrtype, sizeof(uint8_t), attrlen);
        return 1;
    }
    added->parsed.as_u8 = *(attrbody);
    added->is_parsed = 1;
    return 1;
}

static int add_octets_condition_attribute(x2x3_cond_attr_t **attrs,
        uint16_t attrtype, uint16_t attrlen, uint16_t expectedattrlen,
        uint8_t *attrbody, uint32_t *nextattr_id, uint8_t allow_multiple) {

    x2x3_cond_attr_t *added;

    added = add_unparsed_conditional_attribute(attrs, attrtype, attrlen,
            attrbody, nextattr_id, allow_multiple);
    if (!added) {
        return 0;
    }
    if (attrlen != expectedattrlen && expectedattrlen != 0) {
        logger(LOG_INFO,
                "OpenLI: warning -- X2X3 attribute type %u should be %u octets in size but it is actually %u; possible parsing error?",
                attrtype, expectedattrlen, attrlen);
        return 1;
    }

    added->parsed.as_octets = malloc(attrlen * sizeof(uint8_t));
    memcpy(added->parsed.as_octets, attrbody, attrlen);
    added->is_parsed = 1;
    return 1;
}

static int add_string_condition_attribute(x2x3_cond_attr_t **attrs,
        uint16_t attrtype, uint16_t attrlen,
        uint8_t *attrbody, uint32_t *nextattr_id, uint8_t allow_multiple) {

    x2x3_cond_attr_t *added;

    added = add_unparsed_conditional_attribute(attrs, attrtype, attrlen,
            attrbody, nextattr_id, allow_multiple);
    if (!added) {
        return 0;
    }
    if (attrlen == 0) {
        logger(LOG_INFO,
                "OpenLI: warning -- X2X3 attribute type %u has zero length; possible parsing error?",
                attrtype);
        return 1;
    }

    /* +1 because we need to make sure we include a null terminator */
    added->parsed.as_string = (char *)calloc(attrlen + 1, sizeof(char));
    memcpy(added->parsed.as_string, attrbody, attrlen);
    added->is_parsed = 1;
    return 1;
}

void free_x2x3_conditional_attributes(x2x3_cond_attr_t **attrs) {
    size_t i;
    x2x3_cond_attr_t *attr, *tmp;

    for (i = 0; i < X2X3_COND_ATTR_LAST; i++) {
        if (attrs[i] == NULL) {
            continue;
        }

        HASH_ITER(hh, attrs[i], attr, tmp) {
            switch(i) {
                case X2X3_COND_ATTR_SOURCE_IPV4_ADDRESS:
                case X2X3_COND_ATTR_DEST_IPV4_ADDRESS:
                case X2X3_COND_ATTR_SOURCE_IPV6_ADDRESS:
                case X2X3_COND_ATTR_DEST_IPV6_ADDRESS:
                    if (attr->is_parsed && attr->parsed.as_octets) {
                        free(attr->parsed.as_octets);
                    }
                    break;
                case X2X3_COND_ATTR_SEQNO:
                case X2X3_COND_ATTR_TIMESTAMP:
                case X2X3_COND_ATTR_SOURCE_PORT:
                case X2X3_COND_ATTR_DEST_PORT:
                case X2X3_COND_ATTR_IPPROTO:

                    break;

                case X2X3_COND_ATTR_MATCHED_TARGETID:
                case X2X3_COND_ATTR_OTHER_TARGETID:
                case X2X3_COND_ATTR_SDP_SESSION_DESC:
                    if (attr->is_parsed && attr->parsed.as_string) {
                        free(attr->parsed.as_string);
                    }

                    break;

                case X2X3_COND_ATTR_ETSI_102232:
                case X2X3_COND_ATTR_3GPP_33128:
                case X2X3_COND_ATTR_3GPP_33108:
                case X2X3_COND_ATTR_PROPRIETARY:
                case X2X3_COND_ATTR_ADDITIONAL_XID_RELATED:
                case X2X3_COND_ATTR_DOMAINID:
                case X2X3_COND_ATTR_NFID:
                case X2X3_COND_ATTR_IPID:
                case X2X3_COND_ATTR_MIME_CONTENT_TYPE:
                case X2X3_COND_ATTR_MIME_CONTENT_ENCODING:

                    break;

                case X2X3_COND_ATTR_LAST:
                    break;
            }

            HASH_DELETE(hh, attrs[i], attr);
            free(attr);
        }
    }

}

int parse_x2x3_conditional_attributes(uint8_t *hdrstart, uint32_t hlen,
        x2x3_cond_attr_t **attrs) {

    uint8_t *ptr = (hdrstart + sizeof(x2x3_base_header_t));
    uint16_t attrtype, attrlen;
    uint32_t parsed = sizeof(x2x3_base_header_t);
    uint32_t nextattr_id = 1;

    if (hlen <= sizeof(x2x3_base_header_t)) {
        return 0;
    }

    memset(attrs, 0, sizeof(x2x3_cond_attr_t *) * X2X3_COND_ATTR_LAST);

    while (parsed < hlen) {

        attrtype = ntohs(*((uint16_t *)ptr));
        ptr += sizeof(uint16_t);

        attrlen = ntohs(*((uint16_t *)ptr));
        ptr += sizeof(uint16_t);

        if (attrlen > hlen - (parsed + (2 * sizeof(uint16_t)))) {
            logger(LOG_INFO, "OpenLI: parsing error when reading conditional attributes in X2/X3 PDU");
            return -1;
        }

        if (attrtype >= X2X3_COND_ATTR_LAST || attrtype == 0) {
            logger(LOG_INFO, "OpenLI: unsupported conditional attribute seen in X2/X3 PDU: %u", attrtype);
            return -1;
        }

        parsed += sizeof(uint16_t) * 2;
        switch(attrtype) {
            case X2X3_COND_ATTR_SEQNO:
                if (add_u32_condition_attribute(attrs, attrtype, attrlen, ptr,
                            &nextattr_id) == 0) {
                    // TODO error handling?
                    break;
                }
                break;
            case X2X3_COND_ATTR_TIMESTAMP:
                if (add_timespec_condition_attribute(attrs, attrtype, attrlen,
                            ptr, &nextattr_id) == 0) {
                    // TODO error handling?
                    break;
                }
                break;
            case X2X3_COND_ATTR_SOURCE_IPV4_ADDRESS:
            case X2X3_COND_ATTR_DEST_IPV4_ADDRESS:
                if (add_octets_condition_attribute(attrs, attrtype, attrlen,
                        sizeof(uint32_t), ptr, &nextattr_id, 0) == 0) {
                    // try to ignore because it's probably an invalid duplicate
                    break;
                }
                break;
            case X2X3_COND_ATTR_SOURCE_IPV6_ADDRESS:
            case X2X3_COND_ATTR_DEST_IPV6_ADDRESS:
                if (add_octets_condition_attribute(attrs, attrtype, attrlen,
                        16, ptr, &nextattr_id, 0) == 0) {
                    // try to ignore because it's probably an invalid duplicate
                    break;
                }
                break;
            case X2X3_COND_ATTR_SOURCE_PORT:
            case X2X3_COND_ATTR_DEST_PORT:
                if (add_u16_condition_attribute(attrs, attrtype, attrlen, ptr,
                            &nextattr_id) == 0) {
                    // TODO error handling?
                    break;
                }
                break;
            case X2X3_COND_ATTR_IPPROTO:
                if (add_u8_condition_attribute(attrs, attrtype, attrlen, ptr,
                            &nextattr_id) == 0) {
                    // TODO error handling?
                    break;
                }
                break;
            case X2X3_COND_ATTR_MATCHED_TARGETID:
            case X2X3_COND_ATTR_OTHER_TARGETID:
                if (add_string_condition_attribute(attrs, attrtype, attrlen,
                            ptr, &nextattr_id, 1) == 0) {
                    // TODO error handling?
                    break;
                }
                break;
            case X2X3_COND_ATTR_SDP_SESSION_DESC:
                if (add_string_condition_attribute(attrs, attrtype, attrlen,
                            ptr, &nextattr_id, 0) == 0) {
                    // TODO error handling?
                    break;
                }
                break;

            /* XXX
             * These are the attributes that we don't really support so
             * they're not going to make their way into any IRIs or CCs.
             * Mainly we ignore them because they're vaguely defined in the
             * standard and therefore it is difficult to know how to interpret
             * them even if they do appear in a PDU.
             *
             * For now, we'll just skip over them quietly and worry about
             * them in the future if it turns out we need them. At that point,
             * we should hopefully have a useful example to assist us.
             */
            case X2X3_COND_ATTR_ETSI_102232:
            case X2X3_COND_ATTR_3GPP_33128:
            case X2X3_COND_ATTR_3GPP_33108:
            case X2X3_COND_ATTR_PROPRIETARY:
            case X2X3_COND_ATTR_ADDITIONAL_XID_RELATED:
                if (add_unparsed_conditional_attribute(attrs, attrtype, attrlen,
                        ptr, &nextattr_id, 1) == NULL) {
                    // has to be a failure to allocate
                    logger(LOG_INFO, "OpenLI: memory exhaustion when reading conditional attributes in X2/X3 PDU");
                    return -1;
                }
                break;
            case X2X3_COND_ATTR_DOMAINID:
            case X2X3_COND_ATTR_NFID:
            case X2X3_COND_ATTR_IPID:
            case X2X3_COND_ATTR_MIME_CONTENT_TYPE:
            case X2X3_COND_ATTR_MIME_CONTENT_ENCODING:
                if (add_unparsed_conditional_attribute(attrs, attrtype, attrlen,
                        ptr, &nextattr_id, 0)) {
                    // probably an invalid duplicate
                    break;
                }
                break;
            case X2X3_COND_ATTR_LAST:
                // should never hit this!
                break;

        }
        ptr += attrlen;
        parsed += attrlen;
    }

    return parsed;
}

