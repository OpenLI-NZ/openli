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
#include <assert.h>
#include <libtrace.h>
#include <libwandder.h>
#include <libwandder_etsili.h>

#include "logger.h"
#include "collector.h"
#include "intercept.h"
#include "collector_export.h"
#include "etsili_core.h"
#include "ipiri.h"
#include "internetaccess.h"

int ip_iri(collector_global_t *glob, wandder_encoder_t **encoder,
        libtrace_message_queue_t *q, access_session_t *sess,
        ipintercept_t *ipint, etsili_iri_type_t iritype,
        struct timeval *tv, etsili_generic_t *params) {

    openli_export_recv_t msg;
    wandder_etsipshdr_data_t hdrdata;
    openli_exportmsg_t iri;

    if (*encoder == NULL) {
        *encoder = init_wandder_encoder();
    } else {
        reset_wandder_encoder(*encoder);
    }

    hdrdata.liid = ipint->common.liid;
    hdrdata.liid_len = ipint->common.liid_len;
    hdrdata.authcc = ipint->common.authcc;
    hdrdata.authcc_len = ipint->common.authcc_len;
    hdrdata.delivcc = ipint->common.delivcc;
    hdrdata.delivcc_len = ipint->common.delivcc_len;
    hdrdata.operatorid = glob->operatorid;
    hdrdata.operatorid_len = glob->operatorid_len;
    hdrdata.networkelemid = glob->networkelemid;
    hdrdata.networkelemid_len = glob->networkelemid_len;
    hdrdata.intpointid = glob->intpointid;
    hdrdata.intpointid_len = glob->intpointid_len;

    memset(&iri, 0, sizeof(openli_exportmsg_t));
    iri.msgbody = encode_etsi_ipiri(*encoder, &hdrdata,
            (int64_t)(sess->cin), (int64_t)sess->iriseqno, iritype, tv, params);

    iri.encoder = *encoder;
    iri.ipcontents = NULL;
    iri.ipclen = 0;
    iri.destid = ipint->common.destid;
    iri.header = construct_netcomm_protocol_header(iri.msgbody->len,
            OPENLI_PROTO_ETSI_IRI, 0, &(iri.hdrlen));

    memset(&msg, 0, sizeof(openli_export_recv_t));
    msg.type = OPENLI_EXPORT_ETSIREC;
    msg.data.toexport = iri;

    sess->iriseqno ++;
    libtrace_message_queue_put(q, (void *)(&msg));

    return 1;
}

ipiri_id_t *ipiri_create_id_printable(char *idstr, int length) {
    ipiri_id_t *iriid;

    if (length <= 0) {
        return NULL;
    }

    if (length > 128) {
        logger(LOG_DAEMON, "OpenLI: Printable IPIRI ID is too long, truncating to 128 characters.");
        length = 128;
    }

    iriid = (ipiri_id_t *)malloc(sizeof(ipiri_id_t));
    iriid->type = IPIRI_ID_PRINTABLE;
    iriid->content.printable = (char *)malloc(length + 1);
    memcpy(iriid->content.printable, idstr, length);

    if (iriid->content.printable[length - 1] != '\0') {
        iriid->content.printable[length] = '\0';
    }
    return iriid;
}

ipiri_id_t *ipiri_create_id_mac(uint8_t *macaddr) {
    /* TODO */
    return NULL;
}

ipiri_id_t *ipiri_create_id_ipv4(uint32_t addrnum, uint8_t slashbits) {
    /* TODO */
    return NULL;
}

void ipiri_free_id(ipiri_id_t *iriid) {
    if (iriid->type == IPIRI_ID_PRINTABLE) {
        free(iriid->content.printable);
    }
    free(iriid);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
