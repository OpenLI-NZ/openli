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

int ipmm_iri(libtrace_packet_t *pkt, collector_global_t *glob,
        wandder_encoder_t **encoder, libtrace_message_queue_t *q,
        voipintercept_t *vint, voipintshared_t *cin,
        etsili_iri_type_t iritype) {

    void *l3;
    uint16_t ethertype;
    uint32_t rem;
    openli_export_recv_t msg;
    wandder_etsipshdr_data_t hdrdata;
    openli_exportmsg_t iri;
    struct timeval tv;

    l3 = trace_get_layer3(pkt, &ethertype, &rem);
    if (l3 == NULL || rem < sizeof(libtrace_ip_t)) {
        logger(LOG_DAEMON, "OpenLI: packet intended for IPMM IRI is invalid.");
        return -1;
    }

    if (*encoder == NULL) {
        *encoder = init_wandder_encoder();
    } else {
        reset_wandder_encoder(*encoder);
    }

    tv = trace_get_timeval(pkt);

    hdrdata.liid = vint->liid;
    hdrdata.liid_len = vint->liid_len;
    hdrdata.authcc = vint->authcc;
    hdrdata.authcc_len = vint->authcc_len;
    hdrdata.delivcc = vint->delivcc;
    hdrdata.delivcc_len = vint->delivcc_len;
    hdrdata.operatorid = glob->operatorid;
    hdrdata.operatorid_len = glob->operatorid_len;
    hdrdata.networkelemid = glob->networkelemid;
    hdrdata.networkelemid_len = glob->networkelemid_len;
    hdrdata.intpointid = glob->intpointid;
    hdrdata.intpointid_len = glob->intpointid_len;

    iri.msgbody = encode_etsi_ipmmiri(&(iri.msglen), *encoder, &hdrdata,
            (int64_t)(cin->cin), (int64_t)cin->iriseqno, iritype, &tv, l3,
            rem);

    iri.ipcontents = (uint8_t *)l3;
    iri.ipclen = rem;
    iri.destid = vint->destid;
    iri.header = construct_netcomm_protocol_header(iri.msglen,
            OPENLI_PROTO_ETSI_IRI, vint->internalid, &(iri.hdrlen));

    msg.type = OPENLI_EXPORT_ETSIREC;
    msg.data.toexport = iri;

    cin->iriseqno ++;

    libtrace_message_queue_put(q, (void *)(&msg));
    return 1;

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
