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

#ifndef OPENLI_EPSIRI_H_
#define OPENLI_EPSIRI_H_

#include <libwandder.h>
#include <libwandder_etsili.h>
#include "collector.h"
#include "intercept.h"
#include "internetaccess.h"
#include "etsili_core.h"
#include "collector_sync.h"

enum {
        EPSIRI_CONTENTS_IMSI = 1,
        EPSIRI_CONTENTS_MSISDN = 2,
        EPSIRI_CONTENTS_IMEI = 3,
        EPSIRI_CONTENTS_APNAME = 4,
        EPSIRI_CONTENTS_PDP_ADDRESS = 7,
        EPSIRI_CONTENTS_EVENT_TYPE = 8,
        EPSIRI_CONTENTS_EVENT_TIME = 9,
        EPSIRI_CONTENTS_LOCATION_TIME = 10,
        EPSIRI_CONTENTS_GPRS_CORRELATION = 11,
        EPSIRI_CONTENTS_GGSN_IPADDRESS = 14,
        EPSIRI_CONTENTS_INITIATOR = 15,
        EPSIRI_CONTENTS_OPERATOR_IDENTIFIER = 16,
        EPSIRI_CONTENTS_PDPTYPE = 17,
        EPSIRI_CONTENTS_NETWORK_ELEMENT_IPADDRESS = 18,
        EPSIRI_CONTENTS_BEARER_ACTIVATION_TYPE = 19,
        EPSIRI_CONTENTS_BEARER_DEACTIVATION_TYPE = 20,
        /* separate the fields that are a direct copy of the IE from the
         * GTPv2 header -- these go in the EPS-GTPV2-SpecificParameters
         * sequence in the EPS IRI
         */
        EPSIRI_CONTENTS_RAW_ULI = 101,
        EPSIRI_CONTENTS_RAW_RAT_TYPE,
        EPSIRI_CONTENTS_RAW_BEARER_QOS,
        EPSIRI_CONTENTS_RAW_BEARER_ACTIVATION_TYPE,
        EPSIRI_CONTENTS_RAW_APN_AMBR,
        EPSIRI_CONTENTS_RAW_PCO_FROM_UE,
        EPSIRI_CONTENTS_RAW_PCO_FROM_NETWORK,
        EPSIRI_CONTENTS_RAW_BEARER_ID,
        EPSIRI_CONTENTS_RAW_PROCEDURE_TRANSACTION,
        EPSIRI_CONTENTS_RAW_PDN_ADDRESS_ALLOCATION,
        EPSIRI_CONTENTS_RAW_PDN_TYPE,
        EPSIRI_CONTENTS_RAW_FAILED_BEARER_ACTIVATION_REASON,
        EPSIRI_CONTENTS_RAW_ATTACH_TYPE,
        EPSIRI_CONTENTS_RAW_DETACH_TYPE,
        EPSIRI_CONTENTS_RAW_LINKED_BEARER_ID,
        EPSIRI_CONTENTS_RAW_FAILED_BEARER_MODIFICATION_REASON,
        EPSIRI_CONTENTS_RAW_BEARER_DEACTIVATION_CAUSE,
};

/* Values for EPSEvent as defined in 133.108 Appendix B.9 */
enum {
    EPSIRI_EVENT_TYPE_BEARER_ACTIVATION = 18,
    EPSIRI_EVENT_TYPE_START_WITH_BEARER_ACTIVE = 19,
    EPSIRI_EVENT_TYPE_BEARER_MODIFICATION = 20,
    EPSIRI_EVENT_TYPE_BEARER_DEACTIVATION = 21,
    EPSIRI_EVENT_TYPE_UE_REQUESTED_BEARER_RESOURCE_MODIFICATION = 22,
};


#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

