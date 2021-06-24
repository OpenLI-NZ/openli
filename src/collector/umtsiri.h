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

#ifndef OPENLI_UMTSIRI_H_
#define OPENLI_UMTSIRI_H_

#include <libwandder.h>
#include <libwandder_etsili.h>
#include "collector.h"
#include "intercept.h"
#include "internetaccess.h"
#include "etsili_core.h"
#include "collector_sync.h"

enum {
        UMTSIRI_CONTENTS_IMSI = 1,
        UMTSIRI_CONTENTS_MSISDN = 2,
        UMTSIRI_CONTENTS_IMEI = 3,
        UMTSIRI_CONTENTS_APNAME = 4,
        UMTSIRI_CONTENTS_TAI = 5,
        UMTSIRI_CONTENTS_ECGI = 6,
        UMTSIRI_CONTENTS_PDP_ADDRESS = 7,
        UMTSIRI_CONTENTS_EVENT_TYPE = 8,
        UMTSIRI_CONTENTS_EVENT_TIME = 9,
        UMTSIRI_CONTENTS_LOCATION_TIME = 10,
        UMTSIRI_CONTENTS_GPRS_CORRELATION = 11,
        UMTSIRI_CONTENTS_IRI_TYPE = 12,
        UMTSIRI_CONTENTS_GPRS_ERROR_CODE = 13,
        UMTSIRI_CONTENTS_GGSN_IPADDRESS = 14,
        UMTSIRI_CONTENTS_INITIATOR = 15,
        UMTSIRI_CONTENTS_OPERATOR_IDENTIFIER = 16,
        UMTSIRI_CONTENTS_PDPTYPE = 17,
        UMTSIRI_CONTENTS_CGI = 18,
        UMTSIRI_CONTENTS_SAI = 19,
};

enum {
    UMTSIRI_EVENT_TYPE_PDPCONTEXT_ACTIVATION = 1,
    UMTSIRI_EVENT_TYPE_START_WITH_PDPCONTEXT_ACTIVE = 2,
    UMTSIRI_EVENT_TYPE_PDPCONTEXT_DEACTIVATION = 4,
    UMTSIRI_EVENT_TYPE_PDPCONTEXT_MODIFICATION = 13,
};

int create_mobiri_job_from_session(collector_sync_t *sync,
        access_session_t *sess, ipintercept_t *ipint, uint8_t special);

int create_mobiri_job_from_packet(collector_sync_t *sync,
        access_session_t *sess, ipintercept_t *ipint, access_plugin_t *p,
        void *parseddata);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

