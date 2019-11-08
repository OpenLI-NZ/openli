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

enum {
        UMTSIRI_CONTENTS_IMSI,
        UMTSIRI_CONTENTS_MSISDN,
        UMTSIRI_CONTENTS_IMEI,
        UMTSIRI_CONTENTS_APNAME,
        UMTSIRI_CONTENTS_TAI,
        UMTSIRI_CONTENTS_ECGI,
        UMTSIRI_CONTENTS_PDP_ADDRESS,
        UMTSIRI_CONTENTS_EVENT_TYPE,
        UMTSIRI_CONTENTS_EVENT_TIME,
        UMTSIRI_CONTENTS_LOCATION_TIME,
        UMTSIRI_CONTENTS_GPRS_CORRELATION,
        UMTSIRI_CONTENTS_IRI_TYPE,
        UMTSIRI_CONTENTS_GPRS_ERROR_CODE,
        UMTSIRI_CONTENTS_GGSN_IPADDRESS,
        UMTSIRI_CONTENTS_INITIATOR,
        UMTSIRI_CONTENTS_OPERATOR_IDENTIFIER,
};

enum {
    UMTSIRI_EVENT_TYPE_PDPCONTEXT_ACTIVATION = 1,
    UMTSIRI_EVENT_TYPE_START_WITH_PDPCONTEXT_ACTIVE = 2,
    UMTSIRI_EVENT_TYPE_PDPCONTEXT_DEACTIVATION = 4,
};

int encode_umtsiri(wandder_encoder_t *encoder,
        etsili_generic_freelist_t *freegenerics,
        wandder_encode_job_t *precomputed,
        openli_mobiri_job_t *job, uint32_t seqno,
        openli_encoded_result_t *res);


#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

