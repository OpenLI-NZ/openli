/*
 *
 * Copyright (c) 2018-2022 The University of Waikato, Hamilton, New Zealand.
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

#ifndef OPENLI_EMAILIRI_H_
#define OPENLI_EMAILIRI_H_

#include "etsili_core.h"
#include "collector_publish.h"

enum {
    EMAILIRI_CONTENTS_EVENT_TYPE = 1,
    EMAILIRI_CONTENTS_CLIENT_ADDRESS = 2,
    EMAILIRI_CONTENTS_SERVER_ADDRESS = 3,
    EMAILIRI_CONTENTS_CLIENT_PORT = 4,
    EMAILIRI_CONTENTS_SERVER_PORT = 5,
    EMAILIRI_CONTENTS_SERVER_OCTETS_SENT = 6,
    EMAILIRI_CONTENTS_CLIENT_OCTETS_SENT = 7,
    EMAILIRI_CONTENTS_PROTOCOL_ID = 8,
    EMAILIRI_CONTENTS_SENDER = 9,
    EMAILIRI_CONTENTS_RECIPIENTS = 10,
    EMAILIRI_CONTENTS_STATUS = 11,
    EMAILIRI_CONTENTS_TOTAL_RECIPIENTS = 12,
    EMAILIRI_CONTENTS_MESSAGE_ID = 13,
    EMAILIRI_CONTENTS_NATIONAL_PARAMETER = 14,
    EMAILIRI_CONTENTS_NATIONAL_ASN1_PARAMETERS = 15,
    EMAILIRI_CONTENTS_AAA_INFORMATION = 16,
    EMAILIRI_CONTENTS_SENDER_VALIDITY = 17,
};

void free_emailiri_parameters(etsili_generic_t *params);
void prepare_emailiri_parameters(etsili_generic_freelist_t *freegenerics,
        openli_emailiri_job_t *job, etsili_generic_t **params_p);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
