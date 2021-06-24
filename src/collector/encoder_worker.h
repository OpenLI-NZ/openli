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

#ifndef OPENLI_ENCODER_WORKER_H_
#define OPENLI_ENCODER_WORKER_H_

#include <time.h>
#include <pthread.h>
#include <libwandder.h>
#include <Judy.h>

#include "collector_publish.h"
#include "collector.h"
#include "netcomms.h"
#include "etsili_core.h"
#include "export_shared.h"

enum {
    TEMPLATE_TYPE_IPCC_DIRFROM,
    TEMPLATE_TYPE_IPCC_DIRTO,
    TEMPLATE_TYPE_IPCC_DIROTHER,

    TEMPLATE_TYPE_IPMMCC_DIRFROM_IP_RTP,
    TEMPLATE_TYPE_IPMMCC_DIRTO_IP_RTP,
    TEMPLATE_TYPE_IPMMCC_DIROTHER_IP_RTP,

    TEMPLATE_TYPE_UMTSCC_DIRFROM,
    TEMPLATE_TYPE_UMTSCC_DIRTO,
    TEMPLATE_TYPE_UMTSCC_DIROTHER,

};

typedef struct saved_encoding_templates {

    char *key;
    Pvoid_t headers;
    Pvoid_t ccpayloads;
    Pvoid_t iripayloads;

} saved_encoding_templates_t;

void destroy_encoder_worker(openli_encoder_t *enc);
void *run_encoder_worker(void *encstate);

#endif


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
