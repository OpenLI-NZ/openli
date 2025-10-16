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

#ifndef OPENLI_EPSCC_H_
#define OPENLI_EPSCC_H_

#include <libwandder.h>
#include <libwandder_etsili.h>
#include "collector.h"
#include "intercept.h"
#include "internetaccess.h"
#include "etsili_core.h"
#include "collector_sync.h"

openli_export_recv_t *create_epscc_job(char *liid, uint32_t cin,
        uint32_t destid, uint8_t dir, uint8_t *ipcontent, uint32_t ipclen,
        uint8_t icetype, uint16_t gtpseqno);

wandder_encoded_result_t *encode_epscc_body(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, const char *liid, uint32_t cin,
        uint16_t gtpseqno, uint8_t dir, struct timeval tv, uint8_t icetype,
        uint32_t ipclen, openli_liid_format_t liid_format);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

