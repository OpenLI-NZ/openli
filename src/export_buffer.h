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

#ifndef OPENLI_COLLECTOR_BUFFER_H_
#define OPENLI_COLLECTOR_BUFFER_H_

#include <libwandder.h>
#include <libwandder_etsili.h>
#include "netcomms.h"
#include "collector/encoder_worker.h"

typedef struct export_buffer {
    uint8_t *bufhead;
    uint8_t *buftail;
    uint64_t alloced;

    uint32_t deadfront;
    uint32_t partialfront;
    uint8_t hasnetcomm;
    wandder_etsispec_t *decoder;
} export_buffer_t;


void init_export_buffer(export_buffer_t *buf, uint8_t hasnetcomm);
void release_export_buffer(export_buffer_t *buf);
uint64_t get_buffered_amount(export_buffer_t *buf);
uint64_t append_message_to_buffer(export_buffer_t *buf,
        openli_encoded_result_t *msg, uint32_t beensent);
uint64_t append_etsipdu_to_buffer(export_buffer_t *buf,
        uint8_t *pdustart, uint32_t pdulen, uint32_t beensent);
int transmit_buffered_records(export_buffer_t *buf, int fd,
        uint64_t bytelimit);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
