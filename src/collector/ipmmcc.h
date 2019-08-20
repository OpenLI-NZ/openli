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
#ifndef OPENLI_IPMMCC_H_
#define OPENLI_IPMMCC_H_

#include <libtrace.h>
#include "collector.h"

int encode_ipmmcc(wandder_encoder_t *encoder,
        wandder_encode_job_t *precomputed, openli_ipcc_job_t *job,
        uint32_t seqno, struct timeval *tv, openli_encoded_result_t *msg);
int encode_ipmmcc_ber(wandder_buf_t **preencoded_ber,
        openli_ipcc_job_t *job, uint32_t seqno, struct timeval *tv,
        openli_encoded_result_t *msg, wandder_etsili_top_t *top, 
        wandder_encoder_t *encoder, wandder_encode_job_t *precomputed);

int ip4mm_comm_contents(libtrace_packet_t *pkt, packet_info_t *pinfo,
        libtrace_ip_t *ip, uint32_t rem, colthread_local_t *loc);

int ip6mm_comm_contents(libtrace_packet_t *pkt, packet_info_t *pinfo,
        libtrace_ip6_t *ip6, uint32_t rem, colthread_local_t *loc);

#endif

