/*
 *
 * Copyright (c) 2023 The University of Waikato, Hamilton, New Zealand.
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

#include <assert.h>
#include <libtrace.h>
#include <libtrace_parallel.h>

#include "cisco_parser.h"
#include "logger.h"
#include "etsili_core.h"
#include "util.h"
#include "coreserver.h"

/** Converts a Cisco LI-mirrored packet directly into a CC encoding job for
 *  any intercepts that have requested its vendor mirror ID.
 *
 *  The vendor mirror ID is used as the CIN for this intercept, as there is
 *  no useful session identifier in the headers applied by Cisco.
 *
 * @param info          The identity of this collector (e.g. the operator ID,
 *                      device ID, etc).
 * @param loc           The thread-specific state for the thread calling this
 *                      function.
 * @param packet        The packet to be intercepted.
 * @param pinfo         Details about the packet (source and dest IPs, ports,
 *                      timestamp).
 * @param ciscomirrors  The list of IP intercepts that are using a vendor
 *                      mirror ID to nominate their target.
 *
 * @return 1 if a CC encoding job is successfully created and actioned. Returns
 *         0 otherwise.
 */
int generate_cc_from_cisco(collector_identity_t *info, colthread_local_t *loc,
        libtrace_packet_t *packet, packet_info_t *pinfo,
        vendmirror_intercept_list_t *ciscomirrors) {


    return 1;
}

/** Given a packet that has been mirrored by a Cisco device using its LI mode,
 *  this function will return the packet that is encapsulated within the
 *  LI shim header, as a libtrace packet.
 *
 *  Note that the returned packet is created by this function and will
 *  need to be destroyed explicitly once you are done with it.
 *
 *  @param pkt          The mirrored packet as seen by the "mediation server"
 *                      that received it, including the mirroring headers.
 *
 *  @return another libtrace packet that represents the packet that is
 *          encapsulated inside the mirroring headers, or NULL if no such
 *          packet can be found.
 */
libtrace_packet_t *strip_cisco_mirror_header(libtrace_packet_t *pkt) {

    return NULL;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
