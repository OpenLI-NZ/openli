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

#include "agency.h"

void free_liagency(liagency_t *lea) {
	if (lea->hi2_ipstr) {
		free(lea->hi2_ipstr);
	}
	if (lea->hi2_portstr) {
		free(lea->hi2_portstr);
	}
	if (lea->hi3_ipstr) {
		free(lea->hi3_ipstr);
	}
	if (lea->hi3_portstr) {
		free(lea->hi3_portstr);
	}
	if (lea->agencyid) {
		free(lea->agencyid);
	}
	free(lea);
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
