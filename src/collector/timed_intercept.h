/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
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

#ifndef OPENLI_COLLECTOR_TIMED_INTERCEPT_H_
#define OPENLI_COLLECTOR_TIMED_INTERCEPT_H_

#include "collector_base.h"
#include "intercept.h"
#include <time.h>

void add_new_intercept_time_event(Pvoid_t *timeevents, void *intercept,
        intercept_common_t *common);
void remove_intercept_time_event(Pvoid_t *timeevents,
        intercept_common_t *common);
void update_intercept_time_event(Pvoid_t *timeevents, void *intercept,
        intercept_common_t *prevcommon, intercept_common_t *newcommon);
void *check_intercept_time_event(Pvoid_t *timeevents, time_t currtime);
void clear_intercept_time_events(Pvoid_t *timeevents);

#endif

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
