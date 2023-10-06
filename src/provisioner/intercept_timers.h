/*
 * Copyright (c) 2018-2023 The University of Waikato, Hamilton, New Zealand.
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

#ifndef OPENLI_PROVISIONER_INTERCEPT_TIMERS_H_
#define OPENLI_PROVISIONER_INTERCEPT_TIMERS_H_

#include "intercept.h"
#include "util.h"
#include "provisioner.h"

int add_intercept_timer(int epoll_fd, uint64_t tssec, uint64_t now,
        prov_intercept_data_t *ceptdata, int timertype);

int halt_intercept_timer(prov_epoll_ev_t *timer, int epoll_fd);

void free_prov_intercept_data(intercept_common_t *common, int epoll_fd);

int add_all_intercept_timers(int epoll_fd, prov_intercept_conf_t *conf);

int remove_all_intercept_timers(int epoll_fd, prov_intercept_conf_t *conf);

int reset_intercept_timers(provision_state_t *state,
        intercept_common_t *existing, char *target_info,
        char *errorstring, int errorstrlen);

#endif
