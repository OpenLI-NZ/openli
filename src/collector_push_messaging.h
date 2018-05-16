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

#ifndef OPENLI_COLLECTOR_PUSH_MESSAGING_H_
#define OPENLI_COLLECTOR_PUSH_MESSAGING_H_

#include "collector.h"
#include "intercept.h"


void handle_push_aluintercept(libtrace_thread_t *t, colthread_local_t *loc,
        aluintercept_t *alu);
void handle_halt_aluintercept(libtrace_thread_t *t, colthread_local_t *loc,
        aluintercept_t *alu);
void handle_push_ipintercept(libtrace_thread_t *t, colthread_local_t *loc,
        ipsession_t *sess);
void handle_push_ipmmintercept(libtrace_thread_t *t, colthread_local_t *loc,
        rtpstreaminf_t *rtp);
void handle_halt_ipmmintercept(libtrace_thread_t *t, colthread_local_t *loc,
        char *streamkey);
void handle_halt_ipintercept(libtrace_thread_t *t , colthread_local_t *loc,
        ipsession_t *sess);
void handle_push_sipuri(libtrace_thread_t *t, colthread_local_t *loc,
        char *sipuri);
void handle_halt_sipuri(libtrace_thread_t *t, colthread_local_t *loc,
        char *sipuri);
void handle_push_coreserver(libtrace_thread_t *t, colthread_local_t *loc,
        coreserver_t *cs);
void handle_remove_coreserver(libtrace_thread_t *t, colthread_local_t *loc,
        coreserver_t *cs);

#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
