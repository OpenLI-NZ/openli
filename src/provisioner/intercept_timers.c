/*
 *
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

#include "util.h"
#include "provisioner.h"
#include "logger.h"

#include "intercept_timers.h"

int add_intercept_timer(int epoll_fd, uint64_t tssec, uint64_t now,
        prov_intercept_data_t *ceptdata, int timertype) {

    int fd;
    prov_epoll_ev_t **timerptr;
    struct epoll_event ev;

    if (tssec == 0 || tssec < now) {
        return 0;
    }

    if (timertype == PROV_EPOLL_INTERCEPT_START) {
        printf("adding start timer for intercept in %lu seconds\n",
                tssec - now);
        timerptr = &(ceptdata->start_timer);
    } else if (timertype == PROV_EPOLL_INTERCEPT_HALT) {
        printf("adding halt timer for intercept in %lu seconds\n",
                tssec - now);
        timerptr = &(ceptdata->end_timer);
    } else {
        return -1;
    }

    if (*timerptr == NULL) {
        *timerptr = calloc(1, sizeof(prov_epoll_ev_t));
        (*timerptr)->fd = -1;
    }
    if ((*timerptr)->fd != -1) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, (*timerptr)->fd, &ev);
    }
    fd = epoll_add_timer(epoll_fd, tssec - now, *timerptr);
    if (fd == -1) {
        return -1;
    }
    (*timerptr)->fd = fd;
    (*timerptr)->fdtype = timertype;
    (*timerptr)->client = NULL;
    (*timerptr)->cept = ceptdata;

    return 1;
}

int halt_intercept_timer(prov_epoll_ev_t *timer, int epoll_fd) {
    struct epoll_event ev;

    if (timer == NULL) {
        return 0;
    }

    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, timer->fd, &ev) < 0) {
        /* what error handling makes sense here? */
        return -1;
    }

    close(timer->fd);
    timer->fd = -1;
    return 0;
}

void free_prov_intercept_data(intercept_common_t *common, int epoll_fd) {
    prov_intercept_data_t *timers = NULL;

    timers = (prov_intercept_data_t *)(common->local);
    if (timers == NULL) {
        return;
    }
    if (timers->start_timer) {
        halt_intercept_timer(timers->start_timer, epoll_fd);
        free(timers->start_timer);
    }
    if (timers->end_timer) {
        halt_intercept_timer(timers->end_timer, epoll_fd);
        free(timers->end_timer);
    }

    free(timers);
    common->local = NULL;
}

int add_all_intercept_timers(int epoll_fd, prov_intercept_conf_t *conf) {
    ipintercept_t *ipint;
    voipintercept_t *vint;
    emailintercept_t *mailint;

    prov_intercept_data_t *local;
    struct timeval tv;
    int failed = 0;

    gettimeofday(&tv, NULL);

    /* Do IP Intercepts */
    for (ipint = conf->ipintercepts; ipint != NULL; ipint = ipint->hh_liid.next)
    {
        local = (prov_intercept_data_t *)(ipint->common.local);
        if (add_intercept_timer(epoll_fd, ipint->common.tostart_time,
                tv.tv_sec, local, PROV_EPOLL_INTERCEPT_START) < 0) {
            failed = 1;
        }
        if (add_intercept_timer(epoll_fd, ipint->common.toend_time,
                tv.tv_sec, local, PROV_EPOLL_INTERCEPT_HALT) < 0) {
            failed = 1;
        }

    }

    /* Now do the VOIP intercepts */
    for (vint = conf->voipintercepts; vint != NULL; vint = vint->hh_liid.next)
    {
        local = (prov_intercept_data_t *)(vint->common.local);
        if (add_intercept_timer(epoll_fd, vint->common.tostart_time,
                tv.tv_sec, local, PROV_EPOLL_INTERCEPT_START) < 0) {
            failed = 1;
        }
        if (add_intercept_timer(epoll_fd, vint->common.toend_time,
                tv.tv_sec, local, PROV_EPOLL_INTERCEPT_HALT) < 0) {
            failed = 1;
        }
    }

    for (mailint = conf->emailintercepts; mailint != NULL;
            mailint = mailint->hh_liid.next) {
        local = (prov_intercept_data_t *)(mailint->common.local);
        if (add_intercept_timer(epoll_fd, mailint->common.tostart_time,
                tv.tv_sec, local, PROV_EPOLL_INTERCEPT_START) < 0) {
            failed = 1;
        }
        if (add_intercept_timer(epoll_fd, mailint->common.toend_time,
                tv.tv_sec, local, PROV_EPOLL_INTERCEPT_HALT) < 0) {
            failed = 1;
        }
        add_liid_mapping(conf, mailint->common.liid,
                mailint->common.targetagency);
    }
    return failed;
}

int remove_all_intercept_timers(int epoll_fd, prov_intercept_conf_t *conf) {
    ipintercept_t *ipint;
    voipintercept_t *vint;
    emailintercept_t *mailint;

    prov_intercept_data_t *local;

    /* Do IP Intercepts */
    for (ipint = conf->ipintercepts; ipint != NULL; ipint = ipint->hh_liid.next)
    {
        local = (prov_intercept_data_t *)(ipint->common.local);
        if (local == NULL) {
            continue;
        }
        halt_intercept_timer(local->start_timer, epoll_fd);
        halt_intercept_timer(local->end_timer, epoll_fd);
        free(local->start_timer);
        free(local->end_timer);
        free(local);
        ipint->common.local = NULL;
    }

    /* Now do the VOIP intercepts */
    for (vint = conf->voipintercepts; vint != NULL; vint = vint->hh_liid.next)
    {
        local = (prov_intercept_data_t *)(vint->common.local);
        if (local == NULL) {
            continue;
        }
        halt_intercept_timer(local->start_timer, epoll_fd);
        halt_intercept_timer(local->end_timer, epoll_fd);
        free(local->start_timer);
        free(local->end_timer);
        free(local);
        vint->common.local = NULL;
    }

    for (mailint = conf->emailintercepts; mailint != NULL;
            mailint = mailint->hh_liid.next) {
        local = (prov_intercept_data_t *)(mailint->common.local);
        if (local == NULL) {
            continue;
        }
        halt_intercept_timer(local->start_timer, epoll_fd);
        halt_intercept_timer(local->end_timer, epoll_fd);
        free(local->start_timer);
        free(local->end_timer);
        free(local);
        mailint->common.local = NULL;
    }

    return 0;
}
