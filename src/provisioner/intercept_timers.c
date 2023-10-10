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
        timerptr = &(ceptdata->start_timer);
    } else if (timertype == PROV_EPOLL_INTERCEPT_HALT) {
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
        /* If the start time is before now, set the started flag to true
         * so we don't end up sending an erroneous "started" message later
         * on (i.e. after a config reload)
         */
        if (tv.tv_sec > ipint->common.tostart_time) {
            local->start_hi1_sent = 1;
        }
        if (add_intercept_timer(epoll_fd, ipint->common.tostart_time,
                tv.tv_sec, local, PROV_EPOLL_INTERCEPT_START) < 0) {
            failed = 1;
        }
        /* Same as above, but for the "deactivated" message. */
        if (tv.tv_sec > ipint->common.toend_time &&
                ipint->common.toend_time != 0) {
            local->end_hi1_sent = 1;
            local->start_hi1_sent = 0;
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
        if (tv.tv_sec > vint->common.tostart_time) {
            local->start_hi1_sent = 1;
        }
        if (add_intercept_timer(epoll_fd, vint->common.tostart_time,
                tv.tv_sec, local, PROV_EPOLL_INTERCEPT_START) < 0) {
            failed = 1;
        }
        if (tv.tv_sec > vint->common.toend_time &&
                vint->common.toend_time != 0) {
            local->end_hi1_sent = 1;
            local->start_hi1_sent = 0;
        }
        if (add_intercept_timer(epoll_fd, vint->common.toend_time,
                tv.tv_sec, local, PROV_EPOLL_INTERCEPT_HALT) < 0) {
            failed = 1;
        }
    }

    for (mailint = conf->emailintercepts; mailint != NULL;
            mailint = mailint->hh_liid.next) {
        local = (prov_intercept_data_t *)(mailint->common.local);
        if (tv.tv_sec > mailint->common.tostart_time) {
            local->start_hi1_sent = 1;
        }
        if (add_intercept_timer(epoll_fd, mailint->common.tostart_time,
                tv.tv_sec, local, PROV_EPOLL_INTERCEPT_START) < 0) {
            failed = 1;
        }
        if (tv.tv_sec > mailint->common.toend_time &&
                mailint->common.toend_time != 0) {
            local->end_hi1_sent = 1;
            local->start_hi1_sent = 0;
        }
        if (add_intercept_timer(epoll_fd, mailint->common.toend_time,
                tv.tv_sec, local, PROV_EPOLL_INTERCEPT_HALT) < 0) {
            failed = 1;
        }
    }
    return failed;
}

int remove_all_intercept_timers(int epoll_fd, prov_intercept_conf_t *conf) {
    ipintercept_t *ipint;
    voipintercept_t *vint;
    emailintercept_t *mailint;

    /* Do IP Intercepts */
    for (ipint = conf->ipintercepts; ipint != NULL; ipint = ipint->hh_liid.next)
    {
        free_prov_intercept_data(&(ipint->common), epoll_fd);
    }

    /* Now do the VOIP intercepts */
    for (vint = conf->voipintercepts; vint != NULL; vint = vint->hh_liid.next)
    {
        free_prov_intercept_data(&(vint->common), epoll_fd);
    }

    for (mailint = conf->emailintercepts; mailint != NULL;
            mailint = mailint->hh_liid.next) {
        free_prov_intercept_data(&(mailint->common), epoll_fd);
    }

    return 0;
}

int reset_intercept_timers(provision_state_t *state,
        intercept_common_t *existing, char *target_info,
        char *errorstring, int errorstrlen) {

    prov_intercept_data_t *timers = (prov_intercept_data_t *)(existing->local);
    struct timeval tv;

    if (timers == NULL) {
        return 0;
    }

    halt_intercept_timer(timers->start_timer, state->epoll_fd);
    halt_intercept_timer(timers->end_timer, state->epoll_fd);

    gettimeofday(&tv, NULL);

    if (existing->tostart_time > 0 && existing->toend_time > 0 &&
            existing->tostart_time >= existing->toend_time) {
        snprintf(errorstring, errorstrlen, "'starttime' parameter must be a timestamp BEFORE the 'endtime' timestamp");
        return -1;
    }

    if (existing->tostart_time > 0 && existing->tostart_time >
            tv.tv_sec) {
        if (timers->start_hi1_sent && !timers->end_hi1_sent) {
            /* start time has been shifted to a later time, but we had
             * already started intercepting so we need to announce the
             * deactivation.
             */
            announce_hi1_notification_to_mediators(state,
                    existing, target_info, HI1_LI_DEACTIVATED);
        }

        if (add_intercept_timer(state->epoll_fd, existing->tostart_time,
                    tv.tv_sec, timers, PROV_EPOLL_INTERCEPT_START) < 0) {
            snprintf(errorstring, errorstrlen,
                    "unable to create 'intercept start' timer for intercept %s",
                    existing->liid);
            return -1;
        }

    } else if (existing->tostart_time >= 0 && !timers->start_hi1_sent) {
        /* our start time has changed to a time BEFORE now, so we
         * are going to start intercepting...
         */
        if (existing->toend_time == 0 || existing->toend_time > tv.tv_sec) {
            /* but only if the end time is still in the future (or
             * indefinite...
             */
            announce_hi1_notification_to_mediators(state,
                    existing, target_info, HI1_LI_ACTIVATED);
        }
    }

    if (existing->toend_time > 0 && existing->toend_time > tv.tv_sec) {
        if (add_intercept_timer(state->epoll_fd, existing->toend_time,
                    tv.tv_sec, timers, PROV_EPOLL_INTERCEPT_HALT) < 0) {
            snprintf(errorstring, errorstrlen,
                    "unable to create 'intercept end' timer for intercept %s",
                    existing->liid);
            return -1;
        }
        if (timers->end_hi1_sent) {
            if (existing->tostart_time < tv.tv_sec) {
                /* the old end time had been reached, so we have already
                 * sent a deactivated message. But now the end time has
                 * been changed to further in the future so we need to
                 * announce that the intercept is restarting as of now.
                 */
                announce_hi1_notification_to_mediators(state, existing,
                        target_info, HI1_LI_ACTIVATED);
            }
        }

        timers->end_hi1_sent = 0;
    } else if (existing->toend_time > 0 && !timers->end_hi1_sent
            && timers->start_hi1_sent) {
        /* end time has moved to a time BEFORE now, and we've had
         * previously been intercepting so we need to announce that
         * we've stopped.
         */
        announce_hi1_notification_to_mediators(state,
                existing, target_info, HI1_LI_DEACTIVATED);

    } else if (existing->toend_time == 0) {
        if (timers->end_hi1_sent && existing->tostart_time < tv.tv_sec) {
            announce_hi1_notification_to_mediators(state, existing,
                    target_info, HI1_LI_ACTIVATED);
        }
        /* Reset this, so we can correctly send a DEACTIVATED if the
         * intercept is removed later on.
         */
        timers->end_hi1_sent = 0;

    }
    return 1;

}


// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
