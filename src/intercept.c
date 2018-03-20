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
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#include "intercept.h"

void free_all_ipintercepts(libtrace_list_t *interceptlist) {

    libtrace_list_node_t *n;
    ipintercept_t *cept;

    n = interceptlist->head;
    while (n) {
        cept = (ipintercept_t *)n->data;
        if (cept->liid) {
            free(cept->liid);
        }
        if (cept->ipaddr) {
            free(cept->ipaddr);
        }

        if (cept->authcc) {
            free(cept->authcc);
        }

        if (cept->delivcc) {
            free(cept->delivcc);
        }

        if (cept->username) {
            free(cept->username);
        }

        if (cept->targetagency) {
            free(cept->targetagency);
        }

        n = n->next;
    }

    libtrace_list_deinit(interceptlist);
}

static void free_voip_cinmap(voipcinmap_t *cins) {
    voipcinmap_t *c, *tmp;

    /* TODO free all individual CIN contents inside each list item. */

    HASH_ITER(hh_callid, cins, c, tmp) {
        free(c->callid);
        free(c);
    }

}

static void free_voip_cins(voipcin_t *cins) {
    voipcin_t *c, *tmp;
    libtrace_list_node_t *n;
    rtpstreaminf_t *rtp;

    /* TODO free all individual CIN contents inside each list item. */

    HASH_ITER(hh, cins, c, tmp) {
        n = c->mediastreams->head;
        while (n) {
            rtp = *(rtpstreaminf_t **)(n->data);
            free(rtp->addr);
            free(rtp);
            n = n->next;
        }
        libtrace_list_deinit(c->mediastreams);
        free(c);
    }

}

void free_all_voipintercepts(voipintercept_t *vints) {

    voipintercept_t *v, *tmp;
    HASH_ITER(hh_liid, vints, v, tmp) {
        if (v->liid) {
            free(v->liid);
        }
        if (v->authcc) {
            free(v->authcc);
        }
        if (v->delivcc) {
            free(v->delivcc);
        }
        if (v->sipuri) {
            free(v->sipuri);
        }
        if (v->targetagency) {
            free(v->targetagency);
        }

        if (v->cin_callid_map) {
            free_voip_cinmap(v->cin_callid_map);
        }
        if (v->active_cins) {
            free_voip_cins(v->active_cins);
        }
        free(v);
    }

}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
