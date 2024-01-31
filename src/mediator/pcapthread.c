/*
 *
 * Copyright (c) 2018-2022 The University of Waikato, Hamilton, New Zealand.
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

#include <unistd.h>
#include <amqp.h>

#include "logger.h"
#include "lea_send_thread.h"
#include "util.h"
#include "pcapthread.h"
#include "mediator_rmq.h"
#include <libtrace.h>
#include <assert.h>

/** This source file implements the "pcap output" thread that allows
 *  users to write an intercept to disk as a series of pcaps, instead of
 *  delivering it to an agency via the conventional handovers.
 *
 *  This thread is implemented as a special type of LEA send thread that
 *  just happens to use libtrace to write files, so there are a lot of
 *  references to lea_thread_state_t instances etc. Hopefully it is not
 *  too confusing -- just try to think of the pcap thread as like a
 *  inheriting class from the LEA send thread, which overrides or extends
 *  certain functionality to suit its intended purpose.
 *
 *  Because of this, a pcap thread has two state "objects" -- one is an
 *  LEA send thread state instance, which includes all of the state that is
 *  common to both LEA send threads and the pcap thread, the other is the
 *  pcap specific thread state that is never required by an LEA send thread.
 */

/** Halt all ongoing pcap outputs and close their respective files.
 *
 *  @param pstate           The state for the pcap output thread
 */
static void halt_pcap_outputs(pcap_thread_state_t *pstate) {

    active_pcap_output_t *out, *tmp;

    HASH_ITER(hh, pstate->active, out, tmp) {
        HASH_DELETE(hh, pstate->active, out);
        if (out->uri) {
            free(out->uri);
        }
        free(out->liid);
        trace_destroy_output(out->out);
        free(out);
    }
}

/** Concatenates a string onto another, using the provided pointer as
 *  the infered end of the "front" string.
 *
 *  @param str          The string to "add" to the current string
 *  @param bufp         Pointer to the null byte of the string that is being
 *                      added to
 *  @param buflim       Pointer to the end of the allocated space for the
 *                      string being added to
 *
 *  @return the null byte of the newly concatenated string
 */
static char *stradd(const char *str, char *bufp, char *buflim) {
    while (bufp < buflim && (*bufp = *str++) != '\0') {
        ++bufp;
    }
    return bufp;
}

/** Constructs the pcap filename URI for an output file.
 *
 *  @param state            The LEA send thread state for this pcap thread
 *  @param pstate           The pcap specific state for this pcap thread
 *  @param urispace         The string that the URI is to be written into
 *  @param urispacelen      The number of bytes allocated for the urispace
 *                          string.
 *  @param act              The intercept that this output file will belong to
 *
 *  @return 0 if the URI could not fit in the provided string space, 1
 *          otherwise.
 */

static int populate_pcap_uri(lea_thread_state_t *state,
        pcap_thread_state_t *pstate, char *urispace,
        int urispacelen, active_pcap_output_t *act) {

    char *ptr = state->pcap_outtemplate;
    struct timeval tv;
    char tsbuf[12];
    char scratch[9500];
    char *w = scratch;
    char *end = scratch + urispacelen;

    /* Build the URI in 'scratch', then copy it into urispace only if we
     * manage to build it successfully
     */
    assert(ptr);
    gettimeofday(&tv, NULL);
    w = stradd("pcapfile:", w, end);

    w = stradd(state->pcap_dir, w, end);
    w = stradd("/", w, end);

    for (; *ptr; ++ptr) {
        if (*ptr == '%') {
            switch(*(++ptr)) {
                case '\0':
                    --ptr;
                    break;
                case 'L':
                    /* '%L' is replaced with the LIID for the intercept */
                    w = stradd(act->liid, w, end);
                    continue;
                case 's':
                    /* '%s' is replaced with the unix timestamp in seconds */
                    snprintf(tsbuf, sizeof(tsbuf), "%ld", tv.tv_sec);
                    w = stradd(tsbuf, w, end);
                    continue;
                default:
                    /* all other tokens will be handled by strftime */
                    --ptr;
            }
        }
        if (w == end) {
            break;
        }
        *w++ = *ptr;
    }

    /* Make sure we put an appropriate suffix on the file name */
    w = stradd(".pcap", w, end);
    if (state->pcap_compress_level > 0) {
        w = stradd(".gz", w, end);
    }

    if (w >= end || w - scratch >= urispacelen) {
        return 0;
    }

    *w = '\0';
    /* All other '%' formatting is handled by strftime() */
    strftime(urispace, urispacelen, scratch, gmtime(&(tv.tv_sec)));
    return 1;
}

/** De-registers the "rawip" queues for any LIIDs that we have disabled
 *  pcap output for due to being unconfirmed by a reconnecting provisioner.
 *
 *  This method is designed to be called using foreach_liid_agency_mapping()
 *
 *  @param m            The LIID map entry that is being considered
 *  @param arg          The pcap thread state object (requires casting)
 *
 *  @return 0 always
 */
static int deregister_unconfirmed_pcap_liids(liid_map_entry_t *m, void *arg) {
    pcap_thread_state_t *pstate = (pcap_thread_state_t *)arg;

    if (m->unconfirmed == 0) {
        return 0;
    }

    /* If the LIID has not been confirmed as a "pcap" output by now, let's
     * assume it has been removed or re-assigned to an LEA instead.
     *
     * The only thing we really need to do though is deregister the
     * raw IP RMQ queue for that intercept.
     */
    if (pstate->rawip_handover->rmq_consumer) {
        deregister_mediator_rawip_RMQ_consumer(
                pstate->rawip_handover->rmq_consumer, m->liid);
    }
    return 0;
}

/** Opens a pcap output file using libtrace, named after the current time.
 *
 *  @param state            The LEA thread state for this thread
 *  @param pstate           The pcap-specific state for the pcap output thread
 *  @param act              The intercept that requires a new pcap file
 *
 *  @return -1 if an error occurs, 0 otherwise.
 */
static int open_pcap_output_file(lea_thread_state_t *state,
        pcap_thread_state_t *pstate, active_pcap_output_t *act) {

    char uri[4096];
    int compressmethod = TRACE_OPTION_COMPRESSTYPE_ZLIB;
    int compresslevel = state->pcap_compress_level;
    struct timeval tv;

    /* Make sure the user configured a directory for us to put files into */
    if (state->pcap_dir == NULL) {
        if (!pstate->dirwarned) {
            logger(LOG_INFO,
                    "OpenLI Mediator: pcap directory is not configured so will not write any pcap files.");
            pstate->dirwarned = 1;
        }
        return -1;
    }

    if (act == NULL || act->liid == NULL) {
        logger(LOG_INFO,
                "OpenLI Mediator: attempted to open a pcap trace file for an invalid pcap output.");
        return -1;
    }

    if (state->pcap_outtemplate == NULL) {

        /* Name the file after the LIID and current timestamp -- this ensures we
         * will have files that have unique and meaningful names, even if we
         * have multiple intercepts that last over multiple rotation periods.
         */
        gettimeofday(&tv, NULL);

        if (state->pcap_compress_level > 0) {
            snprintf(uri, 4096, "pcapfile:%s/openli_%s_%lu.pcap.gz",
                state->pcap_dir, act->liid, tv.tv_sec);
        } else {
            snprintf(uri, 4096, "pcapfile:%s/openli_%s_%lu.pcap",
                state->pcap_dir, act->liid, tv.tv_sec);
        }
    } else {
        if (populate_pcap_uri(state, pstate, uri, 4096, act) == 0) {
            logger(LOG_INFO,
                    "OpenLI Mediator: unable to create pcap output file name from template '%s'",
                    state->pcap_outtemplate);
            return -1;
        }
    }

    /* Libtrace boiler-plate for creating an output file */
    act->out = trace_create_output(uri);
    if (trace_is_err_output(act->out)) {
        libtrace_err_t err;
        err = trace_get_err_output(act->out);
        logger(LOG_INFO,
                "OpenLI Mediator: Error opening %s for writing trace file: %s",
                uri, err.problem);
        goto pcaptraceerr;
    }

    if (state->pcap_compress_level > 0) {
        if (trace_config_output(act->out, TRACE_OPTION_OUTPUT_COMPRESSTYPE,
                &compressmethod) == -1) {
            libtrace_err_t err;
            err = trace_get_err_output(act->out);
            logger(LOG_INFO,
                    "OpenLI Mediator: Error configuring compression for writing trace file %s: %s",
                    uri, err.problem);
            goto pcaptraceerr;
        }

        /* Make sure we use an "int" here rather than pstate->compresslevel
         * directly, just to avoid libtrace trying to read inappropriate
         * bits of memory.
         */
        if (trace_config_output(act->out, TRACE_OPTION_OUTPUT_COMPRESS,
                &compresslevel) == -1) {
            libtrace_err_t err;
            err = trace_get_err_output(act->out);
            logger(LOG_INFO,
                    "OpenLI Mediator: Error configuring compression for writing trace file %s: %s",
                    uri, err.problem);
            goto pcaptraceerr;
        }
    }

    if (trace_start_output(act->out) == -1) {
        libtrace_err_t err;
        err = trace_get_err_output(act->out);
        logger(LOG_INFO,
                "OpenLI Mediator: Error starting output trace file %s: %s",
                uri, err.problem);
        goto pcaptraceerr;
    }

    act->uri = strdup(uri);
    act->pktwritten = 0;

    return 0;

pcaptraceerr:
    /* Tidying up in the event that something went wrong. */
    trace_destroy_output(act->out);
    act->out = NULL;
    return -1;
}

/** Start a new pcap output for a particular LIID
 *
 *  @param state            The LEA thread state for this thread
 *  @param pstate           The pcap-specific state for the pcap output thread
 *  @param liid             The LIID to create a pcap output for, as a string.
 *
 *  @return a pointer to a new pcap output structure, or NULL if an error
 *          occurred.
 */
static active_pcap_output_t *create_new_pcap_output(
        lea_thread_state_t *state, pcap_thread_state_t *pstate,
        char *liid) {

    active_pcap_output_t *act;

    HASH_FIND(hh, pstate->active, liid, strlen(liid), act);
    if (act) {
        return act;
    }

    act = (active_pcap_output_t *)malloc(sizeof(active_pcap_output_t));
    act->liid = strdup(liid);
    act->uri = NULL;

    if (open_pcap_output_file(state, pstate, act) == -1) {
        free(act->liid);
        if (act->uri) {
            free(act->uri);
        }
        free(act);
        return NULL;
    }
    HASH_ADD_KEYPTR(hh, pstate->active, act->liid, strlen(act->liid), act);
    return act;
}

/** Converts a raw IP packet record into a libtrace packet and writes it
 *  to the appropriate pcap output file.
 *
 *  @param nextrec          Pointer to the start of the raw IP packet record
 *  @param bufrem           The amount of readable bytes in the buffer where
 *                          the raw IP packet record is stored
 *  @param pstate           The pcap-specific state for this thread
 *
 *  @return the number of bytes to advance the buffer to move past the
 *          raw IP packet record that we just wrote to disk.
 */
static uint32_t write_rawip_to_pcap(uint8_t *nextrec, uint64_t bufrem,
        pcap_thread_state_t *pstate) {

    active_pcap_output_t *pcapout;
    uint32_t pdulen;
    unsigned char liidspace[2048];
    uint16_t liidlen;
    uint8_t *pktdata;

    /* The raw IP packet record begins with a four-byte size field, which is
     * the size of the record (not including the size field itself)
     */
    pdulen = *(uint32_t *)nextrec;

    nextrec += sizeof(uint32_t);
    bufrem -= sizeof(uint32_t);

    if (pdulen == 0) {
        return sizeof(uint32_t);
    }

    /* Next is the LIID, which is encoded as a 2 byte size field followed
     * by the LIID string itself (not null-terminated)
     */
    extract_liid_from_exported_msg(nextrec, bufrem, liidspace, 2048, &liidlen);

    nextrec += liidlen;
    bufrem -= liidlen;
    if (pdulen - liidlen > 65535) {
        logger(LOG_INFO, "OpenLI Mediator: raw IP packet is too large to write as a pcap packet, possibly corrupt");
        assert(0);
        return pdulen + sizeof(uint32_t);
    }
    HASH_FIND(hh, pstate->active, liidspace,
            strlen((const char *)liidspace), pcapout);

    /* Hopefully, we already know about this LIID and have a pcap output
     * handle all set up and ready for it. If not, let's just skip past it.
     */
    if (pcapout && pcapout->out) {
        if (!pstate->packet) {
            pstate->packet = trace_create_packet();
        }

        /* nextrec should now point to a pcap header, followed by
         * the raw IP packet content. Thankfully, libtrace will let us
         * "prepare" a packet object from a buffer as long as it contains
         * the format header followed by the raw packet contents.
         */
        pktdata = nextrec;
        if (trace_prepare_packet(pstate->dummypcap, pstate->packet,
                (void *)pktdata, TRACE_RT_DATA_DLT+TRACE_DLT_RAW,
                TRACE_PREP_DO_NOT_OWN_BUFFER) < 0) {
            logger(LOG_INFO, "OpenLI Mediator: error converting received raw IP into a valid libtrace pcap packet");
            return pdulen + sizeof(uint32_t);
        }

        /* Now we can have libtrace write the packet using the pcap format */
        if (trace_write_packet(pcapout->out, pstate->packet) < 0) {
            libtrace_err_t err = trace_get_err_output(pcapout->out);
            logger(LOG_INFO, "OpenLI Mediator: failed to write raw IP to pcap for LIID %s to %s: %s", liidspace, pcapout->uri, err.problem);
            trace_destroy_output(pcapout->out);
            pcapout->out = NULL;
            if (pcapout->uri) {
                free(pcapout->uri);
            }
        } else {
            if (pcapout->pktwritten == 0 && pcapout->uri) {
                logger(LOG_INFO,
                        "OpenLI Mediator: opened new trace file %s for LIID %s",
                        pcapout->uri, pcapout->liid);
            }

            pcapout->pktwritten += 1;
        }
    }

    return pdulen + sizeof(uint32_t);
}


/** Converts a ETSI CC record into a libtrace packet and writes it
 *  to the appropriate pcap output file.
 *
 *  @param nextrec          Pointer to the start of the ETSI CC record
 *  @param bufrem           The amount of readable bytes in the buffer where
 *                          the ETSI CC record is stored
 *  @param pstate           The pcap-specific state for this thread
 *
 *  @return the number of bytes to advance the buffer to move past the
 *          ETSI CC record that we just wrote to disk. Returns 0 if there
 *          is a problem with the ETSI CC record that prevents it from
 *          being written to disk.
 */
static uint32_t write_etsicc_to_pcap(uint8_t *nextrec, uint64_t bufrem,
        pcap_thread_state_t *pstate) {

    active_pcap_output_t *pcapout;
    uint32_t pdulen;
    unsigned char liidspace[2048];
    struct timeval tv;

    if (pstate->decoder == NULL) {
        pstate->decoder = wandder_create_etsili_decoder();
    }

    /* Using the ETSI decoder, grab the record length and the LIID from
     * within the record itself
     */
    wandder_attach_etsili_buffer(pstate->decoder, nextrec, bufrem, false);
    pdulen = wandder_etsili_get_pdu_length(pstate->decoder);

    if (pdulen == 0 || pdulen > bufrem) {
        logger(LOG_INFO, "OpenLI Mediator: pcap thread received an incomplete ETSI CC");
        return 0;
    }

    if (wandder_etsili_get_liid(pstate->decoder, (char *)liidspace,
            2048) == NULL) {
        logger(LOG_INFO, "OpenLI Mediator: unable to find LIID in ETSI CC received by pcap thread");
        return 0;
    }
    HASH_FIND(hh, pstate->active, liidspace, strlen((const char *)liidspace),
            pcapout);

    /* Hopefully, we already know about this LIID and have a pcap output
     * handle all set up and ready for it. If not, let's just skip past it.
     */
    if (pcapout && pcapout->out) {
        uint8_t *rawip;
        uint32_t cclen;
        uint32_t *tsptr;
        char ccname[128];

        if (!pstate->packet) {
            pstate->packet = trace_create_packet();
        }

        /* Convert CC to pcap and write to trace file using libtrace.
         * We don't need the ETSI headers, so we can jump straight to the
         * the CC contents using libwandder
         */
        rawip = wandder_etsili_get_cc_contents(pstate->decoder, &cclen,
                ccname, 128);

        if (rawip == NULL) {
            logger(LOG_INFO, "OpenLI Mediator: unable to find CC contents from ETSI CC seen by pcap thread for LIID %s", liidspace);
            goto exitpcapwrite;
        }
        if (cclen > 65535) {
            logger(LOG_INFO, "OpenLI Mediator: ETSI CC record is too large to write as a pcap packet, possibly corrupt");
            goto exitpcapwrite;
        }

        tv = wandder_etsili_get_header_timestamp(pstate->decoder);

        trace_construct_packet(pstate->packet, TRACE_TYPE_NONE,
                (const void *)rawip, (uint16_t)cclen);

        /* trace_construct_packet() sets the packet timestamp to "now",
         * but we actually want to replace that with the time that the
         * packet was intercepted (as per the timestamp field in the
         * ETSI PS header).
         */

        /* A bit naughty, but this is the only way we can set the
         * pcap timestamp in libtrace at the moment...
         */
        tsptr = (uint32_t *)(pstate->packet->header);
        *tsptr = tv.tv_sec;
        tsptr ++;
        *tsptr = tv.tv_usec;

        if (trace_write_packet(pcapout->out, pstate->packet) < 0) {
            libtrace_err_t err = trace_get_err_output(pcapout->out);
            logger(LOG_INFO, "OpenLI Mediator: failed to write ETSI CC to pcap for LIID %s: %s", liidspace, err.problem);
            trace_destroy_output(pcapout->out);
            pcapout->out = NULL;
        } else {
            if (pcapout->pktwritten == 0 && pcapout->uri) {
                logger(LOG_INFO,
                        "OpenLI Mediator: opened new trace file %s for LIID %s",
                        pcapout->uri, pcapout->liid);
            }
            pcapout->pktwritten += 1;
        }
    }

exitpcapwrite:
    return pdulen;
}

/** Reads intercept records from the export buffer, converts them into the
 *  pcap format and writes them into their corresponding pcap output file(s).
 *
 *  @param ho           The handover which owns the export buffer
 *  @param state        The LEA send thread state for this pcap thread
 *  @param pstate       The pcap-specific thread state for this thread
 *
 *  @return -1 if an error occurs while writing to disk, -2 if an error
 *          occurs while acknowledging the written data in RMQ, 0 if
 *          the writing was successful.
 */
static int write_pcap_from_buffered_rmq(handover_t *ho,
        lea_thread_state_t *state, pcap_thread_state_t *pstate) {
    uint64_t bufrem;
    uint8_t *nextrec = NULL;
    uint32_t advance = 0;
    static int tally = 0;

    bufrem = get_buffered_amount(&(ho->ho_state->buf));
    while ((nextrec = get_buffered_head(&(ho->ho_state->buf), &bufrem))) {
        /* TODO consider limiting the number of records written, so we
         * don't get stuck in here for a long time?
         */
        tally ++;
        if (ho->handover_type == HANDOVER_HI3) {
            if ((advance = write_etsicc_to_pcap(nextrec, bufrem, pstate))
                    == 0) {
                return -1;
            }
        } else if (ho->handover_type == HANDOVER_HI2) {
            /* TODO */
            assert(0);
        } else if (ho->handover_type == HANDOVER_RAWIP) {
            if ((advance = write_rawip_to_pcap(nextrec, bufrem, pstate))
                    == 0) {
                return -1;
            }
        } else {
            logger(LOG_INFO, "OpenLI Mediator: handover is corrupted in pcap thread");
            return -1;
        }

        advance_export_buffer_head(&(ho->ho_state->buf), advance);
    }

    if (!ho->ho_state->valid_rmq_ack) {
        return 0;
    }

    /* acknowledge RMQ messages */
    if (ho->handover_type == HANDOVER_HI3) {
        if (ack_mediator_cc_messages(ho->rmq_consumer,
                ho->ho_state->next_rmq_ack) != 0) {
            logger(LOG_INFO, "OpenLI Mediator: error while acknowledging sent data from internal CC queue by pcapdisk thread");
            return -2;
        }
    } else if (ho->handover_type == HANDOVER_HI2) {
        if (ack_mediator_iri_messages(ho->rmq_consumer,
                ho->ho_state->next_rmq_ack) != 0) {
            logger(LOG_INFO, "OpenLI Mediator: error while acknowledging sent data from internal IRI queue by pcapdisk thread");
            return -2;
        }
    } else if (ho->handover_type == HANDOVER_RAWIP) {
        if (ack_mediator_rawip_messages(ho->rmq_consumer,
                ho->ho_state->next_rmq_ack) != 0) {
            logger(LOG_INFO, "OpenLI Mediator: error while acknowledging sent data from internal rawip queue by pcapdisk thread");
            return -2;
        }
    }

    ho->ho_state->valid_rmq_ack = 0;

    return 0;
}

static int consume_pcap_packets(handover_t *ho, lea_thread_state_t *state,
        pcap_thread_state_t *pstate) {

    int r;

    if ((r = write_pcap_from_buffered_rmq(ho, state, pstate)) == 1) {
        return 0;
    } else if (r == -2) {
        reset_handover_rmq(ho);
        return 0;
    } else if (r == -1) {
        /* pcap writing error */
        return -1;
    }

    /* if we get here, the buffer is empty so read more messages from RMQ */
    if (ho->handover_type == HANDOVER_HI3) {
        r = consume_mediator_cc_messages(ho->rmq_consumer,
                &(ho->ho_state->buf), 1024, &(ho->ho_state->next_rmq_ack));
    } else if (ho->handover_type == HANDOVER_RAWIP) {
        r = consume_mediator_rawip_messages(ho->rmq_consumer,
                &(ho->ho_state->buf), 512, &(ho->ho_state->next_rmq_ack));
    } else if (ho->handover_type == HANDOVER_HI2) {
        r = consume_mediator_iri_messages(ho->rmq_consumer,
                &(ho->ho_state->buf), 1024, &(ho->ho_state->next_rmq_ack));
    } else {
        reset_handover_rmq(ho);
        return 0;
    }

    if (r < 0) {
        reset_handover_rmq(ho);
        return 1;
    } else if (r > 0) {
        ho->ho_state->valid_rmq_ack = 1;
    }

    r = write_pcap_from_buffered_rmq(ho, state, pstate);
    if (r == -2) {
        reset_handover_rmq(ho);
        return 0;
    } else if (r == -1) {
        /* pcap writing error */
    }
    return r;

}

/** Flush any outstanding packets for each active pcap output.
 *
 *  Regular libtrace writes may buffer captured packets for quite some
 *  time before actually writing them to disk, which can lead users to think
 *  that the intercept is not working. Therefore, we regularly trigger
 *  flushing of the pcap outputs to ensure that the file on disk is more
 *  representative of what has been intercepted thus far.
 *
 *  @param pstate           The pcap-specific state for the thread
 */
static void pcap_flush_traces(pcap_thread_state_t *pstate) {
    active_pcap_output_t *pcapout, *tmp;

    HASH_ITER(hh, pstate->active, pcapout, tmp) {
        /* if pktwritten is zero, then no packets have been added since the
         * last flush so no need to bother with an explicit flush call.
         */
        if (pcapout->out && pcapout->pktwritten &&
                trace_flush_output(pcapout->out) < 0) {
            libtrace_err_t err = trace_get_err_output(pcapout->out);
            logger(LOG_INFO,
                    "OpenLI Mediator: error while flushing pcap trace file: %s",
                    err.problem);
            trace_destroy_output(pcapout->out);
            pcapout->out = NULL;
            HASH_DELETE(hh, pstate->active, pcapout);
            free(pcapout->liid);
            if (pcapout->uri) {
                free(pcapout->uri);
            }
            free(pcapout);
        }
        pcapout->pktwritten = 0;
    }
}

/** Rotate the output files being used by each pcap output.
 *
 *  This is done regularly to ensure that there are complete pcap files
 *  (i.e. with no half-written packets and proper footers) available for the
 *  user to hand over to LEAs, if they accept pcap output.
 *
 *  @param state            The LEA thread state for this thread
 *  @param pstate           The pcap-specific state for the pcap output thread
 */
static void pcap_rotate_traces(lea_thread_state_t *state,
        pcap_thread_state_t *pstate) {
    active_pcap_output_t *pcapout, *tmp;

    HASH_ITER(hh, pstate->active, pcapout, tmp) {
        /* Close the existing output file -- this will also flush any
         * remaining output and append any appropriate footer to the file.
         */
        trace_destroy_output(pcapout->out);
        pcapout->out = NULL;

        /* Open a new file, which will be named using the current time */
        if (open_pcap_output_file(state, pstate, pcapout) == -1) {
            logger(LOG_INFO,
                    "OpenLI Mediator: error while rotating pcap trace file");

            if (pcapout->out) {
                trace_destroy_output(pcapout->out);
                pcapout->out = NULL;
            }
            HASH_DELETE(hh, pstate->active, pcapout);
            free(pcapout->liid);
            if (pcapout->uri) {
                free(pcapout->uri);
            }
            free(pcapout);
        }
    }
}

/** Disables pcap output for a particular LIID, closing any existing open
 *  file handle.
 *
 *  @param pstate           The pcap-specific state for the thread
 *  @param liid             The LIID to disable pcap output for
 */
static void pcap_disable_liid(pcap_thread_state_t *pstate, char *liid) {

    active_pcap_output_t *pcapout;

    HASH_FIND(hh, pstate->active, liid, strlen(liid), pcapout);
    if (!pcapout) {
        return;
    }
    logger(LOG_INFO, "OpenLI Mediator: disabling pcap output for LIID '%s'",
            liid);

    if (pcapout->out) {
        trace_destroy_output(pcapout->out);
        pcapout->out = NULL;
    }
    HASH_DELETE(hh, pstate->active, pcapout);
    if (pcapout->uri) {
        free(pcapout->uri);
    }
    free(pcapout->liid);
    free(pcapout);
}

/** Flush the pcap output file handle for all active pcap intercepts. If
 *  the files are due to be rotated, then do the rotation instead.
 *
 *  @param state            The LEA send thread state for this thread
 *  @param pstate           The pcap-specific state for this thread
 */
static void flush_pcap_outputs(lea_thread_state_t *state,
        pcap_thread_state_t *pstate) {

    struct timeval tv;

    gettimeofday(&tv, NULL);
    if (tv.tv_sec % (60 * state->pcap_rotate_frequency) < 60) {
        /* Rotation is due */
        pcap_rotate_traces(state, pstate);
        return;
    }
    pcap_flush_traces(pstate);

}

/** Adds a new LIID to our set of pcap outputs and opens a libtrace file
 *  handle for writing output for that intercept.
 *
 *  @param state            The LEA send thread state for this thread
 *  @param pstate           The pcap-specific state for this thread
 *  @param added            The LIID that is to be added
 */
static void add_new_pcapdisk_liid(lea_thread_state_t *state,
        pcap_thread_state_t *pstate, added_liid_t *added) {

    /* Check if this LIID is actually being added to pcapdisk, or if
     * we are just getting an announcement for a different agency.
     */
    if (strcmp(added->agencyid, state->agencyid) != 0) {
        /* This LIID has switched to another agency, so close any
         * existing pcap output and disable the pcap-specific RMQs */
        pcap_disable_liid(pstate, added->liid);
        if (purge_lea_liid_mapping(state, added->liid) > 0) {
            if (deregister_mediator_rawip_RMQ_consumer(
                        pstate->rawip_handover->rmq_consumer,
                        added->liid) < 0) {
                logger(LOG_INFO,
                        "OpenLI Mediator: WARNING failed to deregister rawip RMQ for LIID %s -> %s",
                        added->liid, state->agencyid);
            }
        }
    } else {
        /* This is an announcement for the pcap thread! */
        int r = insert_lea_liid_mapping(state, added->liid);
        if (r > 0) {
            /* Only register with RMQ if this LIID is "new" */
            if (register_mediator_rawip_RMQ_consumer(
                    pstate->rawip_handover->rmq_consumer, added->liid) < 0) {
                logger(LOG_INFO,
                        "OpenLI Mediator: WARNING failed to register rawip RMQ for LIID %s in pcap thread",
                        added->liid);
            }
        }
        if (create_new_pcap_output(state, pstate, added->liid)
                == NULL) {
            logger(LOG_INFO, "OpenLI Mediator: failed to create new pcap output entity for LIID %s", added->liid);
        }
    }

    free(added->liid);
    free(added->agencyid);
    free(added);
}

/** Parse and action a message received from the main thread.
 *
 *  @param state            The LEA send thread state for this thread
 *  @param pstate           The pcap-specific state for this thread
 *
 *  @return 1 if the pcap thread needs to be halted immediately, 0 otherwise.
 */
int handle_pcap_thread_messages(lea_thread_state_t *state,
        pcap_thread_state_t *pstate) {
    lea_thread_msg_t msg;

    while (libtrace_message_queue_try_get(&(state->in_main), (void *)&msg)
                != LIBTRACE_MQ_FAILED) {

        if (msg.type == MED_LEA_MESSAGE_HALT) {
            /* Main thread wants us to shutdown now */
            return 1;
        }

        if (msg.type == MED_LEA_MESSAGE_SHUTDOWN_TIMER) {
            /* Ignore this -- no need to shutdown the pcap thread */
        }

        if (msg.type == MED_LEA_MESSAGE_RECONNECT) {
            /* Ignore */
        }

        if (msg.type == MED_LEA_MESSAGE_DISCONNECT) {
            /* Ignore */
        }

        if (msg.type == MED_LEA_MESSAGE_RELOAD_CONFIG) {
            /* Config has potentially changed, so re-read it */
            if (read_parent_config(state) == 1) {
                reset_handover_rmq(pstate->rawip_handover);
            }
        }

        if (msg.type == MED_LEA_MESSAGE_UPDATE_AGENCY) {
            /* Set a timer which upon expiry will declare any
             * remaining unconfirmed LIIDs to be withdrawn.
             */
            halt_mediator_timer(state->cleanse_liids);
            if (start_mediator_timer(state->cleanse_liids, 30) < 0) {
                logger(LOG_INFO, "OpenLI Mediator: failed to add timer to remove unconfirmed LIID mappings in pcap output thread");
            }

        }

        if (msg.type == MED_LEA_MESSAGE_REMOVE_LIID) {
            /* An LIID has been withdrawn */
            char *liid = (char *)(msg.data);

            if (pstate->rawip_handover->rmq_consumer != NULL) {
                deregister_mediator_rawip_RMQ_consumer(
                        pstate->rawip_handover->rmq_consumer, liid);
            }

            withdraw_liid_agency_mapping(&(state->active_liids), liid);
            free(liid);
        }

        if (msg.type == MED_LEA_MESSAGE_ADD_LIID) {
            /* An LIID has been assigned to an agency (or pcap) thread */
            added_liid_t *added = (added_liid_t *)msg.data;
            add_new_pcapdisk_liid(state, pstate, added);
        }

    }
    return 0;
}

/** Acts upon a file descriptor or timer event that has been triggered
 *  by this thread's epoll handler.
 *
 *  @param state            The LEA send thread state for this thread
 *  @param pstate           The pcap-specific state for this thread
 *  @param ev               The epoll event that had triggered
 *
 *  @return -1 if an error occurs, 1 if the caller needs to break out of its
 *          current loop, 0 otherwise.
 */
static int pcap_thread_epoll_event(lea_thread_state_t *state,
        pcap_thread_state_t *pstate, struct epoll_event *ev) {

    med_epoll_ev_t *mev = (med_epoll_ev_t *)(ev->data.ptr);
    int ret = 0;

    switch (mev->fdtype) {
        case MED_EPOLL_SIGCHECK_TIMER:
            if (ev->events & EPOLLIN) {
                /* Time to check the message queue again */
                ret = 1;
            } else {
                logger(LOG_INFO, "OpenLI Mediator: main epoll timer has failed in pcapdisk thread");
                ret = 0;
            }
            break;
        case MED_EPOLL_RMQCHECK_TIMER:
            /* This should never fire in this thread, but just in case... */
            ret = agency_thread_action_rmqcheck_timer(state, mev);
            break;
        case MED_EPOLL_CEASE_LIID_TIMER:
            /* Clean up any unconfirmed LIIDs */
            ret = agency_thread_action_cease_liid_timer(state);
            foreach_liid_agency_mapping(&(state->active_liids), pstate,
                    deregister_unconfirmed_pcap_liids);
            break;
        case MED_EPOLL_PCAP_TIMER:
            /* halt the timer
             * for each active pcap output:
             *   check if we need to rotate the file
             *   otherwise, flush pending output to the file
             * restart the timer
             */
            halt_mediator_timer(mev);
            flush_pcap_outputs(state, pstate);
            if (start_mediator_timer(mev, 60) < 0) {
                logger(LOG_INFO, "OpenLI Mediator: unable to reset pcap flush timer in pcap output thread: %s", strerror(errno));
                ret = -1;
            }
            break;

        default:
            logger(LOG_INFO, "OpenLI Mediator: invalid epoll event type %d seen in pcapdisk thread", mev->fdtype);
            ret = -1;
    }

    return ret;
}

/** The "main" method for a pcap output thread.
 *
 *  @param params           The LEA send thread state that has been created
 *                          for this thread.
 *
 *  @return NULL when the thread exits (via pthread_join())
 */
static void *run_pcap_thread(void *params) {
    lea_thread_state_t *state = (lea_thread_state_t *)params;
    med_epoll_ev_t *flushtimer = NULL;
    struct epoll_event evs[64];
    int i, nfds, timerexpired = 0;
    int is_halted = 0;
    pcap_thread_state_t pstate;
    uint32_t firstflush;
    struct timeval tv;

    // defined in lea_send_thread.c
    read_parent_config(state);

    /* Initialise pcap-specific state for this thread */
    pstate.active = NULL;
    pstate.dirwarned = 0;
    pstate.inqueue = (libtrace_message_queue_t *)params;
    pstate.decoder = NULL;
    pstate.packet = NULL;
    pstate.dummypcap = trace_create_dead("pcapfile:/dev/null");
    pstate.rawip_handover = create_new_handover(state->epoll_fd, NULL, NULL,
            HANDOVER_RAWIP, 0, 0);

    register_handover_RMQ_all(pstate.rawip_handover, NULL, "pcapdisk",
            state->internalrmqpass);
    logger(LOG_INFO, "OpenLI Mediator: starting pcap output thread");

    if (create_agency_thread_timers(state) < 0) {
        goto threadexit;
    }

    /* Don't need the RMQ check timer, since we're going to poll the
     * RMQ queues multiple times per second.
     */
    halt_mediator_timer(state->rmqhb);

    /* Set up the flush / rotation timer for our output files */
    gettimeofday(&tv, NULL);
    firstflush = (((tv.tv_sec / 60) * 60) + 60) - tv.tv_sec;

    flushtimer = create_mediator_timer(state->epoll_fd, NULL,
            MED_EPOLL_PCAP_TIMER, firstflush);

    if (flushtimer == NULL) {
        logger(LOG_INFO,
                "OpenLI Mediator: failed to create pcap rotation timer");
    }

    while (!is_halted) {
        /* Check for messages from the main thread */
        is_halted = handle_pcap_thread_messages(state, &pstate);

        if (is_halted) {
            break;
        }

        /* epoll */
        if (start_mediator_ms_timer(state->timerev, 50) < 0) {
            logger(LOG_INFO,"OpenLI Mediator: failed to add timer to epoll in agency thread for %s", state->agencyid);
            break;
        }
        timerexpired = 0;
        while (!timerexpired && !is_halted) {
            nfds = epoll_wait(state->epoll_fd, evs, 64, -1);

            if (nfds < 0) {
                if (errno == EINTR) {
                    continue;
                }
                logger(LOG_INFO, "OpenLI Mediator: error while waiting for epoll events in pcap thread: %s", strerror(errno));
                is_halted = 1;
                continue;
            }

            for (i = 0; i < nfds; i++) {
                timerexpired = pcap_thread_epoll_event(state, &pstate,
                        &(evs[i]));
                if (timerexpired == -1) {
                    is_halted = 1;
                    break;
                }
                if (timerexpired) {
                    break;
                }
            }
        }

        /* Consume available packets and write them to their corresponding
         * pcap files */

        /* TODO error handling? */
        consume_pcap_packets(pstate.rawip_handover, state, &pstate);

        halt_mediator_timer(state->timerev);
    }

threadexit:
    halt_pcap_outputs(&pstate);
    if (pstate.decoder) {
        wandder_free_etsili_decoder(pstate.decoder);
    }
    if (pstate.packet) {
        trace_destroy_packet(pstate.packet);
    }
    if (pstate.dummypcap) {
        trace_destroy_dead(pstate.dummypcap);
    }
    if (pstate.rawip_handover) {
        free_handover(pstate.rawip_handover);
    }

    if (flushtimer) {
        destroy_mediator_timer(flushtimer);
    }

    logger(LOG_INFO, "OpenLI Mediator: ending pcap output thread");
    destroy_agency_thread_state(state);
    pthread_exit(NULL);
}

/** Creates a "dummy" agency for the pcap output thread so that the thread
 *  can make use of existing methods written for the LEA send threads which
 *  require valid handover instances.
 *
 *  @param agency       The agency to initialise with the fake handovers.
 *  @param epollfd      The epoll file descriptor for the pcap thread.
 */
static inline void init_pcapdisk_agency(mediator_agency_t *agency,
        int epollfd) {
    agency->awaitingconfirm = 0;
    agency->agencyid = strdup("pcapdisk");
    agency->disabled = 0;
    agency->disabled_msg = 0;
    agency->hi2 = create_new_handover(epollfd, NULL, NULL, HANDOVER_HI2, 0, 0);
    agency->hi3 = create_new_handover(epollfd, NULL, NULL, HANDOVER_HI3, 0, 0);
}

/** Creates and starts the pcap output thread for an OpenLI mediator.
 *
 *  The pcap thread is treated as another LEA send thread by the mediator,
 *  so it will be added to the set of LEA send threads maintained by the
 *  main mediator thread.
 *
 *  @param medleas          The list of LEA send threads for the mediator
 *
 *  @return 1 always.
 */
int mediator_start_pcap_thread(mediator_lea_t *medleas) {
    lea_thread_state_t *pcap = NULL;
    mediator_lea_config_t *config = &(medleas->config);

    pcap = (lea_thread_state_t *)calloc(1, sizeof(lea_thread_state_t));
    pcap->parentconfig = config;
    pcap->epoll_fd = epoll_create1(0);

    /* probably unnecessary, but doesn't hurt */
    pcap->handover_id = medleas->next_handover_id;
    medleas->next_handover_id += 2;

    libtrace_message_queue_init(&(pcap->in_main), sizeof(lea_thread_msg_t));
    pcap->agencyid = strdup("pcapdisk");
    HASH_ADD_KEYPTR(hh, medleas->threads, pcap->agencyid,
            strlen(pcap->agencyid), pcap);

    /* Use a "dummy" agency so we can re-use our code for managing RMQ
     * consumers.
     */
    init_pcapdisk_agency(&(pcap->agency), pcap->epoll_fd);
    pthread_create(&(pcap->tid), NULL, run_pcap_thread, pcap);
    return 1;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
