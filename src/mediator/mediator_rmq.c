/*
 *
 * Copyright (c) 2018-2020 The University of Waikato, Hamilton, New Zealand.
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

#include <amqp.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>
#include "mediator_coll.h"
#include "logger.h"

static amqp_connection_state_t join_RMQ(mediator_collector_t *medcol,
		uint8_t *msgbody, uint16_t msglen, int logDisabled,
        single_coll_state_t *mstate) {

    amqp_rpc_reply_t ret;
    amqp_envelope_t envelope;
    amqp_frame_t frame;
    struct timeval tv;
    int status;
    tv.tv_usec = 0;
    tv.tv_sec = 1;

    //try connect to RMQ server at address(msgbody)
    //and join the appropiate queue (medID)
    amqp_set_initialize_ssl_library(0);
    amqp_connection_state_t amqp_state = amqp_new_connection();

    amqp_socket_t *ampq_sock = NULL;

    if (medcol->rmqconf->SSLenabled &&
            medcol->sslconf->cacertfile && 
            medcol->sslconf->certfile && 
            medcol->sslconf->keyfile) {

        ampq_sock = amqp_ssl_socket_new(amqp_state);

        if (!ampq_sock) {
            if (!logDisabled)
                logger(LOG_INFO, "OpenLI Mediator: RMQ Faild creating new SSL socket");
            amqp_destroy_connection(amqp_state);
            return NULL;
        }

        amqp_ssl_socket_set_verify_peer(ampq_sock, 0);
        amqp_ssl_socket_set_verify_hostname(ampq_sock, 0);

        if (amqp_ssl_socket_set_cacert(ampq_sock, medcol->sslconf->cacertfile) 
                != AMQP_STATUS_OK) {
            if (!logDisabled)
                logger(LOG_INFO, "OpenLI Mediator: RMQ Failed to load cacert");
            amqp_destroy_connection(amqp_state);
            return NULL;
        }

        if (amqp_ssl_socket_set_key(
                ampq_sock,
                medcol->sslconf->certfile,
                medcol->sslconf->keyfile
                ) != AMQP_STATUS_OK ) {
            if (!logDisabled)
                logger(LOG_INFO,
                        "OpenLI Mediator: RMQ Failed to load SSL cert/key");
            amqp_destroy_connection(amqp_state);
            return NULL;
        }

        //If no port is supplied use defualt
        if (medcol->rmqconf->port == 0) {
            medcol->rmqconf->port = 5671;
        }

        logger(LOG_INFO, "OpenLI Mediator: attempting to connect to RMQ using SSL on port %u", medcol->rmqconf->port);

        if (status = amqp_socket_open_noblock(ampq_sock, msgbody, medcol->rmqconf->port, &tv)){
            if (!logDisabled)
                logger(LOG_INFO,
                        "OpenLI Mediator: RMQ failed to open AMQP socket: %d",
                        status);
            amqp_destroy_connection(amqp_state);
            return NULL;
        }
        if ( (amqp_login(amqp_state, "OpenLI", 0, 131072, 
                medcol->rmqconf->heartbeatFreq,
                AMQP_SASL_METHOD_EXTERNAL, "EXTERNAL")
                ).reply_type != AMQP_RESPONSE_NORMAL ) {
            if (!logDisabled)
                logger(LOG_INFO, 
                        "OpenLI Mediator: RMQ Failed to login using EXTERNAL auth");
            amqp_destroy_connection(amqp_state);
            return NULL;
        }
    } else if (medcol->rmqconf->name && medcol->rmqconf->pass) {
        //start up socket with non SSL auth
        ampq_sock = amqp_tcp_socket_new(amqp_state);

        if (!ampq_sock) {
            if (!logDisabled)
                logger(LOG_INFO, 
                        "OpenLI Mediator: RMQ Error opening new TCP socket");
            amqp_destroy_connection(amqp_state);
            return NULL;
        }

        //If no port is supplied use defualt
        if (medcol->rmqconf->port == 0) {
            medcol->rmqconf->port = 5672;
        }

        if (amqp_socket_open_noblock(ampq_sock, msgbody, 5672, &tv)){
            if (!logDisabled)
                logger(LOG_INFO, 
                        "OpenLI Mediator: RMQ failed to open AMQP socket");
            amqp_destroy_connection(amqp_state);
            return NULL;
        }

        if (amqp_login(amqp_state, "OpenLI", 0, 131072, 
                medcol->rmqconf->heartbeatFreq, AMQP_SASL_METHOD_PLAIN,
                medcol->rmqconf->name, 
                medcol->rmqconf->pass).reply_type != AMQP_RESPONSE_NORMAL) {
            if (!logDisabled)
                logger(LOG_INFO, 
                        "OpenLI Mediator: RMQ Failed to login using PLAIN auth");
            amqp_destroy_connection(amqp_state);
            return NULL;
        }
    } else {
        if (!logDisabled)
            logger(LOG_INFO, 
                    "OpenLI Mediator: RMQ no valid login was provided");
        amqp_destroy_connection(amqp_state);
        return NULL;
    }

    amqp_channel_open_ok_t *r = amqp_channel_open(amqp_state, 1);
    
    if ( (amqp_get_rpc_reply(amqp_state).reply_type) != AMQP_RESPONSE_NORMAL ) {
        if (!logDisabled)
            logger(LOG_ERR, "OpenLI Mediator: RMQ Failed to open channel");
        amqp_destroy_connection(amqp_state);
        return NULL;
    }

    amqp_queue_declare_ok_t *queue_result = amqp_queue_declare(
            amqp_state,
            1,
            mstate->rmq_queueid,
            0,
            1,
            0,
            0,
            amqp_empty_table);

    if (amqp_get_rpc_reply(amqp_state).reply_type != AMQP_RESPONSE_NORMAL ) {
        if (!logDisabled)
            logger(LOG_INFO, "OpenLI Mediator: RMQ Failed to declare queue");
        amqp_destroy_connection(amqp_state);
        return NULL;
    }


    amqp_basic_consume_ok_t *con_ok = amqp_basic_consume(amqp_state,
            1,
            mstate->rmq_queueid,
            amqp_empty_bytes,
            0,
            0,
            0,
            amqp_empty_table);
    
    if (amqp_get_rpc_reply(amqp_state).reply_type != AMQP_RESPONSE_NORMAL ) {
        if (!logDisabled)
            logger(LOG_INFO, "OpenLI Mediator: RMQ Failed to register consumer");
        amqp_destroy_connection(amqp_state);
        return NULL;
    } else {
        if (!logDisabled)
            logger(LOG_INFO, "OpenLI Mediator: RMQ Registered consumer %s", 
                (char *)(mstate->rmq_queueid.bytes));
    }

    return amqp_state;
}

int receive_rmq_invite(mediator_collector_t *medcol,
		single_coll_state_t *mstate) {
    amqp_connection_state_t amqp_state = join_RMQ(medcol, mstate->ipaddr,
			mstate->iplen, 0, mstate);
	int sock_fd;

	if (!amqp_state) return -1;

    sock_fd = amqp_get_sockfd(amqp_state);
	if (sock_fd < 0) {
		return sock_fd;
	}

	mstate->amqp_state = amqp_state;
	if (mstate->incoming_rmq == NULL) {
	    mstate->incoming_rmq = create_net_buffer(NETBUF_RECV, 0, NULL);
	}

    return sock_fd;
}

int check_rmq_status(mediator_collector_t *medcol, active_collector_t *col) {

	amqp_frame_t frame;
    struct timeval tv;
	int ret;
	single_coll_state_t *cs = NULL;

    tv.tv_usec = 1;
    tv.tv_sec = 0;

	cs = (single_coll_state_t *)(col->colev->state);

	if (cs->amqp_state == NULL) {
		return 0;
	}

	ret = amqp_simple_wait_frame_noblock(cs->amqp_state, &frame, &tv);
	switch(ret) {
		case AMQP_STATUS_HEARTBEAT_TIMEOUT:
			logger(LOG_INFO,
					"OpenLI Mediator: RMQ Heartbeat timer expired for %s",
					cs->ipaddr);

		    return -1;
        case AMQP_STATUS_INVALID_PARAMETER:
        case AMQP_STATUS_NO_MEMORY:
		case AMQP_STATUS_BAD_AMQP_DATA:
		case AMQP_STATUS_UNKNOWN_METHOD:
		case AMQP_STATUS_UNKNOWN_CLASS:
		case AMQP_STATUS_TIMER_FAILURE:
		case AMQP_STATUS_SOCKET_ERROR:
		case AMQP_STATUS_SSL_ERROR:
			logger(LOG_INFO,
					"OpenLI Mediator: RMQ connection error, closing");
			return -1;
	}
	return 1;
}

// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :
