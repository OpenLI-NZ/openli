/*
 *
 * Copyright (c) 2025 SearchLight Ltd, New Zealand.
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
#define _GNU_SOURCE

#include "provisioner.h"
#include "updateserver.h"
#include "logger.h"

#ifdef HAVE_SQLCIPHER
#include <sqlcipher/sqlite3.h>
#endif

#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

const char *insert_x2x3_sql =
        "INSERT INTO x2x3_listeners (collector, ip_address, port, last_seen)"
        " VALUES (?, ?, ?, ?); ";
const char *update_x2x3_sql =
        "UPDATE x2x3_listeners SET last_seen = ? "
        "WHERE collector = ? AND ip_address = ? AND port = ?;";
const char *select_x2x3_sql =
        "SELECT * FROM x2x3_listeners WHERE collector = ? AND last_seen > ?;";

const char *insert_udpsink_sql =
        "INSERT INTO udp_sinks (collector, ip_address, port, "
        "identifier, last_seen)"
        " VALUES (?, ?, ?, ?, ?); ";
const char *update_udpsink_sql =
        "UPDATE udp_sinks SET last_seen = ? WHERE "
        "collector = ? AND ip_address = ? AND port = ? AND identifier = ?;";
const char *select_udpsink_sql =
        "SELECT * FROM udp_sinks WHERE collector = ? AND last_seen > ?;";

const char *insert_sql =
        "INSERT INTO observed_clients (identifier, type, ip_address, last_seen,"
        " config_json)"
        " VALUES (?, ?, ?, DATETIME('now'), ?); ";
const char *update_sql =
        "UPDATE observed_clients SET last_seen = DATETIME('now'), "
        "ip_address = ?, config_json = ? "
        "WHERE identifier = ? AND type = ?;";

const char *select_sql =
        "SELECT * FROM observed_clients WHERE type = ?;";

const char *remove_client_sql =
        "DELETE FROM observed_clients WHERE type = ? AND identifier = ?;";

const char *remove_x2x3_sql =
        "DELETE FROM x2x3_listeners WHERE collector = ?;";

const char *remove_udpsink_sql =
        "DELETE FROM udp_sinks WHERE collector = ?;";

const char *upsert_sql =
        "INSERT INTO observed_clients (identifier, type, ip_address, last_seen)"
        " VALUES (?, ?, ?, DATETIME('now')) "
        "ON CONFLICT(identifier, type) DO UPDATE SET "
        "last_seen = (DATETIME('now')), ip_address = ?; ";

int init_clientdb(provision_state_t *state) {
    int rc;
    char *errmsg = NULL;

    if (state == NULL) {
        return 0;
    }

#ifdef HAVE_SQLCIPHER
    if (state->clientdb) {
        sqlite3_close(state->clientdb);
    }

    rc = sqlite3_open(state->clientdbfile, (sqlite3 **)(&(state->clientdb)));
    if (rc != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: failed to open client tracking database at %s: %s",
                state->clientdbfile, sqlite3_errmsg(state->clientdb));
        rc = -1;
        goto endofinit;
    }

    if (state->clientdbkey == NULL) {
        logger(LOG_INFO, "OpenLI provisioner: no key has been provided to access client tracking database");
        rc = -1;
        goto endofinit;
    }

    sqlite3_key(state->clientdb, state->clientdbkey,
            strlen(state->clientdbkey));

    if (sqlite3_exec(state->clientdb, "CREATE TABLE IF NOT EXISTS observed_clients (identifier text not null, type text not null, ip_address text not null, first_seen text default (DATETIME('now')), last_seen text default (DATETIME('now')), primary key (identifier, type));", NULL, NULL,
                NULL) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: error while validating client table in client tracking database: %s", sqlite3_errmsg(state->clientdb));
        rc = -1;
        goto endofinit;
    }

    if (sqlite3_exec(state->clientdb, "ALTER TABLE observed_clients ADD COLUMN config_json TEXT", NULL, NULL, &errmsg) != SQLITE_OK) {
        if (errmsg && strstr(errmsg, "duplicate column name")) {
            // column already exists, carry on
        } else {
            logger(LOG_INFO, "OpenLI provisioner: error while validating client table in client tracking database: %s", sqlite3_errmsg(state->clientdb));
            rc = -1;
            goto endofinit;
        }
    }

    if (sqlite3_exec(state->clientdb, "CREATE TABLE IF NOT EXISTS x2x3_listeners (collector text not null, ip_address text not null, port text not null, last_seen text default (DATETIME('now')), primary key (collector, port, ip_address));", NULL, NULL,
                NULL) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: error while validating x2x3 listener table in client tracking database: %s", sqlite3_errmsg(state->clientdb));
        rc = -1;
        goto endofinit;
    }

    if (sqlite3_exec(state->clientdb, "CREATE TABLE IF NOT EXISTS udp_sinks (collector text not null, ip_address text not null, port text not null, identifier text not null, last_seen text default (DATETIME('now')), primary key (collector, port, ip_address, identifier));", NULL, NULL,
                NULL) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: error while validating UDP sink table in client tracking database: %s", sqlite3_errmsg(state->clientdb));
        rc = -1;
        goto endofinit;
    }

    logger(LOG_INFO, "OpenLI provisioner: client tracking database enabled.");
    state->clientdbenabled = 1;
    rc = 1;
#else
    state->clientdb = NULL;
    rc = 0;
#endif

endofinit:
    if (rc == -1) {
        sqlite3_close(state->clientdb);
        state->clientdb = NULL;
        state->clientdbenabled = 0;
    }
    return rc;
}

int update_udp_sink_row(provision_state_t *state, prov_collector_t *col,
       char *listenaddr, char *listenport, char *identifier,
       uint64_t timestamp) {

    if (state->clientdb == NULL) {
        return 0;
    }

    if (col == NULL || col->client == NULL || col->client->ipaddress == NULL) {
        return 0;
    }

#if HAVE_SQLCIPHER
    sqlite3_stmt *ins_stmt, *upd_stmt;
    int rc;
    char dt_str[32];
    struct tm *tm_info;
    time_t ts = (time_t) timestamp;

    if (sqlite3_prepare_v2(state->clientdb, insert_udpsink_sql, -1, &ins_stmt,
            0) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: failed to prepare insert statement for UDP sink database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    if (sqlite3_prepare_v2(state->clientdb, update_udpsink_sql, -1, &upd_stmt,
            0) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: failed to prepare update statement for UDP sink database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    tm_info = gmtime(&ts);
    strftime(dt_str, 32, "%Y-%m-%d %H:%M:%S", tm_info);

    sqlite3_bind_text(ins_stmt, 1, col->identifier, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 2, listenaddr, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 3, listenport, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 4, identifier, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 5, dt_str, -1, SQLITE_STATIC);

    if ((rc = sqlite3_step(ins_stmt)) == SQLITE_CONSTRAINT) {
        sqlite3_reset(upd_stmt);
        sqlite3_bind_text(upd_stmt, 1, dt_str, -1, SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 2, col->identifier, -1,
                SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 3, listenaddr, -1, SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 4, listenport, -1, SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 5, identifier, -1, SQLITE_STATIC);

        rc = sqlite3_step(upd_stmt);
    }

    if (rc != SQLITE_DONE) {
        logger(LOG_INFO, "OpenLI provisioner: failed to execute upsert statement for UDP sink database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    sqlite3_finalize(ins_stmt);
    sqlite3_finalize(upd_stmt);
#endif
    return 1;
}

int update_x2x3_listener_row(provision_state_t *state, prov_collector_t *col,
       char *listenaddr, char *listenport, uint64_t timestamp) {

    if (state->clientdb == NULL) {
        return 0;
    }

    if (col == NULL || col->client == NULL || col->client->ipaddress == NULL) {
        return 0;
    }

#if HAVE_SQLCIPHER
    sqlite3_stmt *ins_stmt, *upd_stmt;
    int rc;
    char dt_str[32];
    struct tm *tm_info;
    time_t ts = (time_t) timestamp;

    if (sqlite3_prepare_v2(state->clientdb, insert_x2x3_sql, -1, &ins_stmt,
            0) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: failed to prepare insert statement for x2x3 listener database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    if (sqlite3_prepare_v2(state->clientdb, update_x2x3_sql, -1, &upd_stmt,
            0) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: failed to prepare update statement for x2x3 listener database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    tm_info = gmtime(&ts);
    strftime(dt_str, 32, "%Y-%m-%d %H:%M:%S", tm_info);

    sqlite3_bind_text(ins_stmt, 1, col->identifier, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 2, listenaddr, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 3, listenport, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 4, dt_str, -1, SQLITE_STATIC);

    if ((rc = sqlite3_step(ins_stmt)) == SQLITE_CONSTRAINT) {
        sqlite3_reset(upd_stmt);
        sqlite3_bind_text(upd_stmt, 1, dt_str, -1, SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 2, col->identifier, -1,
                SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 3, listenaddr, -1, SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 4, listenport, -1, SQLITE_STATIC);

        rc = sqlite3_step(upd_stmt);
    }

    if (rc != SQLITE_DONE) {
        logger(LOG_INFO, "OpenLI provisioner: failed to execute upsert statement for x2x3 listener database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    sqlite3_finalize(ins_stmt);
    sqlite3_finalize(upd_stmt);
#endif
    return 1;
}

int update_collector_client_row(provision_state_t *state,
        prov_collector_t *col) {

    if (state->clientdb == NULL) {
        return 0;
    }
    if (col == NULL || col->client == NULL || col->client->ipaddress == NULL) {
        return 0;
    }
#if HAVE_SQLCIPHER
    sqlite3_stmt *ins_stmt, *upd_stmt;
    int rc;

    if (sqlite3_prepare_v2(state->clientdb, insert_sql, -1, &ins_stmt, 0) !=
                SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: failed to prepare insert statement for client tracking database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    if (sqlite3_prepare_v2(state->clientdb, update_sql, -1, &upd_stmt, 0) !=
                SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: failed to prepare update statement for client tracking database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    sqlite3_bind_text(ins_stmt, 1, col->identifier, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 2, "collector", -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 3, col->client->ipaddress, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 4, col->jsonconfig, -1, SQLITE_STATIC);

    if ((rc = sqlite3_step(ins_stmt)) == SQLITE_CONSTRAINT) {
        sqlite3_reset(upd_stmt);
        sqlite3_bind_text(upd_stmt, 1, col->client->ipaddress, -1,
                SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 2, col->jsonconfig, -1, SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 3, col->identifier, -1,
                SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 4, "collector", -1, SQLITE_STATIC);

        rc = sqlite3_step(upd_stmt);
    }

    if (rc != SQLITE_DONE) {
        logger(LOG_INFO, "OpenLI provisioner: failed to execute upsert statement for client tracking database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    sqlite3_finalize(ins_stmt);
    sqlite3_finalize(upd_stmt);
#endif
    return 1;
}

int update_mediator_client_row(provision_state_t *state, prov_mediator_t *med) {
    prov_sock_state_t *cs = med->client->state;

    if (state->clientdb == NULL) {
        return 0;
    }
    if (med == NULL || med->details == NULL || med->details->ipstr == NULL) {
        return 0;
    }
    if (cs->halted || !cs->trusted) {
        return 0;
    }
#if HAVE_SQLCIPHER
    sqlite3_stmt *ins_stmt, *upd_stmt;
    char medid_str[128];
    int rc;

    if (sqlite3_prepare_v2(state->clientdb, insert_sql, -1, &ins_stmt, 0) !=
                SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: failed to prepare insert statement for client tracking database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    if (sqlite3_prepare_v2(state->clientdb, update_sql, -1, &upd_stmt, 0) !=
                SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: failed to prepare update statement for client tracking database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    snprintf(medid_str, 128, "%u", med->mediatorid);
    sqlite3_bind_text(ins_stmt, 1, medid_str, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 2, "mediator", -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 3, med->details->ipstr, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 4, NULL, -1, SQLITE_STATIC);

    if ((rc = sqlite3_step(ins_stmt)) == SQLITE_CONSTRAINT) {
        sqlite3_reset(upd_stmt);
        sqlite3_bind_text(upd_stmt, 1, med->details->ipstr, -1, SQLITE_STATIC);
        sqlite3_bind_text(ins_stmt, 2, NULL, -1, SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 3, medid_str, -1, SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 4, "mediator", -1, SQLITE_STATIC);

        rc = sqlite3_step(upd_stmt);
    }

    if (rc != SQLITE_DONE) {
        logger(LOG_INFO, "OpenLI provisioner: failed to execute upsert statement for client tracking database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    sqlite3_finalize(ins_stmt);
    sqlite3_finalize(upd_stmt);
#endif
    return 1;
}

void update_all_client_rows(provision_state_t *state) {
    prov_mediator_t *med, *medtmp;
    prov_collector_t *col, *coltmp;

    HASH_ITER(hh, state->mediators, med, medtmp) {
        update_mediator_client_row(state, med);
    }
    HASH_ITER(hh, state->collectors, col, coltmp) {
        update_collector_client_row(state, col);
    }

}

static char from_hex(char c) {
    if (isdigit(c)) return c - '0';
    if (isxdigit(c)) return tolower(c) - 'a' + 10;
    return 0;
}

static void url_decode(char *dst, const char *src) {
    while (*src) {
        if (*src == '%' && strlen(src) >= 3 && isxdigit(src[1]) &&
                isxdigit(src[2])) {
            *dst++ = from_hex(src[1]) << 4 | from_hex(src[2]);
            src += 3;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

int remove_collector_from_clientdb(provision_state_t *state, const char *idstr)
{

#ifdef HAVE_SQLCIPHER
    prov_collector_t *col, *coltmp;
    sqlite3_stmt *del_stmt, *del_x2x3_stmt, *del_udpsink_stmt;
    int rc;
    char decoded[4096];

    if (strlen(idstr) >= 4096) {
        logger(LOG_INFO, "OpenLI provisioner: collector identifier received via REST API is too long!");
        return -1;
    }

    url_decode(decoded, idstr);
    HASH_ITER(hh, state->collectors, col, coltmp) {
        if (strcmp(col->identifier, decoded) == 0) {
            /* this collector is connected, can't delete it! */
            return 0;
        }
    }

    if (sqlite3_prepare_v2(state->clientdb, remove_client_sql, -1,
            &del_stmt, 0) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: failed to prepare DELETE observed statement for client tracking database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    if (sqlite3_prepare_v2(state->clientdb, remove_x2x3_sql, -1,
            &del_x2x3_stmt, 0) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: failed to prepare DELETE x2x3 statement for client tracking database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    if (sqlite3_prepare_v2(state->clientdb, remove_udpsink_sql, -1,
            &del_udpsink_stmt, 0) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: failed to prepare DELETE UDP sink statement for client tracking database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    sqlite3_bind_text(del_stmt, 1, "collector", -1, SQLITE_STATIC);
    sqlite3_bind_text(del_stmt, 2, decoded, -1, SQLITE_STATIC);

    if ((rc = sqlite3_step(del_stmt)) != SQLITE_DONE) {
        logger(LOG_INFO, "OpenLI provisioner: failed to execute DELETE collector statement for client tracking database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    sqlite3_bind_text(del_x2x3_stmt, 1, decoded, -1, SQLITE_STATIC);
    if ((rc = sqlite3_step(del_x2x3_stmt)) != SQLITE_DONE) {
        logger(LOG_INFO, "OpenLI provisioner: failed to execute DELETE x2x3 statement for client tracking database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    sqlite3_bind_text(del_udpsink_stmt, 1, decoded, -1, SQLITE_STATIC);
    if ((rc = sqlite3_step(del_udpsink_stmt)) != SQLITE_DONE) {
        logger(LOG_INFO, "OpenLI provisioner: failed to execute DELETE UDP sink statement for client tracking database: %s", sqlite3_errmsg(state->clientdb));
        return -1;
    }

    sqlite3_finalize(del_stmt);
    sqlite3_finalize(del_x2x3_stmt);
    sqlite3_finalize(del_udpsink_stmt);
#endif

    return 1;
}

collector_udp_sink_t *fetch_udp_sinks_for_collector(provision_state_t *state,
        size_t *sinkcount, const char *collectorid) {

    collector_udp_sink_t *sinks = NULL;
    *sinkcount = 0;

#ifdef HAVE_SQLCIPHER
    int rc;
    sqlite3_stmt *sel_stmt;
    size_t ind, rows;
    struct tm tm;
    const char *dt_text;

    rows = 0;

    rc = sqlite3_prepare_v2(state->clientdb, select_udpsink_sql, -1, &sel_stmt,
            NULL);
    if (rc != SQLITE_OK) {
        return NULL;
    }

    sqlite3_bind_text(sel_stmt, 1, collectorid, -1, SQLITE_STATIC);
    sqlite3_bind_int(sel_stmt, 2, 0);
    while (sqlite3_step(sel_stmt) == SQLITE_ROW) {
        rows ++;
    }
    sqlite3_reset(sel_stmt);

    if (rows == 0) {
        return NULL;
    }
    sinks = calloc(rows, sizeof(collector_udp_sink_t));
    *sinkcount = rows;
    ind = 0;

    while (sqlite3_step(sel_stmt) == SQLITE_ROW && ind < rows) {

        sinks[ind].ipaddr =
                strdup((const char *)sqlite3_column_text(sel_stmt, 1));
        sinks[ind].port =
                strdup((const char *)sqlite3_column_text(sel_stmt, 2));
        sinks[ind].identifier =
                strdup((const char *)sqlite3_column_text(sel_stmt, 3));

        dt_text = (const char *)sqlite3_column_text(sel_stmt, 4);
        memset(&tm, 0, sizeof(struct tm));
        if (dt_text && strptime(dt_text, "%Y-%m-%d %H:%M:%S", &tm)) {
            sinks[ind].lastseen = timegm(&tm);
        }
        ind ++;
    }
#endif
    return sinks;
}

x2x3_listener_t *fetch_x2x3_listeners_for_collector(provision_state_t *state,
        size_t *listenercount, const char *collectorid) {

    x2x3_listener_t *x2x3 = NULL;
    *listenercount = 0;
#ifdef HAVE_SQLCIPHER
    int rc;
    sqlite3_stmt *sel_stmt;
    size_t ind, rows;
    struct tm tm;
    const char *dt_text;

    rows = 0;

    rc = sqlite3_prepare_v2(state->clientdb, select_x2x3_sql, -1, &sel_stmt,
            NULL);
    if (rc != SQLITE_OK) {
        return NULL;
    }

    sqlite3_bind_text(sel_stmt, 1, collectorid, -1, SQLITE_STATIC);
    sqlite3_bind_int(sel_stmt, 2, 0);
    while (sqlite3_step(sel_stmt) == SQLITE_ROW) {
        rows ++;
    }
    sqlite3_reset(sel_stmt);

    if (rows == 0) {
        return NULL;
    }
    x2x3 = calloc(rows, sizeof(x2x3_listener_t));
    *listenercount = rows;
    ind = 0;

    while (sqlite3_step(sel_stmt) == SQLITE_ROW && ind < rows) {

        x2x3[ind].ipaddr =
                strdup((const char *)sqlite3_column_text(sel_stmt, 1));
        x2x3[ind].port =
                strdup((const char *)sqlite3_column_text(sel_stmt, 2));

        dt_text = (const char *)sqlite3_column_text(sel_stmt, 3);
        memset(&tm, 0, sizeof(struct tm));
        if (dt_text && strptime(dt_text, "%Y-%m-%d %H:%M:%S", &tm)) {
            x2x3[ind].lastseen = timegm(&tm);
        }
        ind ++;
    }
#endif
    return x2x3;
}

known_client_t *_fetch_all_clients(provision_state_t *state,
        size_t *clientcount, const char *where, uint8_t client_enum) {

    known_client_t *clients = NULL;
    *clientcount = 0;

#ifdef HAVE_SQLCIPHER
    int rc;
    sqlite3_stmt *sel_stmt;
    size_t ind, rows;
    const char *id_text, *dt_text;
    struct tm tm;

    rows = 0;

    rc = sqlite3_prepare_v2(state->clientdb, select_sql, -1, &sel_stmt, NULL);
    if (rc != SQLITE_OK) {
        return NULL;
    }

    sqlite3_bind_text(sel_stmt, 1, where, -1, SQLITE_STATIC);
    while (sqlite3_step(sel_stmt) == SQLITE_ROW) {
        rows ++;
    }

    sqlite3_reset(sel_stmt);
    if (rows == 0) {
        return NULL;
    }

    clients = calloc(rows, sizeof(known_client_t));
    if (clients == NULL) {
        return NULL;
    }

    ind = 0;
    while (sqlite3_step(sel_stmt) == SQLITE_ROW && ind < rows) {
        id_text = (const char *)sqlite3_column_text(sel_stmt, 0);

        if (client_enum == TARGET_MEDIATOR) {
            clients[ind].medid = strtoul(id_text, NULL, 10);
            clients[ind].colname = NULL;
        } else {
            clients[ind].colname = strdup(id_text);
            clients[ind].medid = 0xFFFFFFFF;
        }

        clients[ind].type = client_enum;
        clients[ind].ipaddress =
                strdup((const char *)sqlite3_column_text(sel_stmt, 2));

        dt_text = (const char *)sqlite3_column_text(sel_stmt, 3);
        memset(&tm, 0, sizeof(struct tm));
        if (dt_text && strptime(dt_text, "%Y-%m-%d %H:%M:%S", &tm)) {
            clients[ind].firstseen = timegm(&tm);
        }

        dt_text = (const char *)sqlite3_column_text(sel_stmt, 4);
        memset(&tm, 0, sizeof(struct tm));
        if (dt_text && strptime(dt_text, "%Y-%m-%d %H:%M:%S", &tm)) {
            clients[ind].lastseen = timegm(&tm);
        }
        ind ++;
    }
    *clientcount = rows;
#endif
    return clients;

}

known_client_t *fetch_all_mediator_clients(provision_state_t *state,
        size_t *clientcount) {

    return _fetch_all_clients(state, clientcount, "mediator", TARGET_MEDIATOR);
}

known_client_t *fetch_all_collector_clients(provision_state_t *state,
        size_t *clientcount) {

    return _fetch_all_clients(state, clientcount, "collector",
            TARGET_COLLECTOR);
}


void close_clientdb(provision_state_t *state) {
#ifdef HAVE_SQLCIPHER
    if (state->clientdb) {
        sqlite3_close(state->clientdb);
    }
#endif
    state->clientdb = NULL;
    return;
}


