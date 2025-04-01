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

#include <string.h>
#include <sys/types.h>
#include <time.h>

const char *insert_sql =
        "INSERT INTO observed_clients (identifier, type, ip_address, last_seen)"
        " VALUES (?, ?, ?, DATETIME('now')); ";
const char *update_sql =
        "UPDATE observed_clients SET last_seen = DATETIME('now') "
        "WHERE identifier = ? AND type = ? AND ip_address = ?;";

const char *select_sql =
        "SELECT * FROM observed_clients WHERE type = ?;";

const char *upsert_sql =
        "INSERT INTO observed_clients (identifier, type, ip_address, last_seen)"
        " VALUES (?, ?, ?, DATETIME('now')) "
        "ON CONFLICT(identifier, type, ip_address) DO UPDATE SET "
        "last_seen = (DATETIME('now')); ";

int init_clientdb(provision_state_t *state) {
    int rc;
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

    if (sqlite3_exec(state->clientdb, "CREATE TABLE IF NOT EXISTS observed_clients (identifier text not null, type text not null, ip_address text not null, first_seen text default (DATETIME('now', 'utc')), last_seen text default (DATETIME('now', 'utc')), primary key (identifier, type, ip_address));", NULL, NULL,
                NULL) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI provisioner: error while validating client table in client tracking database: %s", sqlite3_errmsg(state->clientdb));
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

    sqlite3_bind_text(ins_stmt, 1, col->client->ipaddress, -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 2, "collector", -1, SQLITE_STATIC);
    sqlite3_bind_text(ins_stmt, 3, col->client->ipaddress, -1, SQLITE_STATIC);

    if ((rc = sqlite3_step(ins_stmt)) == SQLITE_CONSTRAINT) {
        sqlite3_reset(upd_stmt);
        sqlite3_bind_text(upd_stmt, 1, col->client->ipaddress, -1,
                SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 2, "collector", -1, SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 3, col->client->ipaddress, -1,
                SQLITE_STATIC);

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

    if (state->clientdb == NULL) {
        return 0;
    }
    if (med == NULL || med->details == NULL || med->details->ipstr == NULL) {
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

    if ((rc = sqlite3_step(ins_stmt)) == SQLITE_CONSTRAINT) {
        sqlite3_reset(upd_stmt);
        sqlite3_bind_text(upd_stmt, 1, medid_str, -1, SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 2, "mediator", -1, SQLITE_STATIC);
        sqlite3_bind_text(upd_stmt, 3, med->details->ipstr, -1, SQLITE_STATIC);

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

known_client_t *_fetch_all_clients(provision_state_t *state,
        size_t *clientcount, const char *where, uint8_t client_enum) {

    int rc;
    sqlite3_stmt *sel_stmt;
    known_client_t *clients = NULL;
    size_t ind, rows;
    const char *id_text, *dt_text;
    struct tm tm;

    *clientcount = 0;
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

        clients[ind].medid = strtoul(id_text, NULL, 10);
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


