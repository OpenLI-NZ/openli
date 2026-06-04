/*
 *
 * Copyright (c) 2026 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * OpenLI was originally developed by the University of Waikato WAND
 * research group. For further information about OpenLI, please see
 * https://openli.nz/
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

#include "config.h"
#include "logger.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "cinstatedb.h"

#if HAVE_SQLCIPHER
#include <sqlcipher/sqlite3.h>
#endif

const char *select_cinstate_sql =
        "SELECT iriseqno, ccseqno FROM cinstate WHERE "
        "liid = ? AND cin = ?;";

const char *update_cinstate_sql =
        "INSERT INTO cinstate (liid, cin, iriseqno, ccseqno) "
        " VALUES (?, ?, ?, ?) ON CONFLICT (liid, cin) DO "
        "UPDATE SET iriseqno=excluded.iriseqno, ccseqno=excluded.ccseqno; ";

const char *remove_cinstate_liid_sql =
        "DELETE FROM cinstate WHERE liid = ?;";

uint8_t cinstate_db_connect(char *filepath, char *key, void **dbptr) {
    int rc;

    if (filepath == NULL || key == NULL) {
        return 0;
    }

#if HAVE_SQLCIPHER
    rc = sqlite3_open(filepath, (sqlite3 **)dbptr);
    if (rc != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI collector: failed to open CIN state tracking database at %s: %s", filepath, sqlite3_errmsg(*dbptr));
        rc = -1;
        goto endconnect;
    }

    sqlite3_key(*dbptr, key, strlen(key));

    if (sqlite3_exec(*dbptr, "CREATE TABLE IF NOT EXISTS cinstate (liid text, cin integer, iriseqno integer, ccseqno integer, iribegin boolean, iriend boolean, PRIMARY KEY (liid,cin));", NULL, NULL, NULL) != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI collector: error while validating table in CIN state tracking database: %s", sqlite3_errmsg(*dbptr));
        rc = -1;
    }

endconnect:
    if (rc == -1) {
        sqlite3_close(*dbptr);
        *dbptr = NULL;
        return 0;
    }

    return 1;

#else
    return 0;
#endif

}

void cinstate_db_close(void **dbptr) {
    if (dbptr == NULL || *dbptr == NULL) {
        return;
    }
#if HAVE_SQLCIPHER
    sqlite3_close(*dbptr);
#endif
    *dbptr = NULL;
}

void cinstate_db_lookup(void *dbptr, char *liid, uint32_t cin,
        struct cinstate_t *result) {

    if (dbptr == NULL) {
        return;
    }

#if HAVE_SQLCIPHER
    sqlite3_stmt *sel_stmt;
    int rc, step;

    rc = sqlite3_prepare_v2(dbptr, select_cinstate_sql, -1, &sel_stmt, NULL);
    if (rc != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI collector: error while preparing statement to perform lookup in CIN state tracking database: %s", sqlite3_errmsg(dbptr));
        return;
    }

    sqlite3_bind_text(sel_stmt, 1, liid, -1, SQLITE_STATIC);
    sqlite3_bind_int(sel_stmt, 2, cin);

    step = sqlite3_step(sel_stmt);
    if (step == SQLITE_ROW) {
        result->iri_seqno = sqlite3_column_int(sel_stmt, 0);
        result->cc_seqno = sqlite3_column_int(sel_stmt, 1);
    }

    sqlite3_finalize(sel_stmt);
#endif

}

int cinstate_db_update(void *dbptr, char *liid, uint32_t cin,
        struct cinstate_t *update) {

    if (dbptr == NULL) {
        return 0;
    }
    if (liid == NULL || update == NULL) {
        return 0;
    }

#if HAVE_SQLCIPHER
    sqlite3_stmt *upd_stmt;
    int rc;

    if (sqlite3_prepare_v2(dbptr, update_cinstate_sql, -1, &upd_stmt, 0)
            != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI collector: failed to prepare upsert statement for CIN state database: %s", sqlite3_errmsg(dbptr));
        return -1;
    }

    sqlite3_bind_text(upd_stmt, 1, liid, -1, SQLITE_STATIC);
    sqlite3_bind_int(upd_stmt, 2, cin);
    sqlite3_bind_int(upd_stmt, 3, update->iri_seqno);
    sqlite3_bind_int(upd_stmt, 4, update->cc_seqno);

    rc = sqlite3_step(upd_stmt);
    if (rc != SQLITE_DONE) {
        logger(LOG_INFO, "OpenLI collector: failed to execute upsert statement for CIN state database: %s", sqlite3_errmsg(dbptr));
        return -1;
    }

    sqlite3_finalize(upd_stmt);
    return 1;

#endif
    return 0;
}

int cinstate_db_remove_by_liid(void *dbptr, char *liid) {

    if (dbptr == NULL || liid == NULL) {
        return 0;
    }

#if HAVE_SQLCIPHER
    sqlite3_stmt *del_stmt;
    int rc;

    if (sqlite3_prepare_v2(dbptr, remove_cinstate_liid_sql, -1, &del_stmt, 0)
            != SQLITE_OK) {
        logger(LOG_INFO, "OpenLI collector: failed to prepare delete statement for CIN state database: %s", sqlite3_errmsg(dbptr));
        return -1;
    }

    sqlite3_bind_text(del_stmt, 1, liid, -1, SQLITE_STATIC);
    if ((rc = sqlite3_step(del_stmt)) != SQLITE_DONE)  {
        logger(LOG_INFO, "OpenLI collector: failed to execute delete statement for CIN state database: %s", sqlite3_errmsg(dbptr));
        return -1;
    }

    sqlite3_finalize(del_stmt);
    return 1;

#endif
    return 0;

}
