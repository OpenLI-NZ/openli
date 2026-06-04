#!/bin/bash


if [ "$#" -lt 1 ]; then
        echo "Usage: $0 <key> <database file>"
        exit 1
fi

AUTHKEY=$1

if [ "$#" -lt 2 ]; then
        echo "No database filename provided as an argument, using /var/lib/openli/cinstate.db"
        mkdir -p /var/lib/openli/
        DBFILE=/var/lib/openli/cinstate.db
else
        DBFILE=$2
fi

sqlcipher $DBFILE "PRAGMA key=\"${AUTHKEY}\"; CREATE TABLE IF NOT EXISTS cinstate (liid text, cin integer, iriseqno integer, ccseqno integer, PRIMARY KEY (liid,cin));"

