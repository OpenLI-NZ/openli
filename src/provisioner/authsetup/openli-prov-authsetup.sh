#!/bin/bash


if [ "$#" -lt 1 ]; then
        echo "Usage: $0 <key> <database file>"
        exit 1
fi

AUTHKEY=$1

if [ "$#" -lt 2 ]; then
        echo "No database filename provided as an argument, using /var/lib/openli/provauth.db"
        mkdir -p /var/lib/openli/
        DBFILE=/var/lib/openli/provauth.db
else
        DBFILE=$2
fi


sqlcipher $DBFILE "PRAGMA key=\"${AUTHKEY}\"; CREATE TABLE IF NOT EXISTS authcreds (username text primary key, digesthash blob not null, apikey text null);"
