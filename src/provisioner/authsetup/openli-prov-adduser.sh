#!/bin/bash

if [ "$#" -lt 3 ]; then
        echo "Usage: $0 <key> <username> <password> <database file>"
        exit 1
fi

if [ "$#" -lt 4 ]; then
        echo "No database filename provided as an argument, using /var/lib/openli/provauth.db"
        DBFILE=/var/lib/openli/provauth.db
else
        DBFILE=$4
fi

AUTHKEY=$1
NEWUSER=$2
PWORD=$3

DIGESTHASH=`echo -n "${NEWUSER}:provisioner@openli.nz:${PWORD}" | md5sum | cut -d ' ' -f 1`
APIKEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)


sqlcipher $DBFILE "PRAGMA key=\"${AUTHKEY}\"; INSERT INTO authcreds VALUES ('${NEWUSER}', '${DIGESTHASH}', '${APIKEY}');"

if [ $? -eq 0 ]; then
        echo "Successfully added new user ${NEWUSER} -- API key is ${APIKEY}";
        exit 0
else
        echo "Failed to add new user ${NEWUSER}"
fi

