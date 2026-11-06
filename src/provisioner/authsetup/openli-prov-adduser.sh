#!/bin/bash

if [ "$#" -lt 4 ]; then
        echo "Usage: $0 <key> <username> <password> <role> [<database file>] "
        exit 1
fi

if [ "$#" -lt 5 ]; then
        echo "No database filename provided as an argument, using /var/lib/openli/provauth.db"
        DBFILE=/var/lib/openli/provauth.db
else
        DBFILE=$5
fi

VALIDROLES=( "admin" "intercepts" "system" )

AUTHKEY=$1
NEWUSER=$2
PWORD=$3
ROLE=$4

ROLE_OK=0

for r in "${VALIDROLES[@]}"; do
    if [ "${ROLE}" == "${r}" ]; then
        ROLE_OK=1;
        break;
    fi
done

if [ ${ROLE_OK} -eq 0 ]; then
    echo "Error: unsupported role '${ROLE}', must be one of ${VALIDROLES[*]}"
    echo
    echo "Usage: $0 <key> <username> <password> <role> [<database file>] "
    exit 1
fi

DIGESTHASH=`echo -n "${NEWUSER}:provisioner@openli.nz:${PWORD}" | md5sum | cut -d ' ' -f 1`
APIKEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)


sqlcipher $DBFILE "PRAGMA key=\"${AUTHKEY}\"; INSERT INTO authcreds VALUES ('${NEWUSER}', '${DIGESTHASH}', '${APIKEY}', '${ROLE}');"

if [ $? -eq 0 ]; then
        echo "Successfully added new user ${NEWUSER} with role ${ROLE} -- API key is ${APIKEY}";
        exit 0
else
        echo "Failed to add new user ${NEWUSER}"
fi

