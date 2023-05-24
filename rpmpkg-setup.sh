#!/bin/bash
set -x -e -o pipefail

mkdir -p /run/user/${UID}
chmod 0700 /run/user/${UID}
yum install -y wget make gcc

curl -1sLf \
  'https://dl.cloudsmith.io/public/wand/libwandio/cfg/setup/bash.rpm.sh' \
    | bash

curl -1sLf \
  'https://dl.cloudsmith.io/public/wand/libwandder/cfg/setup/bash.rpm.sh' \
    | bash

curl -1sLf \
  'https://dl.cloudsmith.io/public/wand/libtrace/cfg/setup/bash.rpm.sh' \
    | bash

curl -1sLf \
  'https://dl.cloudsmith.io/public/wand/openli/cfg/setup/bash.rpm.sh' \
    | bash

yum update -y

if [[ "$1" =~ rocky* ]]; then
        dnf install -y dnf-plugins-core epel-release || true
        dnf config-manager --set-enabled powertools || true
        dnf module disable -y mariadb || true
        /usr/bin/crb enable || true
fi

if [[ "$1" =~ alma* ]]; then
        dnf install -y dnf-plugins-core epel-release || true
        dnf config-manager --set-enabled powertools || true
        /usr/bin/crb enable || true
fi

if [ "$1" = "centos:8" ]; then
        yum module -y disable mariadb
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm || true
        dnf install -y 'dnf-command(config-manager)' || true
        yum config-manager --set-enabled PowerTools || true
        yum config-manager --set-enabled powertools || true

fi

if [ "$1" = "centos:7" ]; then
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm || true
fi

if [[ "$1" =~ fedora* ]]; then
        dnf install -y rpm-build rpmdevtools 'dnf-command(builddep)' which
        dnf group install -y "C Development Tools and Libraries"
        dnf builddep -y rpm/openli.spec
else
        yum install -y rpm-build yum-utils rpmdevtools which
        yum groupinstall -y 'Development Tools'
        yum-builddep -y rpm/openli.spec
fi

rpmdev-setuptree
