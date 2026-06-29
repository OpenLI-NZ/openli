#!/bin/bash
set -x -e -o pipefail

mkdir -p /run/user/${UID}
chmod 0700 /run/user/${UID}
yum install -y wget make gcc sudo

DISTRO_SUFFIX=$(rpm --eval '%{dist}' | tr -d '.')
DISTRO_VERSION=$(echo "$DISTRO_SUFFIX" | tr -d -c '0-9')

sudo -E dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-${DISTRO_VERSION}.noarch.rpm
sudo /usr/bin/crb enable

cat << EOF > /tmp/packages-nz-openli.repo
[openli]
name=OpenLI Repository from packages.nz
baseurl=https://openli.packages.nz/redhat/${DISTRO_SUFFIX}/x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.nz/repository-public-key.asc

[openlideps]
name=OpenLI Dependencies Repository from packages.nz
baseurl=https://openli.packages.nz/openli-dependencies/redhat/${DISTRO_SUFFIX}/x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.nz/repository-public-key.asc

[libtrace]
name=OpenLI Dependencies Repository from packages.nz
baseurl=https://libtrace.packages.nz/libtrace/redhat/${DISTRO_SUFFIX}/x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.nz/repository-public-key.asc
EOF

sudo mv /tmp/packages-nz-openli.repo /etc/yum.repos.d/

yum update -y

dnf install -y dnf-plugins-core || true
dnf module disable -y mariadb || true

yum install -y rpm-build yum-utils rpmdevtools which
yum groupinstall -y 'Development Tools'
yum-builddep -y rpm/openli.spec

rpmdev-setuptree
