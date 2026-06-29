#!/bin/bash

set -x -e -o pipefail

export DEBEMAIL='salcock@searchlight.nz'
export DEBFULLNAME='Shane Alcock'
export DEBIAN_FRONTEND=noninteractive

export SOURCENAME=`echo ${GITHUB_REF##*/} | cut -d '-' -f 1`

apt-get update
apt-get install -y equivs devscripts dpkg-dev quilt curl apt-transport-https \
    apt-utils ssl-cert ca-certificates gnupg lsb-release debhelper git \
    pkg-config sed

DISTRO_CODENAME=$(lsb_release -sc)
curl -fsSL https://packages.nz/repository-public-key.asc | sudo gpg --dearmor -o /etc/apt/keyrings/packages-nz.gpg
echo "deb [signed-by=/etc/apt/keyrings/packages-nz.gpg] https://openli.packages.nz/openli-dependencies/debian ${DISTRO_CODENAME} main" | sudo tee /etc/apt/sources.list.d/openli-deps-packages-nz.list
echo "deb [signed-by=/etc/apt/keyrings/packages-nz.gpg] https://openli.packages.nz/openli/debian ${DISTRO_CODENAME} main" | sudo tee /etc/apt/sources.list.d/openli-packages-nz.list
sudo apt update

apt-get update
apt-get upgrade -y
