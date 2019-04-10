#!/bin/bash

set -x -e -o pipefail

export DEBEMAIL='packaging@wand.net.nz'
export DEBFULLNAME='WAND Packaging'
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y equivs devscripts dpkg-dev quilt curl apt-transport-https \
    apt-utils ssl-cert ca-certificates gnupg lsb-release debhelper git
apt-get upgrade -y

echo "deb https://dl.bintray.com/wand/general $(lsb_release -sc) main" | \
    tee -a /etc/apt/sources.list.d/wand.list
echo "deb https://dl.bintray.com/wand/libtrace $(lsb_release -sc) main" | \
    tee -a /etc/apt/sources.list.d/wand.list
curl --silent "https://bintray.com/user/downloadSubjectPublicKey?username=wand"\
 | apt-key add -

apt-get update
apt-get upgrade -y

dpkg-parsechangelog -S version | grep -q ${CI_COMMIT_REF_NAME} || debchange --newversion ${CI_COMMIT_REF_NAME} -b "New upstream release"
mk-build-deps -i -r -t 'apt-get -f -y --force-yes'
dpkg-buildpackage -b -us -uc -rfakeroot -j4
