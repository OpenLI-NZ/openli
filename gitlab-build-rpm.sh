set -x -e -o pipefail

if [ "${CI_COMMIT_REF_NAME}" = "" ]; then
        CI_COMMIT_REF_NAME=1.0.4
fi

export QA_RPATHS=$[ 0x0001 ]
SOURCENAME=`echo ${CI_COMMIT_REF_NAME} | cut -d '-' -f 1`


DISTRO=fedora
if [ "$1" = "centos8" ]; then
        DISTRO=centos
fi

if [ "$1" = "centos7" ]; then
        DISTRO=centos
fi

if [ "$1" = "centos6" ]; then
        DISTRO=centos
fi

cat << EOF > /etc/yum.repos.d/bintray-wand-general-rpm.repo
#bintray-wand-general-rpm - packages by wand from Bintray
[bintray-wand-general-rpm]
name=bintray-wand-general-rpm
baseurl=https://dl.bintray.com/wand/general-rpm/${DISTRO}/\$releasever/\$basearch/
gpgkey=https://bintray.com/user/downloadSubjectPublicKey?username=wand
gpgcheck=0
repo_gpgcheck=1
enabled=1
EOF

cat << EOF > /etc/yum.repos.d/bintray-wand-libtrace-rpm.repo
#bintray-wand-libtrace-rpm - packages by wand from Bintray
[bintray-wand-libtrace-rpm]
name=bintray-wand-libtrace-rpm
baseurl=https://dl.bintray.com/wand/libtrace-rpm/${DISTRO}/\$releasever/\$basearch/
gpgkey=https://bintray.com/user/downloadSubjectPublicKey?username=wand
gpgcheck=0
repo_gpgcheck=1
enabled=1
EOF

cat << EOF > /etc/yum.repos.d/bintray-wand-openli-rpm.repo
#bintray-wand-openli-rpm - packages by wand from Bintray
[bintray-wand-openli-rpm]
name=bintray-wand-openli-rpm
baseurl=https://dl.bintray.com/wand/OpenLI-rpm/${DISTRO}/\$releasever/\$basearch/
gpgkey=https://bintray.com/user/downloadSubjectPublicKey?username=wand
gpgcheck=0
repo_gpgcheck=1
enabled=1
EOF

yum install -y wget make gcc

if [ "$1" = "centos8" ]; then
        yum module -v -y disable mariadb
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm || true
        dnf install -y 'dnf-command(config-manager)' || true
        yum config-manager --set-enabled PowerTools || true
fi


if [ "$1" = "centos7" ]; then
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm || true
fi

if [ "$1" = "centos6" ]; then
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm || true
        yum install -y epel-rpm-macros
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

./bootstrap.sh && ./configure && make dist
cp openli-*.tar.gz ~/rpmbuild/SOURCES/${SOURCENAME}.tar.gz
cp rpm/openli.spec ~/rpmbuild/SPECS/

cd ~/rpmbuild && rpmbuild -bb --define "debug_package %{nil}" SPECS/openli.spec

