Name:           openli
Version:        1.1.17
Release:        1%{?dist}
Summary:        Software for performing ETSI-compliant lawful intercept

License:        GPLv3
URL:            https://github.com/OpenLI-NZ/OpenLI
Source0:        https://github.com/OpenLI-NZ/OpenLI/archive/%{version}.tar.gz

BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: bison
BuildRequires: doxygen
BuildRequires: flex
BuildRequires: libyaml-devel
BuildRequires: libtrace4-devel >= 4.0.29
BuildRequires: Judy-devel
BuildRequires: uthash-devel
BuildRequires: libwandder2-devel >= 2.0.17
BuildRequires: zeromq-devel
BuildRequires: gperftools-devel
BuildRequires: libosip2-devel >= 5.0.0
BuildRequires: openssl-devel
BuildRequires: json-c-devel
BuildRequires: libmicrohttpd-devel
BuildRequires: systemd
BuildRequires: sqlcipher-devel
BuildRequires: librabbitmq-devel
BuildRequires: libb64-devel
BuildRequires: zlib-devel
BuildRequires: libuuid-devel

%description
Software for performing ETSI-compliant lawful intercept

%package        provisioner
Summary:        Central provisioning daemon for an OpenLI system
Requires:       bash
Requires:       sqlcipher
Requires(pre):  shadow-utils

%description provisioner
OpenLI is a software suite that allows network operators to conduct
lawful interception of Internet traffic that is compliant with the
ETSI Lawful Intercept standards.
This package contains the provisioner component of the OpenLI
lawful intercept software. The provisioner acts as a centralised
controller for the deployed OpenLI collectors and mediators.
Intercepts are configured on the provisioner, which then pushes
the necessary intercept instructions to any registered collectors
and mediators.

%package        mediator
Summary:        Mediation daemon for an OpenLI system
Requires(pre):  shadow-utils
Requires:       rabbitmq-server

%description mediator
OpenLI is a software suite that allows network operators to conduct
lawful interception of Internet traffic that is compliant with the
ETSI Lawful Intercept standards.
This package contains the mediator component of the OpenLI
lawful intercept software. The mediator collates intercepted
(and encoded) packets from the collectors and routes the packets
to the appropriate law enforcement agency (LEA). The mediator will
maintain active TCP sessions to all known LEAs for both handover
interface 2 and 3, using keep-alives as per the ETSI standard.

%package        collector
Summary:        Collector daemon for an OpenLI system
Requires:       rabbitmq-server
Requires:       libwandder2 >= 2.0.13

%description collector
OpenLI is a software suite that allows network operators to conduct
lawful interception of Internet traffic that is compliant with the
ETSI Lawful Intercept standards.
This package contains the collector component of the OpenLI lawful
intercept software. The collector captures packets on one or more
specified network interfaces, identifies traffic that should be
intercepted (based on instructions from an OpenLI provisioner),
encodes the intercepted traffic using the format described in the
ETSI specifications, and forwards the encoded traffic to the
appropriate mediator for export to the law enforcement agency that
requested the intercept.



%prep
%setup -q -n openli-%{version}

%build
%configure --disable-static --with-man=yes --mandir=%{_mandir} --sysconfdir=/etc/
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'

%pre provisioner
getent group openli >/dev/null || groupadd -r openli
getent passwd openli >/dev/null || \
    useradd -r -g openli -d /etc/openli -s /sbin/nologin \
    -c "User for OpenLI" openli
exit 0

%post provisioner
mkdir -p /var/lib/openli

if [ $1 -eq 1 ]; then
        /bin/systemctl enable openli-provisioner.service openli-provisioner.socket >/dev/null 2>&1 || :

        # Set provisioner config examples to be 0640, so if a user copies
        # them to create their own config then they won't be readable by
        # everyone
        chmod 0640 /etc/openli/provisioner-example.yaml
        chmod 0640 /etc/openli/running-intercept-example.yaml

        # Create provisioner auth database
        s=""
        until s+=$(dd bs=24 count=1 if=/dev/urandom 2>/dev/null | LC_ALL=C tr -cd 'a-zA-Z0-9')
             ((${#s} >= 16)); do :; done
        DBPHRASE=${s:0:16}
        /usr/sbin/openli-prov-authsetup.sh ${DBPHRASE} /var/lib/openli/provauth.db
        echo ${DBPHRASE} > /etc/openli/provauthdb.phrase
        chmod 0640 /etc/openli/provauthdb.phrase
fi

if [ ! -f /etc/openli/.intercept-encrypt ]; then
        # Set up password for encrypting the intercept config file
        s=""
        until s+=$(dd bs=64 count=1 if=/dev/urandom 2>/dev/null | LC_ALL=C tr -cd 'a-zA-Z0-9')
             ((${#s} >= 32)); do :; done
        ENCPHRASE=${s:0:32}
        echo ${ENCPHRASE} > /etc/openli/.intercept-encrypt
        chmod 0640 /etc/openli/.intercept-encrypt
fi



if [ ! -f /etc/openli/.intercept-encrypt ]; then
        # Set up password for encrypting the intercept config file
        s=""
        until s+=$(dd bs=64 count=1 if=/dev/urandom 2>/dev/null | LC_ALL=C tr -cd 'a-zA-Z0-9')
             ((${#s} >= 32)); do :; done
        ENCPHRASE=${s:0:32}
        echo ${ENCPHRASE} > /etc/openli/.intercept-encrypt
        chmod 0640 /etc/openli/.intercept-encrypt
fi

if [ ! -f /etc/openli/integrity-key.pem ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out /etc/openli/integrity-key.pem
    openssl ec -in /etc/openli/integrity-key.pem -pubout -out /etc/openli/integrity-public.pem

    chmod 0600 /etc/openli/integrity-key.pem /etc/openli/integrity-public.pem
fi

chown -R openli: /etc/openli
chown -R openli: /var/lib/openli

if [ -d /var/run/openli ]; then
    chown -R openli: /var/run/openli
fi
chmod 2750 /etc/openli

%preun provisioner
if [ $1 -eq 0 ]; then
        # Disable and stop the units
        /bin/systemctl disable openli-provisioner.service openli-provisioner.socket >/dev/null 2>&1 || :
        /bin/systemctl stop openli-provisioner.service openli-provisioner.socket >/dev/null 2>&1 || :

        # Remove provisioner auth database
        rm -f /var/lib/openli/provauth.db
        rm -f /etc/openli/provauthdb.phrase
        rm -f /etc/openli/.intercept-encrypt
        rm -f /etc/openli/integrity-key.pem
        rm -f /etc/openli/integrity-public.pem
fi

%postun provisioner
if [ $1 -ge 1 ]; then
        # On upgrade, reload init system configuration if we changed unit files
        /bin/systemctl daemon-reload >/dev/null 2>&1 || :
        # On upgrade, restart the daemon
        /bin/systemctl try-restart openli-provisioner.service >/dev/null 2>&1 || :

fi

%pre mediator
getent group openli >/dev/null || groupadd -r openli
getent passwd openli >/dev/null || \
    useradd -r -g openli -d /etc/openli -s /sbin/nologin \
    -c "User for OpenLI" openli
exit 0

%post mediator
if [ $1 -eq 1 ]; then
        /bin/systemctl enable openli-mediator.service openli-mediator.socket >/dev/null 2>&1 || :
fi

chown -R openli: /etc/openli
if [ -d /var/run/openli ]; then
    chown -R openli: /var/run/openli
fi
chmod 2750 /etc/openli

if /bin/systemctl is-active --quiet "rabbitmq-server"; then
    echo ""
else
    /bin/systemctl start rabbitmq-server
fi

if rpm -q "rabbitmq-server" > /dev/null 2>&1; then
    dep_install=$(rpm -q --queryformat '%{INSTALLTIME}\n' "rabbitmq-server")
    this_install=$(rpm -q --queryformat '%{INSTALLTIME}\n' "openli-mediator")
    if [ "$dep_install" -ge "$this_install" ]; then
        # dependency was installed by our own package
        if [ ! -f /etc/rabbitmq/rabbitmq.conf ]; then
            cat > /etc/rabbitmq/rabbitmq.conf <<EOF
# Configuration auto-deployed by OpenLI to limit RMQ connections to localhost.
# Feel free to override if required.
listeners.tcp.default = 127.0.0.1:5672
loopback_users.guest = false
EOF
            chown rabbitmq:rabbitmq /etc/rabbitmq/rabbitmq.conf
        fi
    fi
fi

EXISTS=`rabbitmqctl list_vhosts | grep "^OpenLI-med$" | wc -l`
if [ "$EXISTS" -eq "0" ]; then
    rabbitmqctl add_vhost "OpenLI-med"
fi

EXISTS=`rabbitmqctl list_users | grep "^openli.nz\b" | wc -l`
if [ "$EXISTS" -eq "0" ]; then
    s=""
    until s="$s$(dd bs=24 count=1 if=/dev/urandom 2>/dev/null | LC_ALL=C tr -cd 'a-zA-Z0-9')"
        [ ${#s} -ge 16 ]; do :; done
    CRED=$(printf %.16s $s)

    rabbitmqctl add_user "openli.nz" "${CRED}"
    rabbitmqctl set_permissions -p "OpenLI-med" "openli.nz" ".*" ".*" ".*"
    echo ${CRED} > /etc/openli/rmqinternalpass
    chmod 0640 /etc/openli/rmqinternalpass
    chown openli:openli /etc/openli/rmqinternalpass
fi

/bin/systemctl restart rabbitmq-server

%preun mediator
if [ $1 -eq 0 ]; then
        # Disable and stop the units
        /bin/systemctl disable openli-mediator.service openli-mediator.socket >/dev/null 2>&1 || :
        /bin/systemctl stop openli-mediator.service openli-mediator.socket >/dev/null 2>&1 || :
fi

%postun mediator
if [ $1 -ge 1 ]; then
        # On upgrade, reload init system configuration if we changed unit files
        /bin/systemctl daemon-reload >/dev/null 2>&1 || :
        # On upgrade, restart the daemon
        /bin/systemctl try-restart openli-mediator.service >/dev/null 2>&1 || :
else
        rabbitmqctl delete_user "openli.nz"
        rabbitmqctl delete_vhost "OpenLI-med"
        rm -f /etc/openli/rmqinternalpass
fi

%post collector
if [ $1 -eq 1 ]; then
        /bin/systemctl enable openli-collector.service openli-collector.socket >/dev/null 2>&1 || :
fi

%preun collector
if [ $1 -eq 0 ]; then
        # Disable and stop the units
        /bin/systemctl disable openli-collector.service openli-collector.socket >/dev/null 2>&1 || :
        /bin/systemctl stop openli-collector.service openli-collector.socket >/dev/null 2>&1 || :
fi

%postun collector
if [ $1 -ge 1 ]; then
        # On upgrade, reload init system configuration if we changed unit files
        /bin/systemctl daemon-reload >/dev/null 2>&1 || :
        # On upgrade, restart the daemon
        /bin/systemctl try-restart openli-collector.service >/dev/null 2>&1 || :
fi

%files provisioner
%{_bindir}/openliprovisioner
%{_sbindir}/openli-prov-adduser.sh
%{_sbindir}/openli-prov-authsetup.sh
%{_unitdir}/openli-provisioner.service
%config %{_sysconfdir}/openli/rsyslog.d/10-openli-provisioner.conf
%config %{_sysconfdir}/openli/provisioner-example.yaml
%config %{_sysconfdir}/openli/running-intercept-example.yaml
%doc %{_docdir}/openli/ProvisionerDoc.md
%doc %{_docdir}/openli/TLSDoc.md

%files mediator
%{_bindir}/openlimediator
%{_unitdir}/openli-mediator.service
%config %{_sysconfdir}/openli/rsyslog.d/10-openli-mediator.conf
%config %{_sysconfdir}/openli/mediator-example.yaml
%doc %{_docdir}/openli/MediatorDoc.md

%files collector
%{_bindir}/openlicollector
%{_unitdir}/openli-collector.service
%config %{_sysconfdir}/openli/rsyslog.d/10-openli-collector.conf
%config %{_sysconfdir}/openli/collector-example.yaml
%doc %{_docdir}/openli/CollectorDoc.md


%changelog
* Thu Jan 15 2026 Shane Alcock <salcock@searchlight.nz> - 1.1.17-1
- Updated for 1.1.17 release

* Thu Dec 18 2025 Shane Alcock <salcock@searchlight.nz> - 1.1.16-1
- Updated for 1.1.16 release

* Mon Sep 29 2025 Shane Alcock <salcock@searchlight.nz> - 1.1.15-1
- Updated for 1.1.15 release

* Mon Aug 18 2025 Shane Alcock <salcock@searchlight.nz> - 1.1.14-1
- Updated for 1.1.14 release

* Thu Jun 5 2025 Shane Alcock <salcock@searchlight.nz> - 1.1.13-1
- Updated for 1.1.13 release

* Thu May 1 2025 Shane Alcock <salcock@searchlight.nz> - 1.1.12-1
- Updated for 1.1.12 release

* Wed Nov 20 2024 Shane Alcock <salcock@searchlight.nz> - 1.1.11-1
- Updated for 1.1.11 release

* Mon Nov 4 2024 Shane Alcock <salcock@searchlight.nz> - 1.1.10-1
- Updated for 1.1.10 release

* Wed Sep 18 2024 Shane Alcock <salcock@searchlight.nz> - 1.1.9-1
- Updated for 1.1.9 release

* Thu Jul 25 2024 Shane Alcock <salcock@searchlight.nz> - 1.1.8-1
- Updated for 1.1.8 release

* Tue Jul 23 2024 Shane Alcock <salcock@searchlight.nz> - 1.1.7-1
- Updated for 1.1.7 release

* Mon Jul 1 2024 Shane Alcock <salcock@searchlight.nz> - 1.1.6-1
- Updated for 1.1.6 release

* Wed May 8 2024 Shane Alcock <salcock@searchlight.nz> - 1.1.5-1
- Updated for 1.1.5 release

* Sat Jan 20 2024 Shane Alcock <salcock@searchlight.nz> - 1.1.4-1
- Updated for 1.1.4 release

* Thu Nov 9 2023 Shane Alcock <salcock@searchlight.nz> - 1.1.3-1
- Updated for 1.1.3 release

* Tue Oct 10 2023 Shane Alcock <salcock@searchlight.nz> - 1.1.2-1
- Updated for 1.1.2 release

* Mon Jul 31 2023 Shane Alcock <salcock@searchlight.nz> - 1.1.1-1
- Updated for 1.1.1 release

* Fri May 26 2023 Shane Alcock <salcock@searchlight.nz> - 1.1.0-1
- Updated for 1.1.0 release

* Wed Jun 15 2022 Shane Alcock <salcock@waikato.ac.nz> - 1.0.15-1
- Updated for 1.0.15 release

* Wed Apr 13 2022 Shane Alcock <salcock@waikato.ac.nz> - 1.0.14-1
- Updated for 1.0.14 release

* Wed Feb 9 2022 Shane Alcock <salcock@waikato.ac.nz> - 1.0.13-1
- Updated for 1.0.13 release

* Mon Nov 8 2021 Shane Alcock <salcock@waikato.ac.nz> - 1.0.12-1
- Updated for 1.0.12 release

* Mon Jul 5 2021 Shane Alcock <salcock@waikato.ac.nz> - 1.0.11-1
- Updated for 1.0.11 release

* Tue Apr 27 2021 Shane Alcock <salcock@waikato.ac.nz> - 1.0.10-1
- Updated for 1.0.10 release

* Mon Mar 22 2021 Shane Alcock <salcock@waikato.ac.nz> - 1.0.9-2
- Rebuild package to be able to use latest libtrace release

* Thu Jan 21 2021 Shane Alcock <salcock@waikato.ac.nz> - 1.0.9-1
- Updated for 1.0.9 release
- Remove dependency on rsyslog

* Wed Nov 11 2020 Shane Alcock <salcock@waikato.ac.nz> - 1.0.8-1
- Updated for 1.0.8 release

* Wed Nov 11 2020 Shane Alcock <salcock@waikato.ac.nz> - 1.0.7-2
- Fix hanging in provisioner postinst script

* Tue Nov 10 2020 Shane Alcock <salcock@waikato.ac.nz> - 1.0.7-1
- Updated for 1.0.7 release

* Wed Sep 2 2020 Shane Alcock <salcock@waikato.ac.nz> - 1.0.6-1
- Updated for 1.0.6 release

* Thu May 28 2020 Shane Alcock <salcock@waikato.ac.nz> - 1.0.5-2
- Add explicit rsyslog dependency to each component package

* Fri May 8 2020 Shane Alcock <salcock@waikato.ac.nz> - 1.0.5-1
- Updated for 1.0.5 release

* Mon Jan 13 2020 Shane Alcock <salcock@waikato.ac.nz> - 1.0.4-1
- Updated for 1.0.4 release

* Fri Aug 16 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.0.3-1
- Updated for 1.0.3 release

* Tue Jun 18 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.0.2-2
- Add openssl-devel dependency for encrypted communications

* Tue Jun 4 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.0.2-1
- First OpenLI RPM package
