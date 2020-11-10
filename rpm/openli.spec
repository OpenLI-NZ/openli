Name:           openli
Version:        1.0.7
Release:        1%{?dist}
Summary:        Software for performing ETSI-compliant lawful intercept

License:        GPLv3
URL:            https://github.com/wanduow/OpenLI
Source0:        https://github.com/wanduow/OpenLI/archive/%{version}.tar.gz

BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: make
BuildRequires: bison
BuildRequires: doxygen
BuildRequires: flex
BuildRequires: libyaml-devel
BuildRequires: libtrace4-devel >= 4.0.14
BuildRequires: Judy-devel
BuildRequires: uthash-devel
BuildRequires: libwandder2-devel
BuildRequires: zeromq-devel
BuildRequires: gperftools-devel
BuildRequires: libosip2-devel
BuildRequires: openssl-devel
BuildRequires: json-c-devel
BuildRequires: libmicrohttpd-devel
BuildRequires: systemd
BuildRequires: sqlcipher-devel
BuildRequires: librabbitmq-devel

%description
Software for performing ETSI-compliant lawful intercept

%package        provisioner
Summary:        Central provisioning daemon for an OpenLI system
Requires:       rsyslog
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
Requires:       rsyslog
Requires(pre):  shadow-utils

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
Requires:       rsyslog
Requires:       rabbitmq-server

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
        until s+=$(dd bs=24 count=1 if=/dev/urandom | LC_ALL=C tr -cd 'a-zA-Z0-9')
             ((${#s} >= 16)); do :; done
        DBPHRASE=${s:0:16}
        /usr/sbin/openli-prov-authsetup.sh ${DBPHRASE} /var/lib/openli/provauth.db
        echo ${DBPHRASE} > /etc/openli/provauthdb.phrase
        chmod 0640 /etc/openli/provauthdb.phrase
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
%config %{_sysconfdir}/rsyslog.d/10-openli-provisioner.conf
%config %{_sysconfdir}/openli/provisioner-example.yaml
%config %{_sysconfdir}/openli/running-intercept-example.yaml
%doc %{_docdir}/openli/ProvisionerDoc.md
%doc %{_docdir}/openli/TLSDoc.md

%files mediator
%{_bindir}/openlimediator
%{_unitdir}/openli-mediator.service
%config %{_sysconfdir}/rsyslog.d/10-openli-mediator.conf
%config %{_sysconfdir}/openli/mediator-example.yaml
%doc %{_docdir}/openli/MediatorDoc.md

%files collector
%{_bindir}/openlicollector
%{_unitdir}/openli-collector.service
%config %{_sysconfdir}/rsyslog.d/10-openli-collector.conf
%config %{_sysconfdir}/openli/collector-example.yaml
%doc %{_docdir}/openli/CollectorDoc.md


%changelog
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
