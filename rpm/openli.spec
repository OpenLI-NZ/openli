Name:           openli
Version:        1.0.3
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
BuildRequires: libtrace4-devel
BuildRequires: Judy-devel
BuildRequires: uthash-devel
BuildRequires: libwandder1-devel
BuildRequires: zeromq-devel
BuildRequires: gperftools-devel
BuildRequires: libosip2-devel
BuildRequires: openssl-devel
BuildRequires: json-c-devel
BuildRequires: libmicrohttpd-devel
BuildRequires: systemd

%description
Software for performing ETSI-compliant lawful intercept

%package        provisioner
Summary:        Central provisioning daemon for an OpenLI system

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

%post provisioner
if [ $1 -eq 1 ]; then
        /bin/systemctl enable openli-provisioner.service openli-provisioner.socket >/dev/null 2>&1 || :
fi

%preun provisioner
if [ $1 -eq 0 ]; then
        # Disable and stop the units
        /bin/systemctl disable openli-provisioner.service openli-provisioner.socket >/dev/null 2>&1 || :
        /bin/systemctl stop openli-provisioner.service openli-provisioner.socket >/dev/null 2>&1 || :
fi

%postun provisioner
if [ $1 -ge 1 ]; then
        # On upgrade, reload init system configuration if we changed unit files
        /bin/systemctl daemon-reload >/dev/null 2>&1 || :
        # On upgrade, restart the daemon
        /bin/systemctl try-restart openli-provisioner.service >/dev/null 2>&1 || :
fi

%post mediator
if [ $1 -eq 1 ]; then
        /bin/systemctl enable openli-mediator.service openli-mediator.socket >/dev/null 2>&1 || :
fi

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
* Fri Aug 16 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.0.3-1
- Updated for 1.0.3 release

* Tue Jun 18 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.0.2-2
- Add openssl-devel dependency for encrypted communications

* Tue Jun 4 2019 Shane Alcock <salcock@waikato.ac.nz> - 1.0.2-1
- First OpenLI RPM package
