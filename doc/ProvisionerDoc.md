## Provisioner Configuration
Like all OpenLI components, the provisioner uses YAML as its configuration
file format. If you are unfamiliar with YAML, a decent crash course is
available [here](https://learnxinyminutes.com/docs/yaml/).

An example configuration file (with in-line documentation) can found in
`doc/exampleconfigs/provisioner-example.yaml`.

### Client Socket
The client socket is used to receive incoming connections from collectors.
The client port and address options are used to describe which TCP port and
IP address (on the provisioner host) should be listening for the collector
connections.

Make sure you configure your collectors to connect to the IP address and port
configured here.

### Mediator Socket
The mediator socket is used to receive incoming connections from mediators.
The client port and address options are used to describe which TCP port and
IP address (on the provisioner host) should be listening for the mediator
connections.

As with the client socket, your mediators will need to be configured to
connect to the IP address and port that you have configured here.

### Update Socket
The update socket is used to receive instructions to either add, modify,
delete or query intercepts within the OpenLI system. A simple HTTP server
is run on the socket and there is a RESTful API that can be used to interact
with the update socket. Full documentation of the REST API for intercept
management is available at
https://github.com/OpenLI-NZ/openli/wiki/Intercept-Configuration-REST-API

In addition to intercepts, the update socket can be used to manage the agencies
that the OpenLI system will export intercepts to, as well as the set of
known SIP and RADIUS servers on the network being monitored by OpenLI.

If the provisioner has been configured to use TLS for internal communications,
then the update socket will only accept connections over HTTPS. If you are
using `curl` as a client to push commands to the update socket and have
generated self-signed certificates for OpenLI, you will need to use the
`--cacert` option (with the self-generated CA certificate) to allow `curl`
to validate the provisioner's certificate.

The running intercept config is stored in a file on disk. You may edit this
file directly, but be warned that any changes to the file will only be
applied when the OpenLI provisioner is restarted. In addition, the file is
overwritten whenever an instruction is received over the update socket, so
your changes may be overwritten without ever being applied.

As this socket will allow people to start intercepts and specify where the
intercepted traffic should be sent, be **very** careful about which hosts
on your network can communicate with this socket.

The update socket can be disabled by configuring it to listen on port 0.
This will remove any capacity for the running intercept config to be updated
without having to manually trigger a reload of the provisioner configuration,
but users who are concerned about having an open socket that can start, stop or
modify intercepts may find this to be a preferable option.

#### Encrypting the running intercept config file
In some deployments, it may be required or preferable that the intercept
configuration is stored in an encrypted format.

To enable this capability in OpenLI, you will need to complete the following
steps:

  1. Add `encrypt-intercept-config-file: true` to the top level of your
     provisioner configuration file.
  2. Generate a random 32 character password and write it into a file on disk
     that only the user that will run your provisioner can read.
  3. Start the OpenLI provisioner with the `-K <file>` command line argument,
     where `<file>` is the path to the file containing your password from
     Step 2.

Note that if your running intercept config is unencrypted at the time when
you enable encryption, it will remain unencrypted until either the REST API is
used to modify the intercept configuration OR you manually encrypt the config
file prior to starting the provisioner.

If you have installed OpenLI from a pre-built package and are using the
systemd service files provided by those packages to run the provisioner, you
do not need to worry about Steps 2 and 3 above -- but you will still need to
do Step 1 to turn on encryption support.

To generate the random password, I recommend the following bash code:
```
s=""
until s="$s$(dd bs=64 count=1 if=/dev/urandom 2>/dev/null | LC_ALL=C tr -cd 'a-zA-Z0-9')"
    [ ${#s} -ge 32 ]; do :; done
PASSWORD=$(printf %.32s $s)
echo ${PASSWORD} > /etc/openli/enc-pass.txt
chmod 0640 /etc/openli/enc-pass.txt
```

Don't forget to use `chown` to set the ownership correctly.

To manually encrypt an unencrypted running intercept config file:
```
openssl enc -salt -aes-256-cbc -pbkdf2 -pass file:/etc/openli/enc-pass.txt
    -in <existing-config-file> -out <new-encrypted-file>
```

To manually decrypt an encrypted running intercept config file (e.g. for
debugging purposes):
```
openssl enc -d -aes-256-cbc -pbkdf2 -pass file:/etc/openli/enc-pass.txt
    -in <encrypted-file> -out <decrypted-file>

```


#### Authentication for Provisioner Updates
Optionally, you can configure the update socket to accept requests only from
authenticated users. OpenLI supports two authentication mechanisms at present:
API keys and Digest Authentication. Credentials for both methods are stored
in an encrypted SQLite3 database (and therefore require OpenLI to be built
with support for the `libsqlcipher` library) on the host that the provisioner
is running on.

Full documentation on the authentication system, how to enable it and how
to add users to it can be found at:
https://github.com/OpenLI-NZ/openli/wiki/Authenticated-REST-API

Users can authenticate by either including their API key in their HTTP
requests (using the `X-API-KEY` header) or by performing standard Digest
Authentication (as per RFC 2617) using their assigned username and password
with the realm `provisioner@openli.nz`. If you are using `curl` as a client
to communicate with the update socket, then you simply need to provide your
username and password and set the `--digest` flag and curl will handle the
rest of the authentication for you.

Scripts to create the authentication database and add users to it are
included with the OpenLI source code (in `src/provisioner/authsetup/`) and
are installed by the Debian / RPM packages (into `/usr/sbin/`). See the
aforementioned wiki page for more details on how to use these scripts.

### Agencies
In this context, an agency refers to an LEA (Law Enforcement Agency) that
can issue warrants for intercepts. The configuration for an agency is used
to describe where the resulting intercept records for that agency should be
sent.

For each agency, there are two handover interfaces. The first is HI2, which
is used for transfering IRI (Intercept-Related Information) records. The other
is HI3, which is used for transferring CC (Communication Contents) records.

Each agency should also be assigned a unique "agency ID", which is used
internally by OpenLI to assign specific intercepts to the agency that
requested them.

### VOIP Intercepts

All VOIP (or IPMM, to use ETSI terminology) intercepts are specified using the
voipintercepts option. Each intercept is expressed as an item in a list and
each intercept must be configured with the following six parameters:

* LIID -- the unique lawful intercept ID for this intercept. This will be
  assigned by the agency and should be present on the warrant for the intercept.
* Authorisation country code -- the country within which the authorisation to
  intercept was granted.
* Delivery country code -- the country where the intercept is taking place
  (probably the same as above).
* Mediator -- the ID number of the mediator which will be forwarding the
  intercept records to the requesting agency.
* Agency ID -- the agency that requested the intercept (this should match one
  of the agencies specified elsewhere in this configuration file).
* SIP targets -- a list of identities that can be used to recognise
  activity in the SIP stream that is related to the intercept target. SIP
  targets may be excluded only if the SIP/RTP traffic for this intercept is
  going to be delivered to a collector via the X2/X3 interfaces.

Some VOIP vendors have been known to generate RTP comfort noise packets that
are not considered valid by the LEA decoders. If this problem occurs on your
VOIP network, you can tell OpenLI to avoid intercepting RTP comfort noise
packets by setting the 'voip-ignorecomfort' option to 'yes' at the top level
of your configuration. Please confirm with your LEAs that this is acceptable
before doing so, of course!

### Email Intercepts
All email intercepts are specified using the emailintercepts option.
Each intercept is expressed as an item in a list and each intercept must be
configured with the following six parameters:

* LIID -- the unique lawful intercept ID for this intercept. This will be
  assigned by the agency and should be present on the warrant for the intercept.
* Authorisation country code -- the country within which the authorisation to
  intercept was granted.
* Delivery country code -- the country where the intercept is taking place
  (probably the same as above).
* Mediator -- the ID number of the mediator which will be forwarding the
  intercept records to the requesting agency.
* Agency ID -- the agency that requested the intercept (this should match one
  of the agencies specified elsewhere in this configuration file).
* Targets -- a list of email addresses that belong to the intercept target.

OpenLI supports the interception of email transported using the SMTP, POP3 and
IMAP protocols. For each protocol that you wish to perform email interception
for, you will need to tell OpenLI the IP addresses and ports that each mail
service is being served from -- this is explained in more detail later on.

### IP Data Intercepts

All IP intercepts are specified using the ipintercepts option. As with VOIP
intercepts, each individual intercept is expressed as a list item and each
intercept must be configured with the following parameters:

* LIID -- the unique lawful intercept ID for this intercept. This will be
  assigned by the agency and should be present on the warrant for the intercept.
* Authorisation country code -- the country within which the authorisation to
  intercept was granted.
* Delivery country code -- the country where the intercept is taking place
  (probably the same as above).
* Mediator -- the ID number of the mediator which will be forwarding the
  intercept records to the requesting agency.
* Agency ID -- the agency that requested the intercept (this should match one
  of the agencies specified elsewhere in this configuration file).
* Access type -- the technology used to provide the target with Internet
  access (e.g. DSL, Fiber, Wireless, etc).
* User -- the username assigned to that user within your AAA system. This is
  required, even if the target is only using static IP addresses. For mobile
  intercepts, this should be either the MSISDN, IMSI, or IMEI of the target
  device.
* Mobile Identifier -- (for mobile intercepts only) indicates whether the
  target is to be identified based on their MSISDN, IMSI, or IMEI.

An IP intercept may also include ONE of the following parameters, which is
used to identify the intercept target.

* ALU Shim ID -- if you are using OpenLI to convert Alcatel-Lucent intercepts
  to ETSI-compliant records, this is the value that will be in the intercept-id
  fields of the packets emitted by the mirror.
* JMirror ID -- if you are using Juniper Packet Mirroring to feed intercepted
  traffic into the OpenLI collector(s), any mirrored traffic with an intercept
  ID that matches this value will be treated as belonging to this OpenLI IP
  intercept.
* Cisco Mirror ID -- if you are using Cisco packet mirroring to feed
  intercepted traffic into an OpenLI collector, any mirrored traffic with
  an intercept ID that matches this value will be assumed to belong to this
  OpenLI IP intercept.
* Static IPs -- if the target has a static IP (range), you can use this
  parameter to tell OpenLI which IPs belong to the target.

If you are relying solely on the User as the target identification method, you
will need to ensure that the OpenLI collectors receive a copy of all RADIUS
traffic relating to the subscribers whose IP traffic will be passing that
collector. This includes both Authentication AND Accounting messages, as well
both the Requests and Responses for both message types.

If you are using the ALU Shim or JMirror methods, you will still need to provide
a RADIUS feed to an OpenLI collector to generate the IRI records but the
recipient collector doesn't necessarily need to be the same collector instance
as the one that is receiving the mirrored packets.

For mobile IP intercepts, there are some slight differences. The Access type
must be set to "mobile" to tell OpenLI to detect IP sessions using mobile
session management protocols (such as GTP), instead of RADIUS. The User must
also be set to either the MSISDN, IMSI, or IMEI of the device that is to be
intercepted. You must use the "Mobile Identifier" parameter to tell OpenLI
which type of identifier is described by the User field.

The vendor mirroring interception methods do not apply to mobile IP intercepts.

#### Using the RADIUS Calling Station ID to Identify IP Intercept Targets
In a conventional RADIUS deployment, the identity of the subscriber can be
found within the Username AVP field which is present in RADIUS request
packets. In that case, the value of the RADIUS Username field is what you
should use to configure an IP intercept where the subscriber is the target.

However, some deployments use an alternative approach: the subscriber CPE
is configured to send RADIUS requests with a default username and password
(where all subscribers share the same 'credentials'). Instead, individual
users are recognised using the contents of the Calling Station Id AVP,
which is unique for each subscriber.

To accommodate the latter style of deployment, IP intercepts in OpenLI can
be configured to indicate that the identity provided in the "User" field is
specifically either a RADIUS Username or a RADIUS Calling Station Id (CSID).
If not explicitly configured, OpenLI will assume attempt to match the
identity against both RADIUS AVPs.

Additionally, you may configure the provisioner with a list of "default"
usernames. Any RADIUS Username AVPs that contain a value from that list are
automatically not considered as potential targets, which may improve
collector performance in cases where there are many subscribers that are using
default RADIUS credentials. RADIUS packets with a Username matching a
configured "default" will still have their CSID AVP examined, if present,
to see if it matches the User field for a running intercept.


### SIP Servers and RADIUS Servers
OpenLI uses SIP and RADIUS traffic to maintain internal state regarding which
VOIP calls and IP sessions should be intercepted, respectively. To be able
to recognise SIP and RADIUS traffic that should be used for state tracking,
the OpenLI collectors must be able to identify traffic that is either going
to or from your SIP and RADIUS servers.

SIP servers are defined using the sipservers option. Each SIP server that
you have in your network should be included as a list item within the
'sipservers' option. Failure to configure SIP servers will prevent OpenLI from
performing any VOIP intercepts. A SIP server is configured using the
following parameters:
* ip -- the IP address of the SIP server
* port_lower -- the lowest port number that the SIP server is listening on.
* port_upper -- the highest port number that the SIP server is listening on.

RADIUS servers are defined using the 'radiusservers' option. The configuration
works much the same as for SIP, except that most RADIUS deployments will need
to ensure that their port range covers both the auth service and the accounting
service, as these are usually listening on different ports. A RADIUS server
entry is configured using the same parameters as a SIP server, i.e.:
* ip -- the IP address of the RADIUS server
* port_lower -- the lowest port number that the RADIUS server is listening on.
* port_upper -- the highest port number that the RADIUS server is listening on.

For SIP and RADIUS servers that are only listening on a single port, you may
choose to omit `port_lower` and `port_upper` and instead provide the following
parameter:
* port -- the single port that the server is listening on.


### Email Servers
To be able to intercept email sessions, the OpenLI collectors must be able to
recognise traffic that is sent to or from your email servers. There is a
separate configuration option for each email protocol (IMAP, POP3, SMTP),
named `imapservers`, `pop3servers` and `smtpservers` respectively.

Each mail server in your network should be included as a list item under the
relevant configuration option. Failure to configure email servers correctly
will prevent OpenLI from performing email intercepts properly.
A mail server is configured using two parameters:
* ip -- the IP address of the mail server
* port -- the port that the mail server is listening on

### GTP Servers
For interception of mobile phone traffic, OpenLI uses GTPv2 traffic to track
the state of mobile users' IP sessions. To be able to recognise the GTP traffic
that should be used for this purpose, the OenLI collectors must be able to
identify the traffic that is either going from or to your GTP servers.

GTP servers are defined using the gtpservers option. Each GTP server that
you have in your network should be included as a list item within the
'gtpservers' option. Failure to configure GTP servers will prevent OpenLI from
performing any IP intercepts for targets using a mobile phone. A GTP server is
configured using two parameters:
* ip -- the IP address of the SIP server
* port -- the port that the SIP server is listening on.

NOTE: remember that an IP intercept *must* be configured with an `accesstype`
of "mobile" if you want OpenLI to identify the target's IP traffic using GTP.

### ALU Lawful Intercept translation
Some Alcatel-Lucent devices have a built-in LI system which is not
ETSI-compliant. However, OpenLI is capable of taking a feed of the LI
output produced by these devices and converting them into records that follow
the ETSI standards. The first step is to configure your ALU device to
perform the desired intercept, taking note of the ALU shim ID that is
assigned to that intercept. You'll also need to take note of the IP address
and port to which the device is sending its intercepted traffic (we'll
refer to this as the intercept sink).

At this point, your ALU box should be ready to perform an intercept and
forward it to the "sink". Now, you will need to mirror the ALU-intercept
records that will be sent to the sink to an interface that an OpenLI collector
will be configured to capture packets from. The collector will translate this
duplicate stream of records into ETSI-compliant records and forward them
to the OpenLI mediator.

To configure OpenLI to recognise these mirrored packets as part of an
intercept, you'll need to do two things. First, you'll need to add the
'alumirrors' option to your collector config. More information on this
option is present in CollectorDoc.md.
Second, configure an IP intercept within the provisioner config as described
below, but make sure you include the 'vendmirrorid' parameter and that the
value of that parameter matches the ID that was assigned to the intercept
on the ALU device.

### Juniper Packet Mirroring and OpenLI
Many Juniper devices can be configured to mirror traffic for a particular
subscriber to a mediation device. This can be triggered using either the
DTCP protocol or a RADIUS COA. The mirrored traffic is wrapped in a custom
header (containing an intercept ID and session ID) and is sent to the
mediation device as a UDP packet.

OpenLI collectors are able to fill the role of mediation device for a
Juniper Packet Mirror, decapsulate the UDP and custom mirror headers and
re-encode the mirrored traffic as an ETSI-compliant record before forwarding
it on to the OpenLI mediator.

To configure OpenLI to recognise these mirrored packets as belonging to an
intercept, you'll need to do two things. First, you'll need to add the
'jmirrors' option to your collector config so that the receiving collector
knows which packets contain mirrored traffic that should be decapsulated. More
information on this option is given in CollectorDoc.md.
Second, you must configure an IP intercept within the provisioner config as
described below, but make sure to include the 'vendmirrorid' parameter and that
the value of that parameter matches the Intercept ID that is going to be
assigned to the mirrored traffic when you trigger the mirror on your Juniper
device.



### Pcap Output Mode
For situations where you need to perform an intercept but the requesting
agency is not able to accept a live ETSI stream, OpenLI has the ability to
instead write the captured CC records to a pcap trace file. To enable this
for an intercept, set the agency ID in the intercept configuration to
'pcapdisk'.

For mobile IP intercepts, the GTPv2 traffic for the target's session will
also be included in the pcap trace file.

NOTE: you will also need to set the 'pcapdirectory' and 'pcaprotatefreq'
options in the configuration file for your mediators.

WARNING: you should confirm with the requesting agency that a pcap file is
an acceptable format for an intercept before using pcap output mode.

### Configuration Syntax
The socket options are expressed used standard YAML key-value pairs, where the
key is the option name and the value is your chosen value for that option.

The socket option keys are:
* `clientaddr`            -- the address to listen on for incoming collector
                             connections
* `clientport`            -- the port to listen on for incoming collector
                             connections
* `mediationaddr`         -- the address to listen on for incoming mediator
                             connections
* `mediationport`         -- the port to listen on for incoming mediator
                             connections
* `updateaddr`            -- the address that the update service should listen
                             on
* `updateport`            -- the port that the update service should listen on.
                             Set to 0 to disable the update service.

If you need to disable interception of RTP comfort noise packets (because
they are considered invalid by the agency decoders), you can do so using
the following option key:

* `voip-ignorecomfort`    -- if set to 'yes', RTP comfort noise packets are
                             ignored by OpenLI.

* `intercept-config-file` -- the location of the file which will be used to
                             store the running intercept config. If this file
                             is not empty, then the configuration in this file
                             will be immediately pushed out to the collectors
                             and mediators on start-up. Any changes to the
                             intercept configuration via the update socket will
                             be immediately written out to this file.

If you wish to use TLS to encrypt the messages sent by the provisioner to
the other OpenLI components, you will also need to provide the following
options:

* `tlscert`     --  the location of the component's certificate file
* `tlskey`      --  the location of the component's key file
* `tlsca`       --  the location of the certificate file for the CA that signed
                    the certificates (i.e. openli-ca-crt.pem).


To allow only authenticated users to modify the running intercept config
using the REST API (update service), then you will need to provide the
following options:

* `restauthdb`  -- the SQLite3 database file where the authentication
                   credentials are located
* `restauthkey` -- the passphrase needed to decrypt the SQLite3 database


### Intercept Configuration Syntax
Intercept configuration, i.e. current intercepts, recipient agencies and
special servers, is stored in a separate YAML file. Ideally, a user would
not need to interact with this file at all -- changes would be made via
the update socket and existing configuration can also be queries through
the update socket.

However, for the sake of completeness and to potentially help with
troubleshooting, the format and structure of the intercept configuration
file is provided here. Please note that, due to limitations in the library
that is used to emit the intercept config, the layout of the YAML in this
file is minimalist and not pleasant to read.

Default RADIUS usernames are expressed as a YAML sequence with a key of
`defaultradiususers:`. Each sequence item is a RADIUS Username that you
want OpenLI to ignore when tracking potentially interceptable sessions
from captured RADIUS traffic (because the username is a default that has been
pre-configured on CPEs, and therefore does not correspond to an individual
user).

Agencies are expressed as a YAML sequence with a key of `agencies:`. Each
sequence item represents a single agency and must contain the following
key-value elements:
* `agencyid`      -- the unique internal identifier for this agency
* `agencycountrycode`  -- the 2-letter ISO 3166 country code for the country
                          where the agency is located.
* `hi2address`    -- the address of the HI2 handover on the agency side
* `hi2port`       -- the port number for the HI2 handover on the agency side
* `hi3address`    -- the address of the HI3 handover on the agency side
* `hi3port`       -- the port number for the HI3 handover on the agency side
* `keepalivefreq` -- the frequency at which keep alive messages should be sent
                   to this agency by the mediators (in seconds). Defaults to
                   300. If set to zero, no keep alives are sent.
* `keepalivewait` -- the amount of time (in seconds) to wait for a keep alive
                   response from the agency before terminating the handover
                   connection. Defaults to 30. If set to zero, the mediator
                   will not require a response to keep alives to maintain the
                   handover connections.

VOIP, Email and IPintercepts are also expressed as a YAML sequence, with a key
of `voipintercepts:`, `emailintercepts:`, and `ipintercepts:` respectively.
Each sequence item represents a single intercept.

An IP intercept must contain the following key-value elements:

* `liid`                  -- the LIID
* `authcountrycode`       -- the authorisation country code
* `deliverycountrycode`   -- the delivery country code
* `user`                  -- the AAA username for the target, or the target
                             identifier for mobile intercepts
* `mediator`              -- the ID of the mediator which will forward the
                             intercept
* `agencyid`              -- the internal identifier of the agency that
                             requested the intercept
* `accesstype`            -- the access type provided to the user, will
                             default to 'undefined' if not set
* `mobileident`           -- (required for mobile intercepts only) the type
                             of identifier specified in the `user` element
* `xids`                  -- (required for interception over X2/X3) the XIDs
                             that have been defined for this intercept when
                             the X1 interface was used to configure it on your
                             network, expressed as a YAML sequence

Valid access types are:
  'dialup', 'adsl', 'vdsl', 'fiber', 'wireless', 'lan', 'satellite', 'wimax',
  'cable', 'mobile' and 'wireless-other'.

Valid mobileident values are:
  'imsi', 'msisdn', and 'imei'. If not specified, the default is `msisdn`.

Note that setting the access type to 'mobile' will cause OpenLI to try to use
GTP traffic to identify the target's IP sessions, and the resulting ETSI records
will conform to either the UMTS or EPS format (as opposed to the standard IP
format defined in ETSI TS 102 232-3).

Optional key-value elements for an IP intercept are:

* `radiusident`           -- if set to 'csid', RADIUS packets will only be
                           recognised as belonging to the intercept target
                           if the RADIUS Calling Station ID AVP matches the
                           `user` field defined for this intercept. If set
                           to 'user', RADIUS packets will only be recognised
                           as belonging to the intercept target if the RADIUS
                           Username AVP matches the `user` field defined for
                           this intercept. If not set, then RADIUS packets
                           will be recognised as belonging to the intercept
                           target if the value of either one of those AVPs
                           matches the `user` field.
* `vendmirrorid`          -- if using a vendor mirroring platform to stream
                           packets to the collector, this is the intercept ID
                           that you have assigned to the packets on the
                           mirroring platform for the target user.
                           (only for re-encoding ALU or JMirror intercepts as
                           ETSI)
* `staticips`             -- a list of IP ranges that are known to have been
                           assigned to the target.

`staticips:` are expressed as a YAML list: one list item per IP range that
is associated with the target. Each list item is a YAML map containing the
following key-value elements:

* `iprange`               -- the IP range, expressed in CIDR notation. If a
                             single address (i.e. no subnet) is given, a /32
                             or /128 mask will be added automatically.
* `sessionid`             -- the session ID (also known as CIN) to associate
                             with intercepts for this address range. See
                             example config for more information about the
                             meaning of this field.

---
A VOIP intercept must contain the following key-value elements:

* `liid`                  -- the LIID
* `authcountrycode`       -- the authorisation country code
* `deliverycountrycode`   -- the delivery country code
* `mediator`              -- the ID of the mediator which will forward the
                             intercept
* `agencyid`              -- the internal identifier of the agency that
                             requested the intercept
* `xids`                  -- (required for interception over X2/X3) the XIDs
                             that have been defined for this intercept when
                             the X1 interface was used to configure it on your
                             network, expressed as a YAML sequence
* `siptargets`            -- (not required if interception is over X2/X3)
                             a list of identities that can be used to recognise
                             SIP activity related to the target


A SIP target can be described using the following key-value elements:

* `username`              -- the username that is associated with the target
* `realm`                 -- the host or realm that the user belongs to in your
                           SIP environment; if not present, any SIP where the
                           username appears in the 'To:' URI or an
                           Authorization header will be associated with the
                           target.

---

An email intercept must contain the following key-value elements:

* `liid`                  -- the LIID
* `authcountrycode`       -- the authorisation country code
* `deliverycountrycode`   -- the delivery country code
* `mediator`              -- the ID of the mediator which will forward the
                             intercept
* `agencyid`              -- the internal identifier of the agency that
                             requested the intercept
* `targets`               -- a list of email identities that are being used by
                             the target. You may specify multiple identities
                             for a target (e.g. if they have multiple mailboxes
                             that you need to monitor).

An email target is a JSON object that contains just a single field:

* `address`               -- the email address of the target

Optional key-value elements for an email intercept are:

* `delivercompressed`     -- if email content is compressed (e.g. via the
                             IMAP COMPRESS extension), should OpenLI create
                             CC records using the compressed or decompressed
                             version of the content? Set to `as-is` to emit
                             CC records with compressed content, or
                             `decompressed` to emit CC records using
                             decompressed content. If not set, the approach
                             described by the `email-defaultdelivercompressed`
                             option will be used.


---

All intercept types also support the following optional key-value elements:

* `starttime`             -- do not intercept any traffic observed before this
                             unix timestamp. Default is 0, which will
                             intercept all traffic from the moment the
                             intercept is provisioned.
* `endtime`               -- do not intercept any traffic observed after this
                             unix timestamp. Default is 0, which will
                             continue to intercept traffic until the intercept
                             is explicitly halted.
* `outputhandovers`       -- If set to "all", then both IRI and CCs will be
                             produced by OpenLI for this intercept.
                             If set to "irionly", then only IRIs will be
                             produced by OpenLI for this intercept.
                             If set to "cconly", then only CCs will be produced
                             by OpenLI for this intercept.
                             The default setting is "all".
* `payloadencryption`     -- Specifies if the CC and IRI contents should be
                             encrypted and, if so, which encryption method to
                             use. If set to "none", no encryption is performed.
                             The encryption method supported right now is
                             "aes-192-cbc".
                             The default setting is "none".
* `encryptionkey`         -- The encryption key to use when encrypting CC and
                             IRI contents. This option is mandatory if
                             `payloadencryption` is NOT set to "none". The
                             ideal key length is 24 characters. Shorter keys
                             will be padded with null bytes, longer keys will be
                             truncated to 24 characters.
---

The default approach for delivering compressed email content to the agencies
can be set by adding a key-value pair to the top level of the intercept
configuration. The key should be `email-defaultdelivercompressed` and the value
should be either `as-is` (to deliver compressed content in its original
compressed form) or `decompressed` (to deliver the decompressed version of the
content instead).

The approach described in the `email-defaultdelivercompressed` option will be
applied to all email intercepts, but can be overridden for specific
email intercepts by including the `delivercompressed` config option in the
individual intercept configuration.

If `email-defaultdelivercompressed` is not set, `as-is` will be used as the
default approach for handling compressed email content.


### SIP Target Specifics

OpenLI currently supports five approaches for associating a SIP session
with a VOIP intercept:
  * using the P-Asserted-Identity header;
  * using the Remote-Party-Id header;
  * using the To: URI;
  * using the Authorization header;
  * using the Proxy-Authorization header.

OpenLI does NOT attempt to match SIP traffic to a target based on the contents
of the From: URI by default -- this field can be re-written by SIP clients as
they please and therefore is not a reliable indicator of who is attempting to
create a SIP session. This behaviour may be overridden (and therefore
the From: URI will be treated as valid identifier) by setting the
`sipallowfromident` configuration option to true in the collector
configuration file.

The To: URI can be used for matching incoming calls. As an example, the URI
typically takes the form "sip:roger@sip.example.net". If our goal is to
intercept any incoming calls to that SIP address, we could add the following
SIP target to our VOIP intercept config:

    voipintercepts:
      - liid: RogerIntercept
        authcountrycode: NZ
        deliverycountrycode: NZ
        mediatorid: 1001
        agencyid: "ExampleLEA"
        siptargets:
          - username: roger
            realm: sip.example.net

In situations where the hostname is dynamic, e.g. you use the user's dynamic
IP address as your hostname, then excluding the "realm:" line will result in
OpenLI intercepting all incoming calls for 'roger' regardless of what appears
after the '@' symbol in the To: URI.

For outgoing calls, OpenLI will examine any Authorization and
Proxy-Authorization headers that are present in your SIP INVITE and attempt
to match the user details within against the SIP targets specified in your
configuration file. In an ideal world, the Auth username and realm will match
the user and host that would appear in the To: URI for any incoming calls. In
that case, you'll only need the one SIP target to match both incoming and
outgoing calls.

If the Authorization details for the user are different to what would appear
in the To: URI, then simply add another SIP target to cover the identity
that will appear in the Authorization header. For instance, if our example
user from earlier was to authorize using the username "6478384466" (i.e.
their phone number) against the realm "sippysoft.com", we can update our
config as follows:

    voipintercepts:
      - liid: RogerIntercept
        authcountrycode: NZ
        deliverycountrycode: NZ
        mediatorid: 1001
        agencyid: "ExampleLEA"
        siptargets:
          - username: roger
            realm: sip.example.net
          - username: 6478384466
            realm: sippysoft.com

Now OpenLI should be able to pick up both incoming and outgoing calls for
this user, despite the discrepancies between outgoing Auth and the address
used for routing incoming calls. Once again, "realm:" may be left unspecified,
provided the "username:" is unique within your SIP deployment.

Usernames may be preceded by a `*` character that will act as a wildcard
when comparing the specified target username against the username found
inside the SIP invitations. This can be useful if, for example, your usernames
are phone numbers and may appear in invitations in a variety of different
permutations based on which dialing codes are prepended to the number by
the software that has formed the invite. For instance, a username of
`*3257781` will match any of the following SIP identities: `3257781`,
`643257781`, `+643257781`, or `00643257781`.

