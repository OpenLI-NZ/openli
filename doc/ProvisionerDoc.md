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
  activity in the SIP stream that is related to the intercept target.

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

An IP intercept must also include ONE of the following parameters, which is
used to identify the intercept target.

* User -- the username assigned to that user within your AAA system.
* ALU Shim ID -- if you are using OpenLI to convert Alcatel-Lucent intercepts
  to ETSI-compliant records, this is the value that will be in the intercept-id
  fields of the packets emitted by the mirror.

If you have using User as the target identification method, you will need to
ensure that the OpenLI collectors receive a copy of all RADIUS traffic
relating to the subscribers whose traffic will be passing that collector.
This includes both Authentication AND Accounting messages, as well both the
Requests and Responses for both message types.

If you are using the ALU Shim method, you will still need to provide a
RADIUS feed to an OpenLI collector to generate the IRI records but it
doesn't necessarily need to be the same collector instance as the one that
is receiving the ALU intercept packets.


### SIP Servers and RADIUS Servers
OpenLI uses SIP and RADIUS traffic to maintain internal state regarding which
VOIP calls and IP sessions should be intercepted, respectively. To be able
to recognise SIP and RADIUS traffic that should be used for state tracking,
the OpenLI collectors must be able to identify traffic that is either going
to or from your SIP and RADIUS servers.

SIP servers are defined using the sipservers option. Each SIP server that
you have in your network should be included as a list item within the
sipservers option. Failure to configure SIP servers will prevent OpenLI from
performing any VOIP intercepts. A SIP server is configured using two parameters:
* ip -- the IP address of the SIP server
* port -- the port that the SIP server is listening on.

RADIUS servers are defined using the radiusservers option. The configuration
works much the same as for SIP, except that most RADIUS deployments will need
TWO server entries: one for the auth service and one for the accounting service,
as these are usually listening on different ports.


### Pcap Output Mode
For situations where you need to perform an intercept but the requesting
agency is not able to accept a live ETSI stream, OpenLI has the ability to
instead write the captured CC records to a pcap trace file. To enable this
for an intercept, set the agency ID in the intercept configuration to
'pcapdisk'.

NOTE: you will also need to set the 'pcapdirectory' option in the
configuration file for your mediators.

WARNING: you should confirm with the requesting agency that a pcap file is
an acceptable format for an intercept before using pcap output mode.

### Configuration Syntax
The socket options are expressed used standard YAML key-value pairs, where the
key is the option name and the value is your chosen value for that option.

The socket option keys are:
* clientaddr            -- the address to listen on for incoming collector
                           connections
* clientport            -- the port to listen on for incoming collector
                           connections
* mediationaddr         -- the address to listen on for incoming mediator
                           connections
* mediationport         -- the port to listen on for incoming mediator
                           connections

Agencies are expressed as a YAML sequence with a key of `agencies:`. Each
sequence item represents a single agency and must contain the following
key-value elements:
* agencyid      -- the unique internal identifier for this agency
* hi2address    -- the address of the HI2 handover on the agency side
* hi2port       -- the port number for the HI2 handover on the agency side
* hi3address    -- the address of the HI3 handover on the agency side
* hi3port       -- the port number for the HI3 handover on the agency side
* keepalivefreq -- the frequency at which keep alive messages should be sent
                   to this agency by the mediators (in seconds). Defaults to
                   300. If set to zero, no keep alives are sent.
* keepalivewait -- the amount of time (in seconds) to wait for a keep alive
                   response from the agency before terminating the handover
                   connection. Defaults to 30. If set to zero, the mediator
                   will not require a response to keep alives to maintain the
                   handover connections.

VOIP and IPintercepts are also expressed as a YAML sequence, with a key of
`voipintercepts:` and `ipintercepts:` respectively. Each sequence item
represents a single intercept.

An IP intercept must contain the following key-value elements:

* liid                  -- the LIID
* authcountrycode       -- the authorisation country code
* deliverycountrycode   -- the delivery country code
* user                  -- the AAA username for the target
* alushimid             -- the intercept ID from the ALU intercept packets
                           (only for re-encoding ALU intercepts as ETSI)
* mediator              -- the ID of the mediator which will forward the
                           intercept
* agencyid              -- the internal identifier of the agency that requested
                           the intercept
* accesstype            -- the access type providied to the user, will
                           default to 'undefined' if not set.

Valid access types are:
  'dialup', 'adsl', 'vdsl', 'fiber', 'wireless', 'lan', 'satellite', 'wimax',
  'cable' and 'wireless-other'.


A VOIP intercept must contain the following key-value elements:

* liid                  -- the LIID
* authcountrycode       -- the authorisation country code
* deliverycountrycode   -- the delivery country code
* mediator              -- the ID of the mediator which will forward the
                           intercept
* agencyid              -- the internal identifier of the agency that requested
                           the intercept
* siptargets            -- a list of identities that can be used to recognise
                           SIP activity related to the target


A SIP target can be described using the following key-value elements:

* username              -- the username that is associated with the target
* realm                 -- the host or realm that the user belongs to in your
                           SIP environment; if not present, any SIP where the
                           username appears in the 'To:' URI or an
                           Authorization header will be associated with the
                           target.

### SIP Target Specifics

OpenLI currently supports three approaches for associating a SIP session
with a VOIP intercept: using the To: URI, using the Authorization header,
and using the Proxy-Authorization header. OpenLI does NOT attempt to match
SIP traffic to a target based on the contents of the From: URI -- this field
can be re-written by SIP clients as they please and therefore is not a
reliable indicator of who is attempting to create a SIP session.

The To: URI is used for matching incoming calls. As an example, the URI
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



