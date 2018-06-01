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
* SIP URI -- a SIP URI that identifies the target of the intercept. All SIP and
  RTP traffic for that SIP user will be intercepted.
* Mediator -- the ID number of the mediator which will be forwarding the
  intercept records to the requesting agency.
* Agency ID -- the agency that requested the intercept (this should match one
  of the agencies specified elsewhere in this configuration file).


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
* requirekaresponse -- if set to 'no', OpenLI will NOT disconnect the handovers
                       if they fail to respond to a Keep-Alive message.

VOIP and IPintercepts are also expressed as a YAML sequence, with a key of
`voipintercepts:` and `ipintercepts:` respectively. Each sequence item
represents a single intercept and must contain the following key-value
elements:

* liid                  -- the LIID
* authcountrycode       -- the authorisation country code
* deliverycountrycode   -- the delivery country code
* sipuri                -- the SIP URI for the target  (VOIP only)
* user                  -- the AAA username for the target  (IP only)
* alushimid             -- the intercept ID from the ALU intercept packets
                           (IP only + only for re-encoding ALU intercepts as
                            ETSI)
* mediator              -- the ID of the mediator which will forward the
                           intercept
* agencyid              -- the internal identifier of the agency that requested
                           the intercept


