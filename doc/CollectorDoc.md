## Hardware Recommendations for Collectors

OpenLI is designed to run on a typical Linux install on commodity server
hardware, such as a 1U Supermicro or similar. The actual hardware
requirements will depend on the amount of traffic you expect to be
intercepting, whether you expect to be doing VOIP and IP intercepts on
the same collector, and how much you are willing to trade off against
the possibility of a "worst case" intercept scenario (e.g. a user with
a 1Gb connection which they are flooding with 64 byte packets).

Please note that the OpenLI developers take no responsibility for any
interception failures due to underprovisioned collector hardware.

Having said that, here are some recommendations for a "typical"
collector where we define typical as having to conduct <= 3 concurrent
intercepts for users that are NOT saturating their 1Gbps connection
(and even if they are saturating them, they are using larger packets to do
so).
  * CPU: Intel Xeon or equivalent, at least 8 logical cores but preferably
         more cores if possible.
  * RAM: At least 16 GB -- more RAM will help with buffering if a
         connection to a mediator fails but won't improve speed.
  * NIC: A standard 4 port 1G NIC + an Intel DPDK-capable 10G NIC. The
         standard NIC will be used for management and capturing special
         traffic types (such as RADIUS, SIP and/or RTP).

         The DPDK NIC will be used for IP traffic capture and intercept.
         If the collector is handling VOIP intercepts only, you can
         probably manage without the DPDK NIC.

         See https://core.dpdk.org/supported/ for a list of DPDK-supported
         hardware.
  * Disk: Enough to fit a Linux install + some extra software components.
          If you are anticipating a spotty connection to the mediator(s),
          then extra disk space for buffering may be useful. SSDs are
          not required; a traditional spinning disk should be fine.

## Collector Configuration
Like all OpenLI components, the collector uses YAML as its configuration
file format. If you are unfamiliar with YAML, a decent crash course is
available [here](https://learnxinyminutes.com/docs/yaml/).

An example configuration file (with in-line documentation) can found in
`doc/exampleconfigs/collector-example.yaml`.

### Operator ID
This option should contain a string that uniquely identifies your network.
This is a mandatory field for ETSI compliance and will be used to set the
operatorIdentifier field in the ETSI header. The operator ID should be no
more than 16 characters in length.

### Network Element ID
This option should contain a string that uniquely identifies the location of
the collector within your network. While this is technically
an optional field for ETSI compliance, it is highly recommended that you set
this option. The provided value will be used to set the
networkElementIdentifier field in the ETSI header and should be no more than
16 characters in length.

### Interception Point ID
If you have multiple collectors at a single location, you can use the
Interception Point ID to assign an additional identifier to each exported
ETSI record so that the source collector can be distinguished by the
recipient LEAs. This field is optional and only necessary if the Operator
and Network Element IDs are not a unique identifier for this collector. The
Interception Point ID should be no more than 8 characters in length.

### Provisioner Socket
The provisioner address and port options describe how to connect to the
host that the OpenLI provisioner is running on. If the collector cannot
connect to the provisioner, it will not receive any intercept instructions
and will therefore sit idle. If the connection to the provisioner goes down
for some reason, the collector will periodically attempt to reconnect to it.

### Statistics Logging
This option can be used to configure the collector to log regular statistic
updates, which you can then inspect to gauge whether the collector is
functioning as expected (i.e., is it receiving packets on the capture
interface?). By default, the logging is disabled as it can be somewhat
verbose. The value you set for this option will determine the number of
minutes between statistic dumps from the collector -- setting this to zero
will disable the statistic logging altogether.

### Inputs
The inputs option is used to describe which interfaces should be used to
intercept traffic. Each interface should be expressed using either its
interface name (for non-DPDK capture) or its PCI device ID (for DPDK capture).

You can also configure the number of processing threads that are assigned
to intercepting the packets received on that interface. High speed interfaces
( > 1Gb ) will likely need multiple processing threads. I'd suggest 1 thread
per 2Gb of expected traffic rate on the interface. Bear in mind that the
main limiting factor for performance is actually packet rate rather than
raw throughput, i.e. intercepting 500,000 64 byte packets per second is a
much higher workload than intercepting 100,000 1500 byte packets.

### ALU Mirror Configuration
If you are using OpenLI to translate the intercept records produced by
Alcatel-Lucent devices into ETSI-compliant output, any collectors that
are expected to receive mirrored copies of the ALU intercept records need
to be able to identify which packets are encapsulated records to be
translated.

This is done by configuring the collector with a sequence of known sinks for
the ALU intercept traffic under the 'alumirrors' top-level configuration
option. Each sequence entry is defined using two parameters:
* ip -- the IP address of the sink
* port -- the port that the sink is listening on for ALU intercept records

Note that in this context, the sink refers to the destination IP address
and port of the mirrored ALU traffic.

### Configuration Syntax
All config options aside from the input configuration are standard YAML
key-value pairs, where the key is the option name and the value is your chosen
value for that option.

The basic option keys are:
* provisioneraddr   -- connect to a provisioner at this IP address
* provisionerport   -- connect to a provisioner listening on this port
* operatorid        -- set the operator ID
* networkelementid  -- set the network element ID
* interceptpointid  -- set the interception point ID
* seqtrackerthreads -- set the number of threads to use for sequence number
                       tracking (defaults to 1).
* encoderthreads    -- set the number of threads to use for encoding ETSI
                       records (defaults to 2).
* forwardingthreads -- set the number of threads to use for forwarding
                       encoded ETSI records to the mediators (defaults to 1).
* logstatfrequency  -- set the frequency (in minutes) that the collector
                       should dump detailed statistics about the collection
                       process to the logger. Defaults to 0 (no stat logging).

Inputs are specified as a YAML sequence with a key of `inputs:`. Each
sequence item represents a single traffic source to intercept traffic from
and must contain the following two key-value elements:
* uri              -- [a libtrace URI](https://github.com/LibtraceTeam/libtrace/wiki/Supported-Trace-Formats)
                      describing which interface to intercept packets on.
* threads          -- the number of processing threads to use with this input.

As described above, ALU mirrors are defined as a YAML sequence with a key
of `alumirrors:`. Each sequence item must contain the following two
key-value elements:
* ip -- the IP address of the sink
* port -- the port that the sink is listening on for ALU intercept records

Be aware that increasing the number of threads used for sequence number
tracking, encoding or forwarding can actually decrease OpenLI's performance,
especially if there are more threads active than CPU cores available on
the collector host machine. Also, OpenLI uses a number of internal threads
for message-passing and connection maintenance, which will also be
contending for CPU time. A good rule of thumb is that the total number
of input threads, sequence tracker threads, encoding threads and forwarding
threads should NOT exceed the number of CPU cores on your machine.




