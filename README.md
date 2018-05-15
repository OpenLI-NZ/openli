OpenLI -- open source ETSI-compliant Lawful Intercept software

Version: pre-release

---------------------------------------------------------------------------

Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
All rights reserved.

This code has been developed by the University of Waikato WAND research group. For further information please see http://www.wand.net.nz/.

---------------------------------------------------------------------------

## Dependencies

* [libtrace 4.0.0 or later](http://research.wand.net.nz/software/libtrace.php)
  (packages for Debian / Ubuntu are available
  [from WAND](http://packages.wand.net.nz) as well).

* [libwandder](https://github.com/wanduow/libwandder/tree/develop)

* libyaml -- Debian / Ubuntu users can install the libyaml-dev package.

* libosip2 -- Debian / Ubuntu users can install the libosip2-dev package.

* uthash -- Debian / Ubuntu users can install the uthash-dev package.

## Building OpenLI

To build OpenLI, just follow the series of steps given below.

1. Run the `./bootstrap.sh` script at the top level of the source tree (only
   required if you have cloned the OpenLI git repo).

2. Run the `./configure` script.

    If you wish to install OpenLI to a non-standard location (which is typically
    `/usr/local/`), append `--prefix=<location>` to the `./configure` command.

    If you have installed any of the dependencies in non-standard locations,
    you may need to also tell `./configure` where they are using the CFLAGS
    and LDFLAGS arguments. For example, if I had installed libtrace into the
    `/home/wand/` directory, I would need to add
    `CFLAGS="-I/home/wand/include" LDFLAGS="-L/home/wand/lib"` to the
    `./configure` command.

3. Run `make`.

4. To install OpenLI on your system, run `make install`. If you haven't set
   the prefix in Step 2, you'll probably need to run this command as a
   superuser (e.g. `sudo make install`).

   **This last step is optional -- the OpenLI software components should run without needing to be installed.**


## Running OpenLI

OpenLI consists of three software components: the provisioner, the collector
and the mediator. In a typical deployment, you would have **1** provisioner,
**1** mediator (although multiple mediators are supported) and **multiple**
collectors (1 per interception point in your network).

The provisioner acts as a centralised controller for the OpenLI system. All
other components report their presence to the provisioner, which then issues
intercept instructions for the components to carry out. In the case of the
collectors, these instructions will identify the interception target and
detail which mediator should receive the intercept records from that target.
For the mediator, the instructions will describe how to connect to the law
enforcement agencies and which intercepts should be forwarded to each agency.

The mediator collates the intercept records produced by the collectors and
forwards them to the appropriate agency via the handovers (HI2 and HI3, to
use ETSI terminology). The mediator also maintains the TCP sessions for the
agency handovers, including sending keep-alives when the handovers are
otherwise idle.

The collector captures the packets that are observed on one or more network
interfaces. If any of the packets is destined to or sent by an intercept
target, the collector will encode the packet using the ETSI standard and
forward the encoded packet onto a mediator as an intercept record. The
collector also maintains all of the necessary internal state to map intercept
targets (which are typically expressed as SIP URIs or ISP usernames) to their
corresponding RTP or IP sessions. A collector can capture using multiple
input sources (i.e. capture interfaces) and use multiple threads to spread
the collection workload across multiple CPU cores.

More details on how to configure and run each component can be found in the
relevant document in the `doc/` directory included with the OpenLI source.
Example configuration for each component is also included in this directory.


# Changing configuration of a running OpenLI system

If you wish to make changes to the configuration of a running instance of
OpenLI, sending a SIGHUP to any running OpenLI process will cause it to
re-read its configuration file and apply any changes that have occurred. Any
ongoing intercepts that have not been modified will continue uninterrupted.

In particular, this is the primary mechanism for adding and removing intercepts
at the moment, e.g. to add an intercept, add it to the provisioner config
file and send a SIGHUP to the OpenLI provisioner process. The provisioner
will read the new intercept details from the config and push that out to all
of the collectors and mediators that it is managing. Halting an intercept
works much the same way, except you remove the intercept from the config file
before sending SIGHUP to the provisioner.


