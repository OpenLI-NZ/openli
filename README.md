OpenLI -- open source ETSI-compliant Lawful Intercept software

Version: pre-release

---------------------------------------------------------------------------

Copyright (c) 2018 The University of Waikato, Hamilton, New Zealand.
All rights reserved.

This code has been developed by the University of Waikato WAND research group.
For further information please see http://www.wand.net.nz/.

---------------------------------------------------------------------------

## IMPORTANT
This software is currently in a pre-release state and should not be relied
upon to satisfy your lawful intercept requirements. We still have more testing
and refinement to complete before a formal release will occur, but we have
made the code available now to allow people to experiment with OpenLI
and figure out how to integrate it properly into their production network
once the software is complete.

## Dependencies

* [libtrace 4.0.4 or later](http://research.wand.net.nz/software/libtrace.php)
  (packages for Debian / Ubuntu are available
  [from WAND](http://packages.wand.net.nz) as well).

* [libwandder 1.0.1 or later](https://github.com/wanduow/libwandder/)
  (packages for Debian / Ubuntu are available
  [from WAND](http://packages.wand.net.nz) as well).

* libyaml -- Debian / Ubuntu users can install the libyaml-dev package.
  Required for all components.

* libosip2 -- Debian / Ubuntu users can install the libosip2-dev package.
  Only required for the collector.

* uthash -- Debian / Ubuntu users can install the uthash-dev package.
  Required for all components.

* libzmq -- Debian / Ubuntu users can install the libzmq3-dev package.
  Required for all components.

* libJudy -- Debian / Ubuntu users can install the libjudy-dev package.
  Required for the collector and the mediator.

* libtcmalloc -- Debian / Ubuntu users can install the libgoogle-perftools-dev
  package. Optional, but highly recommended for performance reasons.

## Building OpenLI

To build OpenLI, just follow the series of steps given below.

1. Run the `./bootstrap.sh` script at the top level of the source tree (only
   required if you have cloned the OpenLI git repo).

2. Run the `./configure` script.

    If you wish to install OpenLI to a non-standard location (which is typically
    `/usr/local/`), append `--prefix=<location>` to the `./configure` command.

    `./configure` will fail if any of the required dependencies are missing.
    If you have installed any of the dependencies in non-standard locations,
    you may need to also tell `./configure` where they are using the CFLAGS
    and LDFLAGS arguments. For example, if I had installed libtrace into the
    `/home/wand/` directory, I would need to add
    `CFLAGS="-I/home/wand/include" LDFLAGS="-L/home/wand/lib"` to the
    `./configure` command.

    To disable the building of any of the three core OpenLI components, you
    can add any of the following to your './configure' command.

      --disable-provisioner
      --disable-mediator
      --disable-collector


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


## Changing configuration of a running OpenLI system

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


## Common problems with OpenLI

Q. OpenLI doesn't build or complains about unresolved symbols when I try to
   start one of the tools!

A. Unfortunately there are plenty of reasons why this might happen. Here are
   a few things you can try that might resolve your issue:

* If you've installed any dependencies from source, then it may be that
  your system is having trouble finding them. Try running
  `sudo ldconfig` then try again.

* Try installing the latest 'develop' branch of libtrace from
  https://github.com/LibtraceTeam/libtrace

* Try installing the latest 'develop' branch of libwandder from
  https://github.com/wanduow/libwandder

* Try installing the latest 'develop' branch of openli itself from
  https://git.cms.waikato.ac.nz/WAND/OpenLI

  If all else fails, send us an email at contact@wand.net.nz and someone
  will try to help you.


Q. My collector keeps logging messages "dropped X packets in last second".

A. This means that your collector is not keeping up with the number of
   packets that it is trying to intercept. This can be a tricky problem
   to solve.

   If you have unused CPU cores, try increasing the number of threads
   used by the collector input that is handling your IP traffic. You can
   also try increasing the number of encoding threads used by the collector.

   If the input source for your IP traffic is a standard network interface,
   you may want to consider using an Intel DPDK capable interface instead.
   This may require you to install a DPDK-supported NIC on your collector.
   See DPDKNotes.md in the doc/ directory for more information on how to
   configure a DPDK interface for use with OpenLI.

   Otherwise, your options are:
* use more powerful hardware for your collector (more CPU cores
  generally helps most).

* find a way to split the interception workload across multiple
  collectors (only if the workload is coming from multiple intercepts).

* accept that your LI needs are too large to be handled by a simple
  open-source project and ask your vendors if they can supply you with
  a better solution.


