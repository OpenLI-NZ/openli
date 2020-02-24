This guide aims to give you a set of steps you can follow to get DPDK
up and running on your OpenLI collector.

These steps have been written from the perspective of someone using
Debian Linux with an Intel X520 10G NIC -- you may be required to make
certain adjustments for other situations (i.e. other Linux distros
will have different package management systems).

We have also assumed that you already have certain software installed
on your system such as git and gcc. If a step fails because you are
missing a tool or library, you will need to resolve that before continuing.

IMPORTANT: These notes were written from the perspective of someone who is
building DPDK from source -- this is not necessary in many cases now, as
fairly decent packages for DPDK are now available for major Linux
distributions and the libtrace packages automatically include DPDK as a
dependency. If you want to make your life easier and just use the
packaged version of DPDK, stop reading this file and try the wiki page at
https://github.com/wanduow/openli/wiki/DPDK-and-OpenLI instead!


========================

Step 1: Make sure you have a NIC installed that is supported by DPDK.

  Hopefully one of your NICs appears on https://core.dpdk.org/supported/ as
  supported hardware.


Step 2: Install the Linux headers package for your system, if the headers
        are not already present.

  For 64 bit Debian / Ubuntu, this is done via:

     > sudo apt-get install linux-headers-amd64


Step 3: Clone the current DPDK code base.

     > git clone git://dpdk.org/dpdk-stable/
     > cd dpdk-stable


Step 4: Build the DPDK code to create a single shared library. This library
        will be installed into /usr/local/lib/.

     > sudo make install T=x86_64-native-linuxapp-gcc CONFIG_RTE_BUILD_SHARED_LIB=y EXTRA_CFLAGS="-fPIC" DESTDIR="/usr/local/"

  Note: this build may take a while...


Step 5: Set the RTE_SDK and RTE_TARGET environment variables.

     > export RTE_SDK=`pwd`
     > export RTE_TARGET=x86_64-native-linuxapp-gcc

  Note: these environment variables must be set whenever you want to interact
        with DPDK, so you may want to consider adding them to your .profile.
        In that case, replace `pwd` with the absolute path to the dpdk-stable
        directory.


Step 6: Enable huge pages memory on your host using the DPDK setup script.

     > sudo ./usertools/dpdk-setup.sh

   Choose the "Setup hugepage mappings for NUMA systems" option.

   Reserve 256 pages for each node on your system, then exit the script.


Step 7: Clone the current libtrace code base.

     > cd ../
     > git clone https://github.com/LibtraceTeam/libtrace.git
     > cd libtrace


Step 8: Configure libtrace to be built with DPDK support.

     > ./bootstrap.sh
     > ./configure --with-dpdk=yes LDFLAGS=-L/usr/local/lib CPPFLAGS=-I/usr/local/include

  The final output from the configure script should include the line:

     configure: Compiled with DPDK live capture support: Yes

Step 9: Build and install your DPDK-enabled libtrace

     > make
     > sudo make install


Step 10: If the DPDK interface is currently up and/or configured with an IP
        address, take the interface down.

  For this example, my interface name is 'dos1'.

     > sudo ip link set dos1 down


Step 11: Load the uio module.

     > sudo modprobe uio


Step 12: Use the dpdk-setup.sh script to load the igb_uio module.

     > cd ../dpdk-stable
     > sudo ./usertools/dpdk-setup.sh

   Choose "Insert IGB UIO module"


Step 13: Use the dpdk-setup.sh script to bind your DPDK interface to IGB UIO.

     > sudo ./usertools/dpdk-setup.sh  (if not still running from step 12)

   Choose "Bind Ethernet/Crypto device to IGB UIO module"

   This will display a list of network devices available for binding. Find
   the one that matches the name of the interface you wish to bind.

   For example, I want to bind 'dos1' so I find the following line under the
   "Network devices using kernel driver" heading:

       0000:42:00.1 'Ethernet 10G 2P X520 Adapter 154d' if=dos1 drv=ixgbe unused=igb_uio

   Note the "if=dos1" part of that line -- that's how I know it refers to dos1.

   The script will be waiting for you to input a PCI address. The PCI address
   is the first part of the line you just identified. In my case, the address
   I need to enter is "0000:42:00.1".

   Remember this PCI address; you'll need it later on.


Step 14: Test that libtrace can see packets on the DPDK interface.

  First, get some packets appearing on the interface. Mirroring some
  existing traffic to the DPDK interface would be a good way to do this,
  but this is left as an exercise for the reader.

  Then use the tracepktdump tool included with libtrace to print the first
  5 captured packets to standard output:

     > sudo /usr/local/bin/tracepktdump -c 5 dpdk:0000:42:00.1

  Don't forget to use your PCI address in place of 0000:42:00.1!

  Hopefully, you should see a textual description of five packets. If you
  get an error, something has failed -- hopefully the error message will give
  you an idea as to which step you missed or screwed up.


Step 15: Configure a DPDK input source in your OpenLI collector config.

  Specifically, add something like this to the "inputs:" section of the
  config file:

    inputs:
      - uri: dpdk:0000:42:00.1          # or whatever URI worked in step 14
        threads: 4

