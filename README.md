findmacs
========

Discover MAC address for IP range using ARP

This tool will query every IP in a given range and print received MAC address to standard output. It uses ARP protocol. Devices connected to the network not using IP protocol won't get discovered.

Optionally you can provide a MAC address list to filter output. Filter can be set to show addresses in list or not in list.

compile
=======

This tool compiles under Linux

    $ gcc findmacs.c -o findmacs

usage
=====

    Usage: findmacs [-apvh] [-t time] [-r IP/CIDR] [-l filename [-i]] interface
    
      -r IP/CIDR      Scan this IP range. If not given <localIP>/24 is used
      -l filename     Load MAC addresses listed in <filename> and use them as allowed.
                      Only addresses found in network and not in list will be reported.
      -t time         Set wait-for-reply timeout to <time> milliseconds. Default is 950 ms
      -i              Report MAC addresses found in list (invert report)
      -a              Accept ANY reply, even if it wasn't triggered by us
      -p              Print IP address being queried
      -v              Increase verbosity level
      -h              Print this help
      -V              Print version and copyright information
 
