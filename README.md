findmacs
========

Discover MAC address for IP range using ARP

This tool will query every IP in a given range and print received MAC address to standard output. It uses ARP protocol. Devices connected to the network not using IP protocol won't get discovered.

compile
=======

    $ gcc findmacs.c -o findmacs

usage
=====

    Usage: findmacs [-apvh] [-r IP/CIDR] interface
    
      -r IP/CIDR      Scan this IP range. If not given <localIP>/24 is used
      -a              Accept ANY reply, even if it wasn't triggered by us
      -p              Print IP address being queried
      -v              Increase verbosity level
      -h              Print this help
 
