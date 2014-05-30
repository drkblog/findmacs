findmacs
========

Discover MAC address for IP range using ARP

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
 
