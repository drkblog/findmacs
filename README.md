findmacs
========

Discover MAC address for IP range using ARP

This tool will query every IP in a given range and print received MAC address to standard output. It uses ARP protocol. Devices connected to the network not using IP protocol won't get discovered.

compile
=======

This tool compiles under Linux

    $ gcc findmacs.c -o findmacs

usage
=====

    Usage: findmacs [-apvh] [-r IP/CIDR] interface
    
      -r IP/CIDR      Scan this IP range. If not given <localIP>/24 is used
      -a              Accept ANY reply, even if it wasn't triggered by us
      -p              Print IP address being queried
      -v              Increase verbosity level
      -h              Print this help
 
Sample output
=============

    $ sudo ./findmacs -vr 192.168.0.1/28 eth0
    Interface eth0
    Local IP 192.168.0.14
    Local MAC 94:de:81:a8:f4:15
    Scan range 192.168.0.1/28
    
    192.168.0.1     00:23:54:e0:c9:91 in reply to 192.168.0.14     94:de:81:a8:f4:15
    192.168.0.4     00:19:99:87:5b:54 in reply to 192.168.0.14     94:de:81:a8:f4:15
    192.168.0.6     00:22:15:db:ba:18 in reply to 192.168.0.14     94:de:81:a8:f4:15
    192.168.0.7     00:22:4d:39:84:05 in reply to 192.168.0.14     94:de:81:a8:f4:15
    192.168.0.10    00:22:15:a9:7c:2d in reply to 192.168.0.14     94:de:81:a8:f4:15
    192.168.0.12    00:19:99:88:5e:1b in reply to 192.168.0.14     94:de:81:a8:f4:15
    192.168.0.15    00:19:92:81:71:2e in reply to 192.168.0.14     94:de:81:a8:f4:15
