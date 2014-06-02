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

    Usage: findmacs [-apvhV] [-t time] [-r IP/CIDR] [-l filename [-i]] interface
    
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
 
Return value
============

The script returns 1 if there was at least one MAC address printed in standard output. If not, it returns 0. Any other returned value means that there was an error during execution.

Sample output
=============

    $ sudo ./findmacs -vr 192.168.0.1/28 eth0
    Interface eth0
    Local IP 192.168.0.49
    Local MAC 94:de:80:b8:f5:45
    Scan range 192.168.0.1/28
    
    00:22:54:e3:c9:91       192.168.0.1     ->      94:de:86:a8:f5:45       192.168.0.19
    00:19:93:88:5b:54       192.168.0.4     ->      94:de:86:a8:f5:45       192.168.0.19
    00:22:15:4b:b7:88       192.168.0.6     ->      94:de:86:a8:f5:45       192.168.0.19
    00:22:4d:38:04:05       192.168.0.7     ->      94:de:86:a8:f5:45       192.168.0.19
    00:22:13:28:2c:2d       192.168.0.10    ->      94:de:86:a8:f5:45       192.168.0.19
    00:19:99:33:53:1b       192.168.0.12    ->      94:de:86:a8:f5:45       192.168.0.19
    00:19:99:83:21:7e       192.168.0.15    ->      94:de:86:a8:f5:45       192.168.0.19


