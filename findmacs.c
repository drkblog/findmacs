/**
*  findMACs -- Discover MAC addresses for IP range using ARP
*  Copyright (C) 2014 Leandro Fernández
*  http://www.drk.com.ar/findmacs
*
*  This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

// String length for IP and IP/CIDR
#define IPSTR_ADDR_LEN 16
#define IPCIDRSTR_ADDR_LEN 20

// Configuration flags
#define ACCEPT_ANY 0x01
#define PRINT_REQ  0x02
#define VERBOSE    0x04

// Print usage information
void usage();
// Incremente a 32 bit integer in network byte order
uint32_t inc_netorder(uint32_t value);
// Split a string IP/CIDR into network address and IP count
int split_cidr_range(const char * target, struct in_addr * ip_range, uint32_t * ip_count);
// Find MAC addresses for <target> range using <interface_index>, <mac>, and <ip>
int getMACs(int fd, int interface_index, char mac[ETHER_ADDR_LEN], char * ip, char * target, int flags);

int main(int argc, char ** argv)
{
  int fd, c, flags = 0;
  char target[IPCIDRSTR_ADDR_LEN] = "";
  char interface_name[IFNAMSIZ] = "";
  int interface_index;
  unsigned char interface_mac[ETHER_ADDR_LEN];
  char interface_ip[IPSTR_ADDR_LEN];
  struct ifreq ifr;

  // Read arguments
  opterr = 0;

  while ((c = getopt (argc, argv, "hr:")) != -1)
    switch (c)
    {
      case 'h':
        usage();
        abort();
        break;
      case 'a':
        flags |= ACCEPT_ANY;
        break;
      case 'p':
        flags |= PRINT_REQ;
        break;
      case 'v':
        flags |= VERBOSE;
        break;
      case 'r':
        strncpy(target, optarg, IPCIDRSTR_ADDR_LEN);
        break;
      case '?':
        if (optopt == 'r')
          fprintf (stderr, "Option -r requires an IP range IP/CIDR.\n", optopt);
        else if (isprint(optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
        return 1;
      default:
        abort ();
    }

  // Check it's root
  if (getuid() != 0)
  {
    fprintf(stderr, "You have to be root!\n");
    exit(-1);
  }

  // Check range
  if (strlen(target) && split_cidr_range(target, NULL, NULL))
  {
    fprintf(stderr, "You must enter IP/CIDR range. For example: 10.0.0.1/24\n");
    exit(-1);
  }

  /// START ///
  if (optind < argc) {
    strncpy(interface_name, argv[optind], IFNAMSIZ-1);
    interface_name[IFNAMSIZ]=0; // We don't want a buffer overrun here
  }

  if (interface_name[0] == 0)
  {
    fprintf(stderr, "You must specify an interface\n");
    exit(-1);
  }

  fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
  if (fd < 0) {
    perror("creting socket");
    exit(-1);
  }
  memcpy(ifr.ifr_name, interface_name, strlen(interface_name));
  ifr.ifr_name[strlen(interface_name)]=0;

  if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
  {
    perror("getting interface index");
    exit(-1);
  }
  interface_index = ifr.ifr_ifindex;

  if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1)
  {
    perror("getting interface MAC address");
    exit(-1);
  }
  memcpy(interface_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

  if (ioctl(fd, SIOCGIFADDR, &ifr)==-1)
  {
    perror("getting interface IP address");
    exit(-1);
  }
  struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
  memcpy(interface_ip, inet_ntoa(ipaddr->sin_addr), IPSTR_ADDR_LEN);

  if (!strlen(target))
  {
    // User didn't give a target range. User our IP/24
    sprintf(target, "%s/24", interface_ip);
  }

  printf("IP %s\n", interface_ip);
  printf("MAC %02x:%02x:%02x:%02x:%02x:%02x\n", interface_mac[0], interface_mac[1], interface_mac[2], interface_mac[3], interface_mac[4], interface_mac[5]);
  printf("RANGE %s\n\n", target);

  getMACs(fd, interface_index, interface_mac, interface_ip, target, flags);

  close(fd);

  return 0;
}

int getMACs(int fd, int interface_index, char mac[ETHER_ADDR_LEN], char * ip, char * target, int flags)
{
  const unsigned char ether_broadcast_addr[] = {0xff,0xff,0xff,0xff,0xff,0xff};
  struct sockaddr_ll addr = {0}, r_addr = {0};
  struct ether_arp req, *rep;
  struct in_addr source_ip_addr = {0};
  struct in_addr target_ip_addr = {0};
  struct in_addr ip_range = {0};
  struct iovec iov[1];
  struct msghdr message;
  struct msghdr reply;
  ssize_t reply_len;
  char buffer[512];
  struct iovec r_iov[1];
  int p;
  uint32_t ip_count, i;

  // Prepare range
  split_cidr_range(target, &ip_range, &ip_count);
  

  // Construct target address
  addr.sll_family   = AF_PACKET;
  addr.sll_ifindex  = interface_index;
  addr.sll_halen    = ETHER_ADDR_LEN;
  addr.sll_protocol = htons(ETH_P_ARP);
  memcpy(addr.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);

  // Construct ARP request
  req.arp_hrd = htons(ARPHRD_ETHER);
  req.arp_pro = htons(ETH_P_IP);
  req.arp_hln = ETHER_ADDR_LEN;
  req.arp_pln = sizeof(in_addr_t);
  req.arp_op  = htons(ARPOP_REQUEST);
  memset(&req.arp_tha, 0, sizeof(req.arp_tha));

  if (!inet_aton(ip, &source_ip_addr)) {
    fprintf(stderr, "%s is not a valid IP address", ip);
    return 2;
  }
  memcpy(&req.arp_spa, &source_ip_addr.s_addr, sizeof(req.arp_spa));
  memcpy(req.arp_sha, mac, ETHER_ADDR_LEN);

  for(i=0; i<ip_count; ++i) {

    ip_range.s_addr = inc_netorder(ip_range.s_addr); // Skip the first one (network address)
    memcpy(&req.arp_tpa, &ip_range.s_addr, sizeof(req.arp_tpa));
    if (flags & PRINT_REQ)
      printf("Sending ARP request for %s\n", inet_ntoa(ip_range));
  
    // Send the packet
    iov[0].iov_base=&req;
    iov[0].iov_len=sizeof(req);
    
    message.msg_name=&addr;
    message.msg_namelen=sizeof(addr);
    message.msg_iov=iov;
    message.msg_iovlen=1;
    message.msg_control=0;
    message.msg_controllen=0;
    
    if (sendmsg(fd, &message, 0) == -1) {
      perror("sending ARP request");
      exit(-1);
    }
  
  
    r_iov[0].iov_base = buffer;
    r_iov[0].iov_len  = sizeof(req);
    reply.msg_name    = &r_addr;
    reply.msg_namelen = sizeof(r_addr);
    reply.msg_iov     = r_iov;
    reply.msg_iovlen  = 1;
    reply.msg_control = 0;
    reply.msg_controllen = 0;
  
    // Wait for reply
    if ((reply_len = recvmsg(fd, &reply, 0)) < 0) {
      perror("receiving ARP request");
      exit(-1);
    }
  
    // Check it's an ARP reply and it's for us (unless ACCEPT_ANY was given)
    rep = (struct ether_arp*)buffer;
    if (ntohs(rep->arp_op) == ARPOP_REPLY 
        && (*(uint32_t*)rep->arp_spa == *(uint32_t*)req.arp_tpa) || (flags & ACCEPT_ANY)) {
      for(p=0; p < sizeof(in_addr_t); ++p) {
        printf("%d%c", rep->arp_spa[p], (p+1 < sizeof(in_addr_t))?'.':'\t');
      }
      for(p=0; p < ETHER_ADDR_LEN; ++p) {
        printf("%02x%c", rep->arp_sha[p], (p+1 < ETHER_ADDR_LEN)?':':'\0');
      }
      if (flags & VERBOSE) {
        // Print ARP destination (usually our IP)
        printf(" in reply to ");
        for(p=0; p < sizeof(in_addr_t); ++p) {
          printf("%d%c", rep->arp_tpa[p], (p+1 < sizeof(in_addr_t))?'.':'\t');
        }
        for(p=0; p < ETHER_ADDR_LEN; ++p) {
          printf("%02x%c", rep->arp_tha[p], (p+1 < ETHER_ADDR_LEN)?':':'\0');
        }
      }
      printf("\n");
    }
  } //for

  return 0;
}

int split_cidr_range(const char * target, struct in_addr * ip_range, uint32_t * ip_count)
{
  char tmp[IPCIDRSTR_ADDR_LEN];
  int count;
  struct in_addr range;
  char * cidr;
  uint32_t mask = 0xFFFFFFFF;

  strncpy(tmp, target, IPCIDRSTR_ADDR_LEN);

  cidr = strchr(tmp, '/');
  if (cidr == NULL)
    return 1; // Error

  ++cidr;
  if (cidr == NULL)
    return 1; // Error

  count = atoi(cidr);
  if (count < 1 || count > 32)
    return 1; // Error

  --cidr;
  *cidr = 0; // Cut tmp string

  mask = mask << 32-count;

  if (inet_aton(tmp, &range) == 0)
    return 2; // Error

  // Apply mask
  range.s_addr &= htonl(mask);

  // OK
  if (ip_range)
    memcpy(ip_range, &range, sizeof(range)); // Return value if pointer was given

  if (ip_count)
    *ip_count = ~mask; // Return value if pointer was given

  return 0;
}

uint32_t inc_netorder(uint32_t value)
{
  return ntohl(htonl(value)+1);
}

void usage()
{
  printf("Usage: findmacs [-r IP/CIDR] interface\n\n");
  printf("  -r IP/CIDR      Scan this IP range. If not given <localIP>/24 is used\n");
  printf("  -a              Accept ANY reply, even if it wasn't triggered by us\n");
  printf("  -p              Print IP address being queried\n");
  printf("  -v              Increase verbosity level\n");
  printf("  -h              Print this help\n\n");
}
