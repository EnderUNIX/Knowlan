/**************************************************************************
 *   kn_arp.c                                                             *
 *                                                                        *
 *   Copyright (C) 2003 Halil Demirezen  <halil@enderunix.org>            *
 *   									  *
 *   kn_arp.c includes functions that send and recieve ARP packets to     *
 *   extract IP and MAC address infos of the online machines on the LAN.  *
 *									  *
 *								          *
 *   This program is free software; you can redistribute it and/or modify *
 *   it under the terms of the GNU General Public License as published by *
 *   the Free Software Foundation; either version 2, or (at your option)  *
 *   any later version.                                                   *
 *                                                                        *
 *   This program is distributed in the hope that it will be useful,      *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of       *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        *
 *   GNU General Public License for more details.                         *
 *                                                                        *
 *   You should have received a copy of the GNU General Public License    *
 *   along with this program; if not, write to the Free Software          *
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.            *
 *                                                                        *
 **************************************************************************/



#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <libnet.h>

#include "kn_defs.h"

#ifdef __BSD__
#define ether_addr_octet octet
#endif

extern int fd[2];
extern int output_mode;

/* we have to get netmask externall using pcap library. 
   here we can get it. It works, problem  
*/

bpf_u_int32 netmask(char *interface)
{
    bpf_u_int32 netmask;
    bpf_u_int32 ipaddr;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    dev = interface;
    pcap_lookupnet(dev, &ipaddr, &netmask, errbuf);
    return(netmask);
}


/* this is an infinite look that listenes for arp packets that are
   ARP_REPLY, then it extracts them. and print the proper information
   to the user. As the options vary, the format and the contents of the
   info vary. This procedure is called as a child process. After 
   parent's packet sending process ends, and after a 100 ms sleep (last  
   sleep of parent, parent sends a SIGKILL signal to this child process.
   Because of having a non SIGKILL handler, child exits. 
*/

int arp(char *interface)
{
	char *dev; 
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr hdr;     /* pcap.h */
	struct ether_header *eth;   /* net/ethernet.h */
	struct arppacket *arp;
	struct in_addr tmp;
	unsigned long ip;
	unsigned char buffer[256];
	pid_t parent;
	
	parent = getppid();
	dev = interface;

	if ((descr = pcap_open_live(dev, 1500, 0, 500, errbuf)) == NULL) {
		fprintf(stderr, "pcap_open_live %s failed: %s\n", dev, errbuf);
		exit(1);
     	}
		/* infinite loop for 
		   waiting ARP_REPLY packets.
		*/ 
	if(output_mode == NORMAL_OUTPUT){
		memset(buffer, 0x0, 256);
		sprintf(buffer, "----------------------------------------------\n");
		sprintf(buffer + 47, " EnderUNIX knowlan 0.1.1 - LAN Address Extractor\n");
		sprintf(buffer + 96, " Use -h option for a brief help about the tool\n");
		sprintf(buffer + 143, "----------------------------------------------\n");
		sprintf(buffer + 190, "Interface Name: %s\n", interface);
		write(fd[1], buffer, sizeof(buffer));
		kill(parent, SIGUSR2);
		memset(buffer, 0x0, 256);
		sprintf(buffer, "IP ADRESSES\tMAC ADDRESSES\n");
		write(fd[1], buffer, sizeof(buffer));
		kill(parent, SIGUSR2);
	}

        usleep(300);
	do{
		packet = pcap_next(descr,&hdr);
		eth = (struct ether_header *) packet;
		if (hdr.len < 14)
			continue;
		if (eth == NULL)
			continue;
		if(htons(eth->ether_type) == ETHERTYPE_ARP){
			arp = (struct arppacket *) packet;			
			if(htons(arp->opcode) == ARPOP_REPLY){
				memcpy((char *)&ip, arp->sourceip, 4);
				tmp.s_addr = ip;
				memset(buffer, 0x0, 256);
				sprintf(buffer, "%s\t%02X:%02X:%02X:%02X:%02X:%02X\n",inet_ntoa(tmp), arp->sourceadd[0], arp->sourceadd[1], arp->sourceadd[2],
					        arp->sourceadd[3], arp->sourceadd[4], arp->sourceadd[5]);
				write(fd[1], buffer, sizeof(buffer));
				kill(parent, SIGUSR2);
			}  
		}
	}while(1);
	return 0;
}



int send_arp_packet(char *interface)
{
	struct arppacket *arp;
	u_short packet_size = 42;
	u_char errbuf[256];
	unsigned ip, ip_dst,net;
	u_char *packet;
	struct ether_addr *eth;
	struct libnet_link_int *libnet_link_int;
	u_long number, i;
	char *dev;
 
	if(libnet_init_packet(packet_size, &packet) == -1){
		printf("Can't allocate memory for packet\n");
		return -1;
   	}

	dev = interface;
	libnet_init_packet(packet_size, &packet);
	if ((libnet_link_int = libnet_open_link_interface(interface, errbuf)) == NULL) {
		fprintf(stderr, "cannot open link interface %s: %s\n", interface, errbuf);
		return -1;
  	}

	ip = libnet_get_ipaddr(libnet_link_int, interface, errbuf);
	ip = htonl(ip);
	eth = libnet_get_hwaddr(libnet_link_int, interface, errbuf);
	arp = (struct arppacket *)packet;
		/* let's fill the arp 
		   packet for the proper info 
		*/
	arp->protocoltype = htons(ETHERTYPE_ARP);    /* ARP protocol */
	arp->hardwaretype = htons(ARPHRD_ETHER);     /* Hardware ether */
	arp->resprotocol = htons(ETHERTYPE_IP);      /* Next protocol */
	arp->halen = 6;			             /* Hardare address length */
	arp->palen = 4;				     /* protocol address length */
	arp->opcode = htons(ARPOP_REQUEST);	     /* Arp Opcode */
	memset(arp->destmac, 0xff, 6);	       
	memset(arp->destadd, 0x0, 6);
	memcpy(arp->sourcemac, eth->ether_addr_octet, 6);   /* my ethernet mac */
	memcpy(arp->sourceadd, eth->ether_addr_octet, 6);   /* my arp mac */
	memcpy(arp->sourceip, (char *)&ip, 4);	            /* my arp ip address */	   
	net = netmask(interface);	 		    /* let's get mask */
	number = ntohl(~net);        			    /* maximum number of hosts in the lan */
		/* here send all possible ip 
		   addresses whether they are on 
		   or not. We will decide on this
		   depending on whether they reply 
		   arp back or not 
		*/
	for(i = 1; i < number; i++) {
		ip_dst = (ip & net) | htonl(i);
		memcpy(arp->destip, (char *)&ip_dst, 4);
		if(libnet_write_link_layer(libnet_link_int, interface, (u_char *)packet, packet_size) == -1){
			printf("libnet_write_link_layer failed\n");
			return -1;
		}	
		usleep(100); 
	}
	return 0;
}
