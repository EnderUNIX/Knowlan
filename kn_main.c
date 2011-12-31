/**************************************************************************
 *   kn_main.c                                                            *
 *                                                                        *
 *   Copyright (C) 2003 Halil Demirezen  <halil@enderunix.org>            *
 *                                                                        *
 *   kn_main.c is the starting point of the program. It forks and with    *
 *   child it recieves ARP replies and with parent it sends ARP packets   *
 *   and after sending ARP reqests finishes, it quits the child by 	  *
 *   killing it.							  *
 *  									  *
 *                                                                        *
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
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <signal.h>

#include "kn_defs.h"


void wout(void);

char *optarg;
int fd[2];
int output_mode = NORMAL_OUTPUT;

int main(int argc, char **argv)
{
     int i, c, error = 0;
     char *interface = NULL;
     char errbuf[PCAP_ERRBUF_SIZE];
     pcap_t * descr;
     char *dev;

		/* if we do not specfify an 
		   interface, let's give it 
		   to pcap to determine  an 
		   interface
   		*/

	if(pipe(fd) < 0)
		perror("Pipe error"), exit(-1);
      
	while(!error && (c = getopt(argc, argv, "i:hvq")) != -1){
		switch(c){
			case 'i':
				interface = optarg;
				break;
			case 'q':
				output_mode = QUIET_OUTPUT;
				break;
			case 'h':			
 				usage();
				return 0;	
			case 'v':
				version();
				return 0;
		}
			if(c == 'i' && !interface) return -1;
	 }

	 if(!interface){	
		interface = pcap_lookupdev(errbuf);
		if(interface == NULL){
		   fprintf(stderr, "can't open device\n");
		   return -1;
		}
	 }

	if(getuid() != 0){
	    fprintf(stderr, "You need root privileges to run knowlan\n");
	    return -1;
	}

     	dev = interface;
	if ((descr = pcap_open_live(dev, 1500, 0, 500, errbuf)) == NULL) {
		fprintf(stderr, "pcap_open_live %s failed: %s\n", dev, errbuf);
		exit(1);
	}
		 /* if we are here, we have got 
		    no problem at all. Let's do 
		    our job 
		 */

	if((i = fork()) == 0){
		/* in the child, there is an 
		   infinite loop that waits 
		   for the arp replies and 
		   printing ip addresses of 
		   the arp replies. 
		*/	
		signal(SIGUSR1, exit);
		arp(interface);
	} else {
		signal(SIGUSR2, wout);
		/* here we did some trick,
		   after sending arp request 
		   packets,  we send   kill 
		   signal to the child which 
		   collects arp replies, on a lan, 
		   arp reply must be less than 100 
		   msec, after sending last packet 
		   and 100msec sleep, we kill child. 
		   That is over. 
		*/
		send_arp_packet(interface);
		kill(i, SIGUSR1);
	}
	return 0;
}

void usage()
{
	fprintf(stderr, "Usage: knowlan [options] [interface]\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "-i interface\tact on different interface\n");
	fprintf(stderr, "-h\t\tprints this help\n");
	fprintf(stderr, "-v\t\tversion number\n");
	fprintf(stderr, "-q\t\tA raw output for piping and logging\n");
	fprintf(stderr, "Halil Demirezen <halil@enderunix.org>\n");
}

void version()
{
	fprintf(stderr, "0.2\n");
}

void wout(void)
{
	unsigned char buffer[256];
	if(read(fd[0], buffer, sizeof(buffer)) > 0){
		write(1, buffer, strlen(buffer));
	}
}




