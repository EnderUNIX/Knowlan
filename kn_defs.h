/**************************************************************************
 *   kn_defs.h                                                            *
 *                                                                        *
 *   Copyright (C) 2003 Halil Demirezen  <halil@enderunix.org>            *
 *                                                                        *
 *   kn_defs.h includes arppacket structure for better handling And	  *
 *   includes prototypes of the functions used.				  *
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

#define NORMAL_OUTPUT	0
#define QUIET_OUTPUT	1

struct arppacket {
        u_char destmac[6];
        u_char sourcemac[6];
        unsigned short protocoltype;
        unsigned short hardwaretype;
        unsigned short resprotocol;
        u_char halen;
        u_char palen;
        unsigned short opcode;
        u_char sourceadd[6];
        u_char sourceip[4];
        u_char destadd[6];
        u_char destip[4];
};


int arp(char *);
int send_arp_packet(char *);
int fork(void);
void usage(void);
void version(void);
void wout(void);
