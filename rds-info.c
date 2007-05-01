/*
 * Copyright (c) 2006 Oracle.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rdstool.h"

void print_usage(int rc)
{
	FILE *output = rc ? stderr : stdout;

	verbosef(0, output,
		 "Usage: %s [-c] [-s]\n"
		 "	-c	statistic counters\n"
		 "	-f	flows\n"
		 "	-k	sockets\n"
		 "	-n	connections\n"
		 "	-r	recv queue messages\n"
		 "	-s	send queue messages\n"
		 "	-t	retransmit queue messages\n"
		 "	-T	TCP transport sockets\n",
		 progname);

	exit(rc);
}
void print_version()
{
}

#define RDS_INFO_COUNTERS		10000
#define RDS_INFO_CONNECTIONS		10001
#define RDS_INFO_FLOWS			10002
#define RDS_INFO_SEND_MESSAGES		10003
#define RDS_INFO_RETRANS_MESSAGES       10004
#define RDS_INFO_RECV_MESSAGES          10005
#define RDS_INFO_SOCKETS                10006
#define RDS_INFO_TCP_SOCKETS            10007

struct rds_info_counter {
	uint8_t		name[32];
	uint64_t	value;
};

#define RDS_INFO_CONNECTION_FLAG_SENDING	0x01
#define RDS_INFO_CONNECTION_FLAG_CONNECTING	0x02
#define RDS_INFO_CONNECTION_FLAG_CONNECTED	0x04

struct rds_info_connection {
	uint64_t	next_tx_seq;
	uint64_t	next_rx_seq;
	uint32_t	laddr;
	uint32_t	faddr;
	uint8_t		transport[15];           /* null term ascii */
	uint8_t		flags;
} __attribute__((packed));

struct rds_info_flow {
	uint32_t	laddr;
	uint32_t	faddr;
	uint32_t	bytes;
	uint16_t	lport;
	uint16_t	fport;
} __attribute__((packed));

struct rds_info_socket {
	uint32_t	sndbuf;
	uint32_t	bound_addr;
	uint32_t	connected_addr;
	uint16_t	bound_port;
	uint16_t	connected_port;
	uint32_t	rcvbuf;
} __attribute__((packed));

#define RDS_INFO_MESSAGE_FLAG_ACK               0x01
#define RDS_INFO_MESSAGE_FLAG_FAST_ACK          0x02

struct rds_info_message {
	uint64_t	seq;
	uint32_t	len;
	uint32_t	laddr;
	uint32_t	faddr;
	uint16_t	lport;
	uint16_t	fport;
	uint8_t		flags;
} __attribute__((packed));

struct rds_info_tcp_socket {
	/* _addr and _port are network (big) endian */
        uint32_t          local_addr;
        uint16_t          local_port;
        uint32_t          peer_addr;
        uint16_t          peer_port;
        uint64_t             hdr_rem;
        uint64_t             data_rem;
        uint32_t             last_sent_nxt;
        uint32_t             last_expected_una;
        uint32_t             last_seen_una;
} __attribute__((packed));


#define rds_conn_flag(conn, flag, letter) \
	(conn.flags & RDS_INFO_CONNECTION_FLAG_##flag ? letter : '-')

#define min(a, b) (a < b ? a : b)

#define copy_into(var, data, each) ({			\
	int __ret = 1;					\
	memset(&var, 0, sizeof(var));			\
	memcpy(&var, data, min(each, sizeof(var)));	\
	__ret;						\
})

#define for_each(var, data, each, len) 			\
	for (;len > 0 && copy_into(var, data, each);	\
	     data += each, len -= min(len, each))

int main(int argc, char **argv)
{
	socklen_t len = 0;
	void *data = NULL;
	int status = 1;
	int info = 0;
	int fd;
	int each;
	int c;

	while ((c = getopt(argc, argv, "+cfknrstT")) != EOF) {
		switch (c) {
			case 'c':
				info = RDS_INFO_COUNTERS;
				break;
			case 'f':
				info = RDS_INFO_FLOWS;
				break;
			case 'k':
				info = RDS_INFO_SOCKETS;
				break;
			case 'n':
				info = RDS_INFO_CONNECTIONS;
				break;
			case 'r':
				info = RDS_INFO_RECV_MESSAGES;
				break;
			case 's':
				info = RDS_INFO_SEND_MESSAGES;
				break;
			case 't':
				info = RDS_INFO_RETRANS_MESSAGES;
				break;
			case 'T':
				info = RDS_INFO_TCP_SOCKETS;
				break;
			case '?':
				verbosef(0, stderr,
					 "%s: Invalid option \'-%c\'\n",
					 progname, optopt);
				print_usage(1);
				break;
		}
	}

	if (info == 0) {
		verbosef(0, stderr, "%s: No output chosen\n", progname);
		print_usage(1);
	}

	fd = socket(PF_RDS, SOCK_SEQPACKET, 0);
	if (fd < 0) {
		verbosef(0, stderr, "%s: Unable to create socket: %s\n",
			 progname, strerror(errno));
		goto out;
	}

	while ((each = getsockopt(fd, SOL_RDS, info, data, &len)) < 0) {
		if (errno != ENOSPC) {
			verbosef(0, stderr, "%s: Unable get statistics: %s\n",
				 progname, strerror(errno));
			goto out;
		}


		if (data)
			data = realloc(data, len);
		else
			data = malloc(len);

		if (data == NULL) {
			verbosef(0, stderr, "%s: Unable to allocate memory "
				 "for %u bytes of info: %s\n", progname, len,
				 strerror(errno));
			goto out;
		}
	}

	switch(info) {
	case RDS_INFO_COUNTERS: {
		struct rds_info_counter ctr;

		for_each(ctr, data, each, len)
			printf("%-25s: %"PRIu64"\n", ctr.name, ctr.value);
		break;
	}

	case RDS_INFO_CONNECTIONS: {
		struct rds_info_connection conn;
		struct in_addr addr;
		
		for_each(conn, data, each, len) {
			addr.s_addr = conn.laddr;
			printf("%15s ", inet_ntoa(addr));
			addr.s_addr = conn.faddr;
			printf("%15s %16"PRIu64" %16"PRIu64" ",
				inet_ntoa(addr), conn.next_tx_seq,
				conn.next_rx_seq);
			printf("%c%c%c\n",
			      rds_conn_flag(conn, SENDING, 's'),
			      rds_conn_flag(conn, CONNECTING, 'c'),
			      rds_conn_flag(conn, CONNECTED, 'C'));
		}
		break;
	}

	case RDS_INFO_SOCKETS: {
		struct rds_info_socket sk;
		struct in_addr addr;
		
		for_each(sk, data, each, len) {
			addr.s_addr = sk.bound_addr;
			printf("%15s %5u", inet_ntoa(addr),
			       ntohs(sk.bound_port));
			addr.s_addr = sk.connected_addr;
			printf("%15s %5u %10u %10u\n",
				inet_ntoa(addr), ntohs(sk.connected_port),
				sk.sndbuf, sk.rcvbuf);
		}
		break;
	}

	case RDS_INFO_FLOWS: {
		struct rds_info_flow flow;
		struct in_addr addr;
		
		for_each(flow, data, each, len) {
			addr.s_addr = flow.laddr;
			printf("%15s %5u", inet_ntoa(addr), ntohs(flow.lport));
			addr.s_addr = flow.faddr;
			printf("%15s %5u %10u\n",
				inet_ntoa(addr), ntohs(flow.fport),
				flow.bytes);
		}
		break;
	}

	case RDS_INFO_SEND_MESSAGES:
	case RDS_INFO_RECV_MESSAGES:
	case RDS_INFO_RETRANS_MESSAGES: {
		struct rds_info_message msg;
		struct in_addr addr;
		char c = ' ';
		
		for_each(msg, data, each, len) {
			if (msg.flags & RDS_INFO_MESSAGE_FLAG_ACK)
				c = 'a';
			else if (msg.flags & RDS_INFO_MESSAGE_FLAG_FAST_ACK)
				c = 'f';

			addr.s_addr = msg.laddr;
			printf("%15s %5u", inet_ntoa(addr), ntohs(msg.lport));
			addr.s_addr = msg.faddr;
			printf("%15s %5u %16"PRIu64" %10u %c\n",
				inet_ntoa(addr), ntohs(msg.fport), msg.seq,
				msg.len, c);
		}
		break;
	}

	case RDS_INFO_TCP_SOCKETS: {
		struct rds_info_tcp_socket ts;
		struct in_addr addr;
		
		for_each(ts, data, each, len) {
			addr.s_addr = ts.local_addr;
			printf("%15s %5u", inet_ntoa(addr),
				ntohs(ts.local_port));
			addr.s_addr = ts.local_addr;
			printf("%15s %5u %10"PRIu64" %10"PRIu64" %10u %10u\n",
				inet_ntoa(addr), ntohs(ts.peer_port),
				ts.hdr_rem, ts.data_rem, ts.last_sent_nxt,
				ts.last_expected_una, ts.last_seen_una);
		}
		break;
	}

	}

	status = 0;

out:
	return status;
}
