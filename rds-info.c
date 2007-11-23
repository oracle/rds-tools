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

#include "net/rds.h"
#include "rdstool.h"

#define rds_conn_flag(conn, flag, letter) \
	(conn.flags & RDS_INFO_CONNECTION_FLAG_##flag ? letter : '-')

#define min(a, b) (a < b ? a : b)
#define array_size(foo) (sizeof(foo) / sizeof(foo[0]))

#define copy_into(var, data, each) ({			\
	int __ret = 1;					\
	memset(&var, 0, sizeof(var));			\
	memcpy(&var, data, min(each, sizeof(var)));	\
	__ret;						\
})

#define for_each(var, data, each, len) 			\
	for (;len > 0 && copy_into(var, data, each);	\
	     data += each, len -= min(len, each))

static void print_counters(void *data, int each, socklen_t len, void *extra)
{
	struct rds_info_counter ctr;

	printf("\nCounters:\n%25s %16s\n", "CounterName", "Value");

	for_each(ctr, data, each, len)
		printf("%25s %16"PRIu64"\n", ctr.name, ctr.value);
}

static void print_sockets(void *data, int each, socklen_t len, void *extra)
{
	struct rds_info_socket sk;
	struct in_addr addr;

	printf("\nRDS Sockets:\n%15s %5s %15s %5s %10s %10s\n",
		"BoundAddr", "BPort", "ConnAddr", "CPort", "SndBuf",
		"RcvBuf");
	
	for_each(sk, data, each, len) {
		addr.s_addr = sk.bound_addr;
		printf("%15s %5u ", inet_ntoa(addr),
		       ntohs(sk.bound_port));
		addr.s_addr = sk.connected_addr;
		printf("%15s %5u %10u %10u\n",
			inet_ntoa(addr), ntohs(sk.connected_port),
			sk.sndbuf, sk.rcvbuf);
	}
}

static void print_conns(void *data, int each, socklen_t len, void *extra)
{
	struct rds_info_connection conn;
	struct in_addr addr;

	printf("\nRDS Connections:\n%15s %15s %16s %16s %3s\n",
		"LocalAddr", "RemoteAddr", "NextTX", "NextRX", "Flg");
	
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
}

static void print_msgs(void *data, int each, socklen_t len, void *extra)
{
	struct rds_info_message msg;
	struct in_addr addr;

	printf("\n%s Message Queue:\n%15s %5s %15s %5s %16s %10s\n",
		(char *)extra,
		"LocalAddr", "LPort", "RemoteAddr", "RPort", "Seq", "Bytes");
	
	for_each(msg, data, each, len) {
		addr.s_addr = msg.laddr;
		printf("%15s %5u ", inet_ntoa(addr), ntohs(msg.lport));
		addr.s_addr = msg.faddr;
		printf("%15s %5u %16"PRIu64" %10u\n",
			inet_ntoa(addr), ntohs(msg.fport), msg.seq, msg.len);
	}
}

static void print_tcp_socks(void *data, int each, socklen_t len, void *extra)
{		
	struct rds_info_tcp_socket ts;
	struct in_addr addr;

	printf("\nTCP Connections:\n"
		"%15s %5s %15s %5s %10s %10s %10s %10s %10s\n",
		"LocalAddr", "LPort", "RemoteAddr", "RPort",
		"HdrRemain", "DataRemain", "SentNxt", "ExpectUna", "SeenUna");
	
	for_each(ts, data, each, len) {
		addr.s_addr = ts.local_addr;
		printf("%15s %5u ", inet_ntoa(addr),
			ntohs(ts.local_port));
		addr.s_addr = ts.local_addr;
		printf("%15s %5u %10"PRIu64" %10"PRIu64" %10u %10u %10u\n",
			inet_ntoa(addr), ntohs(ts.peer_port),
			ts.hdr_rem, ts.data_rem, ts.last_sent_nxt,
			ts.last_expected_una, ts.last_seen_una);
	}
}

struct info {
	int opt_val;
	char *description;
	void (*print)(void *data, int each, socklen_t len, void *extra);
	void *extra;
	int option_given;
};

struct info infos[] = {
	['c'] = { RDS_INFO_COUNTERS, "statistic counters",
		print_counters, NULL, 0 },
	['k'] = { RDS_INFO_SOCKETS, "sockets", 
		print_sockets, NULL, 0 },
	['n'] = { RDS_INFO_CONNECTIONS, "connections",
		print_conns, NULL, 0 },
	['r'] = { RDS_INFO_RECV_MESSAGES, "recv queue messages",
		print_msgs, "Receive", 0 },
	['s'] = { RDS_INFO_SEND_MESSAGES, "send queue messages",
		print_msgs, "Send", 0 },
	['t'] = { RDS_INFO_RETRANS_MESSAGES, "retransmit queue messages",
		  print_msgs, "Retransmit", 0 },
	['T'] = { RDS_INFO_TCP_SOCKETS, "TCP transport sockets",
		  print_tcp_socks, NULL, 0 },
};

void print_usage(int rc)
{
	FILE *output = rc ? stderr : stdout;
	int i;

	verbosef(0, output, "The following options limit output to the given "
		 "sources:\n");

	for (i = 0; i < array_size(infos); i++) {
		if (!infos[i].opt_val)
			continue;
		printf("    -%c %s\n", i, infos[i].description);
	}

	verbosef(0, output,
		"\n\nIf no options are given then all sources are used.\n");
	exit(rc);
}

void print_version()
{
}

int main(int argc, char **argv)
{
	char optstring[258] = "+";
	int given_options = 0;
	socklen_t len = 0;
	void *data = NULL;
	int fd;
	int each;
	int c;
	char *last;
	int i;

	/* quickly append all our info options to the optstring */
	last = &optstring[strlen(optstring)];
	for (i = 0; i < array_size(infos); i++) {
		if (!infos[i].opt_val)
			continue;
		*last = (char)i;
		last++;
		*last = '\0';
	}

	while ((c = getopt(argc, argv, optstring)) != EOF) {
		if (c >= array_size(infos) || !infos[c].opt_val) {
			verbosef(0, stderr, "%s: Invalid option \'-%c\'\n",
				 progname, optopt);
			print_usage(1);
		}

		infos[c].option_given = 1;
		given_options++;
	}

	fd = socket(PF_RDS, SOCK_SEQPACKET, 0);
	if (fd < 0) {
		verbosef(0, stderr, "%s: Unable to create socket: %s\n",
			 progname, strerror(errno));
		return 1;
	}

	for (i = 0; i < array_size(infos); i++) {
		if (!infos[i].opt_val ||
		    (given_options && !infos[i].option_given))
			continue;

		/* read in the info until we get a full snapshot */
		while ((each = getsockopt(fd, SOL_RDS, infos[i].opt_val, data,
				   &len)) < 0) {
			if (errno != ENOSPC) {
				verbosef(0, stderr,
					 "%s: Unable get statistics: %s\n",
					 progname, strerror(errno));
				return 1;
			}
			if (data)
				data = realloc(data, len);
			else
				data = malloc(len);

			if (data == NULL) {
				verbosef(0, stderr,
					 "%s: Unable to allocate memory "
					 "for %u bytes of info: %s\n",
					 progname, len, strerror(errno));
				return 1;
			}
		}

		infos[i].print(data, each, len, infos[i].extra);

		if (given_options && --given_options == 0)
			break;
	}

	return 0;
}
