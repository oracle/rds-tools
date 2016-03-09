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

#include "rds.h"
#include "pfhack.h"

/* WHUPS changed the struct rds_info_connection definition b/w rds in 1.4 & 1.5. gotta support both
   for now. TODO remove check of transport[15] once ofed pre-1.5 is extinct. */
#define rds_conn_flag(conn, flag, letter) \
	(conn.flags & RDS_INFO_CONNECTION_FLAG_##flag \
	|| conn.transport[15] & RDS_INFO_CONNECTION_FLAG_##flag ? letter : '-')

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

#define verbosef(lvl, f, fmt, a...) do { \
        if (opt_verbose >= (lvl)) \
                fprintf((f), fmt, ##a); \
} while (0)

static int	opt_verbose = 0;

char *progname = "rds-info";

/* Like inet_ntoa, but can be re-entered several times without clobbering
 * the previously returned string. */
static const char *paddr(int af, const void *addrp)
{
	static char nbuf[8][INET6_ADDRSTRLEN];
	static int which = 0;
	char *string;

	string = nbuf[which];
	which = (which + 1) % 8;

	inet_ntop(af, addrp, string, INET6_ADDRSTRLEN);
	return string;
}

static const char *ipv4addr(uint32_t addr)
{
	return paddr(AF_INET, &addr);
}

static const char *ipv6addr(const void *addr)
{
	return paddr(AF_INET6, addr);
}

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

	printf("\nRDS Sockets:\n%15s %5s %15s %5s %10s %10s %8s\n",
		"BoundAddr", "BPort", "ConnAddr", "CPort", "SndBuf",
		"RcvBuf", "Inode");

	for_each(sk, data, each, len) {
		printf("%15s %5u %15s %5u %10u %10u %8Lu\n",
			ipv4addr(sk.bound_addr),
			ntohs(sk.bound_port),
			ipv4addr(sk.connected_addr),
			ntohs(sk.connected_port),
			sk.sndbuf, sk.rcvbuf,
			(unsigned long long) sk.inum);
	}
}

static void print_conns(void *data, int each, socklen_t len, void *extra)
{
	struct rds_info_connection conn;

	printf("\nRDS Connections:\n%15s %15s %4s %16s %16s %4s\n",
		"LocalAddr", "RemoteAddr", "Tos", "NextTX", "NextRX", "Flgs");
	
	for_each(conn, data, each, len) {
		printf("%15s %15s %4u %16"PRIu64" %16"PRIu64" %c%c%c%c\n",
			ipv4addr(conn.laddr),
			ipv4addr(conn.faddr),
			conn.tos,
			conn.next_tx_seq,
			conn.next_rx_seq,
			rds_conn_flag(conn, SENDING, 's'),
			rds_conn_flag(conn, CONNECTING, 'c'),
			rds_conn_flag(conn, CONNECTED, 'C'),
			rds_conn_flag(conn, ERROR, 'E'));
	}
}

static void print_msgs(void *data, int each, socklen_t len, void *extra)
{
	struct rds_info_message msg;

	printf("\n%s Message Queue:\n%15s %5s %15s %5s %4s %16s %10s\n",
		(char *)extra,
		"LocalAddr", "LPort", "RemoteAddr", "RPort", "Tos","Seq", "Bytes");
	
	for_each(msg, data, each, len) {
		printf("%15s %5u %15s %5u %4u %16"PRIu64" %10u\n",
			ipv4addr(msg.laddr),
			ntohs(msg.lport),
			ipv4addr(msg.faddr),
			ntohs(msg.fport),
			msg.tos,
			msg.seq, msg.len);
	}
}

static void print_tcp_socks(void *data, int each, socklen_t len, void *extra)
{		
	struct rds_info_tcp_socket ts;

	printf("\nTCP Connections:\n"
		"%15s %5s %15s %5s %10s %10s %10s %10s %10s\n",
		"LocalAddr", "LPort", "RemoteAddr", "RPort",
		"HdrRemain", "DataRemain", "SentNxt", "ExpectUna", "SeenUna");
	
	for_each(ts, data, each, len) {
		printf("%15s %5u %15s %5u %10"PRIu64" %10"PRIu64" %10u %10u %10u\n",
			ipv4addr(ts.local_addr),
			ntohs(ts.local_port),
			ipv4addr(ts.peer_addr),
			ntohs(ts.peer_port),
			ts.hdr_rem, ts.data_rem, ts.last_sent_nxt,
			ts.last_expected_una, ts.last_seen_una);
	}
}

static void print_ib_conns(void *data, int each, socklen_t len, void *extra)
{
	struct rds_info_rdma_connection ic;

	printf("\nRDS IB Connections:\n%15s %15s %4s %3s %32s %32s\n",
		"LocalAddr", "RemoteAddr", "Tos", "SL", "LocalDev", "RemoteDev");

	for_each(ic, data, each, len) {
		printf("%15s %15s %4u %3u %32s %32s",
			ipv4addr(ic.src_addr),
			ipv4addr(ic.dst_addr),
			ic.tos,ic.sl,
			ipv6addr(ic.src_gid),
			ipv6addr(ic.dst_gid));

		if (opt_verbose) {
			printf("  send_wr=%u", ic.max_send_wr);
			printf(", recv_wr=%u", ic.max_recv_wr);
			printf(", send_sge=%u", ic.max_send_sge);
			printf(", rdma_mr_max=%u", ic.rdma_mr_max);
			printf(", rdma_mr_size=%u", ic.rdma_mr_size);
			printf(", cache_allocs=%u", ic.cache_allocs);
		}

		printf("\n");
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
	['I'] = { RDS_INFO_IB_CONNECTIONS, "IB transport connections",
		  print_ib_conns, NULL, 0 },
};

static void print_usage(int rc)
{
	FILE *output = rc ? stderr : stdout;
	int i;

	fprintf(stderr, "rds-info version %s\n", RDS_VERSION);

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

int main(int argc, char **argv)
{
	char optstring[258] = "v+";
	int given_options = 0;
	socklen_t len = 0;
	void *data = NULL;
	int fd;
	int each;
	int c;
	char *last;
	int i;
	int pf;
	int sol;

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
		switch (c) {
		case 'v':
			opt_verbose++;
			continue;
		}

		if (c >= array_size(infos) || !infos[c].opt_val) {
			verbosef(0, stderr, "%s: Invalid option \'-%c\'\n",
				 progname, optopt);
			print_usage(1);
		}

		infos[c].option_given = 1;
		given_options++;
	}

#ifdef DYNAMIC_PF_RDS
	pf = discover_pf_rds();
	sol = discover_sol_rds();
#else
	pf = PF_RDS;
	sol = SOL_RDS;
#endif
	fd = socket(pf, SOCK_SEQPACKET, 0);
	if (fd < 0) {
		verbosef(0, stderr, "%s: Unable to create socket: %s\n",
			 progname, strerror(errno));
		return 1;
	}

	for (i = 0; i < array_size(infos); i++) {
		int invalid_opt = 0;
		if (!infos[i].opt_val ||
		    (given_options && !infos[i].option_given))
			continue;

		/* read in the info until we get a full snapshot */
		while ((each = getsockopt(fd, sol, infos[i].opt_val, data,
				   &len)) < 0) {
			if (errno != ENOSPC) {
				verbosef(0, stderr,
					 "%s: Unable get statistics: %s\n",
					 progname, strerror(errno));
				invalid_opt = 1;
				break;
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

		if (invalid_opt)
			continue;

		infos[i].print(data, each, len, infos[i].extra);

		if (given_options && --given_options == 0)
			break;
	}

	return 0;
}
