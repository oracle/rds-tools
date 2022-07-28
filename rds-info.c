/*
 * Copyright (c) 2006, 2018 Oracle and/or its affiliates. All rights reserved.
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

#define _GNU_SOURCE
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
#include <stdbool.h>
#include <time.h>

#include "rds.h"
#include "pfhack.h"

/* WHUPS changed the struct rds_info_connection definition b/w rds in 1.4 & 1.5. gotta support both
   for now. TODO remove check of transport[15] once ofed pre-1.5 is extinct. */

#define rds_conn_flag(conn_flags, flag, transport, letter) \
	(conn_flags & RDS_INFO_CONNECTION_FLAG_##flag \
	|| transport[15] & RDS_INFO_CONNECTION_FLAG_##flag ? letter : '-')

#define min(a, b) (a < b ? a : b)
#define max(a, b) (a > b ? a : b)
#define array_size(foo) (sizeof(foo) / sizeof(foo[0]))

#define copy_into(var, data, each) ({			\
	int __ret = 1;					\
	memset(&var, 0, sizeof(var));			\
	memcpy(&var, data, min(each, sizeof(var)));	\
	__ret;						\
})

#define kB(a) ((float)a / 1024.0)

#define for_each(var, data, each, len) 			\
	for (;len > 0 && copy_into(var, data, each);	\
	     data += each, len -= min(len, each))

#define verbosef(lvl, f, fmt, a...) do { \
        if (opt_verbose >= (lvl)) \
                fprintf((f), fmt, ##a); \
} while (0)

#define ADD_FIELD_STR_LEN 256

static int	opt_verbose = 0;
static int	opt_add;
char		add_fields[ADD_FIELD_STR_LEN] = "";

char *progname = "rds-info";

/* IPv4/v6 address output string width */
#define PRT_IPV4_WIDTH	15
#define PRT_IPV6_WIDTH	37

#define PROCPATHLEN 32
#define TASK_COMM_LEN 16

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

static const char *ipv6addr(const void *addr)
{
	return paddr(AF_INET6, addr);
}

/*
 * If prt_ipv6 is true, the given pointer is a struct in6_addr and IPv4
 * address is represented as an IPv4 mapped address.  If prt_ipv6 is false,
 * the given pointer is a struct in_addr.  This function returns a pointer
 * to an ASCII representation of the given address.
 */
static const char *ipaddr(const void *addr, bool prt_ipv6)
{
	struct in6_addr *v6addr = (struct in6_addr *)addr;

	if (prt_ipv6) {
		if (IN6_IS_ADDR_V4MAPPED(v6addr))
			return paddr(AF_INET, &v6addr->s6_addr32[3]);
		else
			return paddr(AF_INET6, v6addr);
	} else {
		return paddr(AF_INET, addr);
	}
}

static void print_counters(void *data, int each, socklen_t len, void *extra,
			   bool prt_ipv6)
{
	struct rds_info_counter ctr;

	printf("\nCounters:\n%32s %16s\n", "CounterName", "Value");

	for_each(ctr, data, each, len)
	  printf("%32s %16"PRIu64"\n", ctr.name, (uint64_t) ctr.value);
}

/* Returns 0 on success. */
static int get_comm(pid_t pid, char *comm, int sz)
{
	char file_path[PROCPATHLEN];
	size_t size;
	FILE *fp;

	if (pid == 0)
		return -1;

	sprintf(file_path, "/proc/%d/comm", pid);

	fp = fopen(file_path, "r");
	if (!fp)
		return -1;

	size = fread(comm, sizeof(char), sz, fp);
	if (ferror(fp))
		return -1;

	fclose(fp);
	size = max(size, 1);
	comm[size - 1] = '\0';
	return 0;
}

/*
 * On a non supported kernel, the value in the field would be set to 0
 * and a supported kernel returns -1 to indicate a non-congested state.
 * Thus we use this function to swap the 0 and -1 values to indicate
 * a non congested state and a non-supported state.
 */
static void get_congested(int *congested)
{
	if (*congested == 0)
		*congested = -1;
	else if (*congested == -1)
		*congested = 0;
}

static void print_sockets(void *data, int each, socklen_t len, void *extra,
			  bool prt_ipv6)
{
	char comm[TASK_COMM_LEN];
	struct rds6_info_socket sk6;
	struct rds_info_socket sk;
	int prt_width;

	if (prt_ipv6)
		prt_width = PRT_IPV6_WIDTH;
	else
		prt_width = PRT_IPV4_WIDTH;

	printf("\nRDS Sockets:\n%*s %5s %*s %5s %10s %10s %8s %8s %10s %16s\n",
	       prt_width, "BoundAddr", "BPort", prt_width, "ConnAddr", "CPort",
	       "SndBuf", "RcvBuf", "Inode", "Cong", "Pid", "Comm");

	if (prt_ipv6) {
		for_each(sk6, data, each, len) {
			printf("%*s %5u %*s %5u %10u %10u %8llu",
			       prt_width, ipaddr(&sk6.bound_addr, prt_ipv6),
			       ntohs(sk6.bound_port),
			       prt_width, ipaddr(&sk6.connected_addr, prt_ipv6),
			       ntohs(sk6.connected_port),
			       sk6.sndbuf, sk6.rcvbuf,
			       (unsigned long long)sk6.inum);
			get_congested(&sk6.cong);
				printf(" %8d", sk6.cong);
			if (get_comm(sk6.pid, comm, TASK_COMM_LEN) != -1)
				printf(" %10u %16s", sk6.pid, comm);
			printf("\n");
		}
	} else {
		for_each(sk, data, each, len) {
			printf("%*s %5u %*s %5u %10u %10u %8llu",
			       prt_width, ipaddr(&sk.bound_addr, prt_ipv6),
			       ntohs(sk.bound_port),
			       prt_width, ipaddr(&sk.connected_addr, prt_ipv6),
			       ntohs(sk.connected_port),
			       sk.sndbuf, sk.rcvbuf,
			       (unsigned long long)sk.inum);
			get_congested(&sk.cong);
				printf(" %8d", sk.cong);
			if (get_comm(sk.pid, comm, TASK_COMM_LEN) != -1)
				printf(" %10u %16s", sk.pid, comm);
			printf("\n");
		}
	}
}

static void print_time(time_t *time)
{
	char buf[128];

	if ((*time) == 0) {
		printf("%-24s ", "---");
	} else {
		strftime(buf, sizeof(buf), "%D %H:%M:%S %Z", localtime(time));
		printf("%-24s ", buf);
	}
}

#define MAC_DISCON_REASON       (sizeof(conn_drop_reasons)/sizeof(char *))
char *conn_drop_reasons[] = {
	"--",
	"user reset",
	"invalid connection state",
	"failure to move to DOWN state",
	"connection destroy",
	"conn_connect failure",
	"hb timeout",
	"reconnect timeout",
	"cancel operation on socket",
	"race between ESTABLISHED event and drop",
	"conn is not in CONNECTING state",
	"qp event",
	"incoming REQ in CONN_UP state",
	"incoming REQ in CONNECTING state",
	"passive setup_qp failure",
	"rdma_accept failure",
	"active setup_qp failure",
	"rdma_connect failure",
	"resolve_route failure",
	"detected rdma_cm_id mismatch",
	"ROUTE_ERROR event",
	"ADDR_ERROR event",
	"CONNECT_ERROR or UNREACHABLE or DEVICE_REMOVE event",
	"CONSUMER_DEFINED reject",
	"REJECTED event",
	"ADDR_CHANGE event",
	"DISCONNECTED event",
	"TIMEWAIT_EXIT event",
	"post_recv failure",
	"send_ack failure",
	"no header in incoming msg",
	"corrupted header in incoming msg",
	"fragment header mismatch",
	"recv completion error",
	"send completion error",
	"post_send failure",
	"rds_rdma module unload",
	"active bonding failover",
	"corresponding loopback conn drop",
	"active bonding failback",
	"sk_state to TCP_CLOSE",
	"tcp_send failure",
};

static void print_paths(void *data, int each, socklen_t len, void *extra,
			bool prt_ipv6)
{
	struct rds_info_connection_paths *rds_cinfo;
	int prt_width;
	struct rds_path_info *pinfo;

	printf("\nRDS Paths:\n");
	if (prt_ipv6)
		prt_width = PRT_IPV6_WIDTH;
	else
		prt_width = PRT_IPV4_WIDTH;
	while (len) {
		int i = 0;

		rds_cinfo = (struct rds_info_connection_paths *)data;
		len -= each;
		data += each;
		printf("\t%*s %*s %4s %7s\n", prt_width, "LocalAddr",
		       prt_width, "RemoteAddr", "Tos", "Trans");
		printf("\t%*s %*s %4u %7s\n",
			prt_width, ipaddr(&rds_cinfo->local_addr, 1),
			prt_width, ipaddr(&rds_cinfo->peer_addr, 1),
			rds_cinfo->tos,
			rds_cinfo->transport);
		printf("\n%-4s %-24s %-24s %-24s %-10s %-6s %-11s %-s\n",
		       "P", "Connected@", "Attempt@",
		       "Reset@", "Attempts", "RDS", "Down(Secs)", "Reason");
		pinfo = (struct rds_path_info *) (rds_cinfo + 1);
		do {
			printf("%-4d ", pinfo->index);
			print_time(&pinfo->connect_time);
			print_time(&pinfo->attempt_time);
			print_time(&pinfo->reset_time);
			printf("%-10d ", pinfo->connect_attempts);
			printf("%c%c%c%c   ",
			rds_conn_flag(pinfo->flags, SENDING,
				      rds_cinfo->transport, 's'),
			rds_conn_flag(pinfo->flags, CONNECTING,
				      rds_cinfo->transport, 'c'),
			rds_conn_flag(pinfo->flags, CONNECTED,
				      rds_cinfo->transport, 'C'),
			rds_conn_flag(pinfo->flags, ERROR,
				      rds_cinfo->transport, 'E'));
			if ((pinfo->flags & RDS_INFO_CONNECTION_FLAG_CONNECTED) &&
			    pinfo->reset_time != 0) {
				printf("%-11ld ",
				       pinfo->connect_time - pinfo->reset_time);
			} else {
				printf("%-11s ", "---");
			}
			if (pinfo->disconnect_reason > MAC_DISCON_REASON)
				printf("%15d\n", pinfo->disconnect_reason);
			else
				printf("%-s\n",
				       conn_drop_reasons[pinfo->disconnect_reason]);
			pinfo++;
		} while (++i < rds_cinfo->npaths);
		if (len)
			printf("\n");
	}
}

static void print_conns(void *data, int each, socklen_t len, void *extra,
			bool prt_ipv6)
{
	struct rds6_info_connection conn6;
	struct rds_info_connection conn;
	int prt_width;

	if (prt_ipv6)
		prt_width = PRT_IPV6_WIDTH;
	else
		prt_width = PRT_IPV4_WIDTH;

	printf("\nRDS Connections:\n%*s %*s %4s %16s %16s %4s\n",
	       prt_width, "LocalAddr", prt_width, "RemoteAddr", "Tos",
	       "NextTX", "NextRX", "Flgs");

	if (prt_ipv6) {
		for_each(conn6, data, each, len) {
			printf("%*s %*s %4u %16"PRIu64" %16"PRIu64" %c%c%c%c\n",
			       prt_width, ipaddr(&conn6.laddr, prt_ipv6),
			       prt_width, ipaddr(&conn6.faddr, prt_ipv6),
			       conn6.tos,
			       (uint64_t) conn6.next_tx_seq,
			       (uint64_t) conn6.next_rx_seq,
			       rds_conn_flag(conn6.flags, SENDING,
					     conn6.transport, 's'),
			       rds_conn_flag(conn6.flags, CONNECTING,
					     conn6.transport, 'c'),
			       rds_conn_flag(conn6.flags, CONNECTED,
					     conn6.transport, 'C'),
			       rds_conn_flag(conn6.flags, ERROR,
					     conn6.transport, 'E'));
		}
	} else {
		for_each(conn, data, each, len) {
			printf("%*s %*s %4u %16"PRIu64" %16"PRIu64" %c%c%c%c\n",
			       prt_width, ipaddr(&conn.laddr, prt_ipv6),
			       prt_width, ipaddr(&conn.faddr, prt_ipv6),
			       conn.tos,
			       (uint64_t) conn.next_tx_seq,
			       (uint64_t) conn.next_rx_seq,
			       rds_conn_flag(conn.flags, SENDING,
					     conn.transport, 's'),
			       rds_conn_flag(conn.flags, CONNECTING,
					     conn.transport, 'c'),
			       rds_conn_flag(conn.flags, CONNECTED,
					     conn.transport, 'C'),
			       rds_conn_flag(conn.flags, ERROR,
					     conn.transport, 'E'));
		}
	}
}

static void print_msgs(void *data, int each, socklen_t len, void *extra,
		       bool prt_ipv6)
{
	struct rds6_info_message msg6;
	struct rds_info_message msg;
	int prt_width;

	if (prt_ipv6)
		prt_width = PRT_IPV6_WIDTH;
	else
		prt_width = PRT_IPV4_WIDTH;

	printf("\n%s Message Queue:\n%*s %5s %*s %5s %4s %16s %10s\n",
	       (char *)extra,
	       prt_width, "LocalAddr", "LPort", prt_width, "RemoteAddr",
	       "RPort", "Tos", "Seq", "Bytes");

	if (prt_ipv6) {
		for_each(msg6, data, each, len) {
			printf("%*s %5u %*s %5u %4u %16"PRIu64" %10u\n",
			       prt_width, ipaddr(&msg6.laddr, prt_ipv6),
			       ntohs(msg6.lport),
			       prt_width, ipaddr(&msg6.faddr, prt_ipv6),
			       ntohs(msg6.fport),
			       msg6.tos,
			       (uint64_t) msg6.seq, msg6.len);
		}
	} else {
		for_each(msg, data, each, len) {
			printf("%*s %5u %*s %5u %4u %16"PRIu64" %10u\n",
			       prt_width, ipaddr(&msg.laddr, prt_ipv6),
			       ntohs(msg.lport),
			       prt_width, ipaddr(&msg.faddr, prt_ipv6),
			       ntohs(msg.fport),
			       msg.tos,
			       (uint64_t) msg.seq, msg.len);
		}
	}
}

static void print_tcp_socks(void *data, int each, socklen_t len, void *extra,
			    bool prt_ipv6)
{		
	struct rds6_info_tcp_socket ts6;
	struct rds_info_tcp_socket ts;
	int prt_width;

	if (prt_ipv6)
		prt_width = PRT_IPV6_WIDTH;
	else
		prt_width = PRT_IPV4_WIDTH;

	printf("\nTCP Connections:\n"
	       "%*s %5s %*s %5s %10s %10s %10s %10s %10s\n",
	       prt_width, "LocalAddr", "LPort", prt_width, "RemoteAddr",
	       "RPort", "HdrRemain", "DataRemain", "SentNxt", "ExpectUna",
	       "SeenUna");

	if (prt_ipv6) {
		for_each(ts6, data, each, len) {
			printf("%*s %5u %*s %5u %10"PRIu64" %10"PRIu64" %10u %10u %10u\n",
			       prt_width, ipaddr(&ts6.local_addr, prt_ipv6),
			       ntohs(ts6.local_port),
			       prt_width, ipaddr(&ts6.peer_addr, prt_ipv6),
			       ntohs(ts6.peer_port),
			       (uint64_t) ts6.hdr_rem, (uint64_t) ts6.data_rem, ts6.last_sent_nxt,
			       ts6.last_expected_una, ts6.last_seen_una);
		}
	} else {
		for_each(ts, data, each, len) {
			printf("%*s %5u %*s %5u %10"PRIu64" %10"PRIu64" %10u %10u %10u\n",
			       prt_width, ipaddr(&ts.local_addr, prt_ipv6),
			       ntohs(ts.local_port),
			       prt_width, ipaddr(&ts.peer_addr, prt_ipv6),
			       ntohs(ts.peer_port),
			       (uint64_t) ts.hdr_rem, (uint64_t) ts.data_rem, ts.last_sent_nxt,
			       ts.last_expected_una, ts.last_seen_una);
		}
	}
}

static void print_ib_conns(void *data, int each, socklen_t len, void *extra,
			   bool prt_ipv6)
{
	struct rds6_info_rdma_connection ic6;
	struct rds_info_rdma_connection ic;
	int prt_width;

	if (prt_ipv6)
		prt_width = PRT_IPV6_WIDTH;
	else
		prt_width = PRT_IPV4_WIDTH;

	if (opt_verbose && (!opt_add)) {
		memset(add_fields, 0, ADD_FIELD_STR_LEN);
		strcat(add_fields, "cache_allocs");
		strcat(add_fields, ", recv_alloc_ctr");
		strcat(add_fields, ", recv_free_ctr");
		strcat(add_fields, ", send_alloc_ctr");
		strcat(add_fields, ", send_free_ctr");
		strcat(add_fields, ", send_bytes");
		strcat(add_fields, ", recv_bytes");
		strcat(add_fields, ", r_read_bytes");
		strcat(add_fields, ", r_write_bytes");
		strcat(add_fields, ", tx_poll_ts");
		strcat(add_fields, ", rx_poll_ts");
		strcat(add_fields, ", tx_poll_cnt");
		strcat(add_fields, ", rx_poll_cnt");
		strcat(add_fields, ", scq_vector");
		strcat(add_fields, ", rcq_vector");
	}

	printf("\nRDS IB Connections:\n%*s %*s %4s %3s %32s %32s %10s %10s",
	       prt_width, "LocalAddr", prt_width, "RemoteAddr", "Tos", "SL",
	       "LocalDev", "RemoteDev", "SrcQPNo", "DstQPNo");

	if (opt_add || opt_verbose) {
		if (strcasestr(add_fields, "cache_allocs"))
			printf("%15s", "Cache Allocs");
		if (strcasestr(add_fields, "recv_alloc_ctr"))
			printf("%15s", "Recv_alloc_ctr");
		if (strcasestr(add_fields, "recv_free_ctr"))
			printf("%15s", "Recv_free_ctr");
		if (strcasestr(add_fields, "send_alloc_ctr"))
			printf("%15s", "Send_alloc_ctr");
		if (strcasestr(add_fields, "send_free_ctr"))
			printf("%15s", "Send_free_ctr");
		if (strcasestr(add_fields, "send_bytes"))
			printf("%16s", "Send_bytes KiB");
		if (strcasestr(add_fields, "recv_bytes"))
			printf("%16s", "Recv_bytes KiB");
		if (strcasestr(add_fields, "r_read_bytes"))
			printf("%19s", "R_read_bytes KiB");
		if (strcasestr(add_fields, "r_write_bytes"))
			printf("%19s", "R_write_bytes KiB");
		if (strcasestr(add_fields, "tx_poll_ts"))
			printf("%15s", "Tx_poll_ts_ms");
		if (strcasestr(add_fields, "rx_poll_ts"))
			printf("%15s", "Rx_poll_ts_ms");
		if (strcasestr(add_fields, "tx_poll_cnt"))
			printf("%15s", "Tx_poll_cnt");
		if (strcasestr(add_fields, "rx_poll_cnt"))
			printf("%15s", "Rx_poll_cnt");
		if (strcasestr(add_fields, "scq_vector"))
			printf("%15s", "Scq_vector");
		if (strcasestr(add_fields, "rcq_vector"))
			printf("%15s", "Rcq_vector");
	}

	printf("\n");

	if (prt_ipv6) {
		for_each(ic6, data, each, len) {
			printf("%*s %*s %4u %3u %32s %32s %10d %10d",
			       prt_width, ipaddr(&ic6.src_addr, prt_ipv6),
			       prt_width, ipaddr(&ic6.dst_addr, prt_ipv6),
			       ic6.tos, ic6.sl,
			       ipv6addr(ic6.src_gid),
			       ipv6addr(ic6.dst_gid),
			       ic6.qp_num,
			       ic6.dst_qp_num);

			if (opt_add || opt_verbose) {
				if (strcasestr(add_fields, "cache_allocs"))
					printf("%15"PRIu32, ic6.cache_allocs);
				if (strcasestr(add_fields, "recv_alloc_ctr"))
					printf("%15"PRIu32, ic6.recv_alloc_ctr);
				if (strcasestr(add_fields, "recv_free_ctr"))
					printf("%15"PRIu32, ic6.recv_free_ctr);
				if (strcasestr(add_fields, "send_alloc_ctr"))
					printf("%15"PRIu32, ic6.send_alloc_ctr);
				if (strcasestr(add_fields, "send_free_ctr"))
					printf("%15"PRIu32, ic6.send_free_ctr);
				if (strcasestr(add_fields, "send_bytes"))
					printf("%16.2f", kB(ic6.send_bytes));
				if (strcasestr(add_fields, "recv_bytes"))
					printf("%16.2f", kB(ic6.recv_bytes));
				if (strcasestr(add_fields, "r_read_bytes"))
					printf("%19.2f", kB(ic6.r_read_bytes));
				if (strcasestr(add_fields, "r_write_bytes"))
					printf("%19.2f", kB(ic6.r_write_bytes));
				if (strcasestr(add_fields, "tx_poll_ts"))
					printf("%15"PRIu64, (uint64_t) ic6.tx_poll_ts);
				if (strcasestr(add_fields, "rx_poll_ts"))
					printf("%15"PRIu64, (uint64_t) ic6.rx_poll_ts);
				if (strcasestr(add_fields, "tx_poll_cnt"))
					printf("%15"PRIu64, (uint64_t) ic6.tx_poll_cnt);
				if (strcasestr(add_fields, "rx_poll_cnt"))
					printf("%15"PRIu64, (uint64_t) ic6.rx_poll_cnt);
				if (strcasestr(add_fields, "scq_vector"))
					printf("%15"PRId32, ic6.scq_vector);
				if (strcasestr(add_fields, "rcq_vector"))
					printf("%15"PRId32, ic6.rcq_vector);
			}

			printf("\n");
		}
	} else {
		for_each(ic, data, each, len) {
			printf("%*s %*s %4u %3u %32s %32s %10d %10d",
			       prt_width, ipaddr(&ic.src_addr, prt_ipv6),
			       prt_width, ipaddr(&ic.dst_addr, prt_ipv6),
			       ic.tos, ic.sl,
			       ipv6addr(ic.src_gid),
			       ipv6addr(ic.dst_gid),
			       ic.qp_num,
			       ic.dst_qp_num);

			if (opt_add || opt_verbose) {
				if (strcasestr(add_fields, "cache_allocs"))
					printf("%15"PRIu32, ic.cache_allocs);
				if (strcasestr(add_fields, "recv_alloc_ctr"))
					printf("%15"PRIu32, ic.recv_alloc_ctr);
				if (strcasestr(add_fields, "recv_free_ctr"))
					printf("%15"PRIu32, ic.recv_free_ctr);
				if (strcasestr(add_fields, "send_alloc_ctr"))
					printf("%15"PRIu32, ic.send_alloc_ctr);
				if (strcasestr(add_fields, "send_free_ctr"))
					printf("%15"PRIu32, ic.send_free_ctr);
				if (strcasestr(add_fields, "send_bytes"))
					printf("%16.2f", kB(ic.send_bytes));
				if (strcasestr(add_fields, "recv_bytes"))
					printf("%16.2f", kB(ic.recv_bytes));
				if (strcasestr(add_fields, "r_read_bytes"))
					printf("%19.2f", kB(ic.r_read_bytes));
				if (strcasestr(add_fields, "r_write_bytes"))
					printf("%19.2f", kB(ic.r_write_bytes));
				if (strcasestr(add_fields, "tx_poll_ts"))
					printf("%15"PRIu64, (uint64_t)ic.tx_poll_ts);
				if (strcasestr(add_fields, "rx_poll_ts"))
					printf("%15"PRIu64, (uint64_t) ic.rx_poll_ts);
				if (strcasestr(add_fields, "tx_poll_cnt"))
					printf("%15"PRIu64, (uint64_t) ic.tx_poll_cnt);
				if (strcasestr(add_fields, "rx_poll_cnt"))
					printf("%15"PRIu64, (uint64_t)ic.rx_poll_cnt);
				if (strcasestr(add_fields, "scq_vector"))
					printf("%15"PRId32, ic.scq_vector);
				if (strcasestr(add_fields, "rcq_vector"))
					printf("%15"PRId32, ic.rcq_vector);
			}

			printf("\n");
		}
	}
}

/*
 * opt_val_v6 constains the preferred socket option (IPv6) to use.  opt_val_v4
 * constains the secondary socket option (IPv4) in case the kernel does not
 * support IPv6.
 */
struct info {
	int opt_val_v6;
	int opt_val_v4;
	char *description;
	void (*print)(void *data, int each, socklen_t len, void *extra,
		      bool prt_ipv6);
	void *extra;
	int option_given;
};

struct info infos[] = {
	['c'] = { RDS_INFO_COUNTERS, RDS_INFO_COUNTERS, "statistic counters",
		print_counters, NULL, 0 },
	['k'] = { RDS6_INFO_SOCKETS, RDS_INFO_SOCKETS, "sockets",
		print_sockets, NULL, 0 },
	['n'] = { RDS6_INFO_CONNECTIONS, RDS_INFO_CONNECTIONS, "connections",
		print_conns, NULL, 0 },
	['p'] = { RDS6_INFO_CONN_PATHS, RDS_INFO_CONN_PATHS, "paths",
		print_paths, NULL, 0 },
	['r'] = { RDS6_INFO_RECV_MESSAGES, RDS_INFO_RECV_MESSAGES,
		"recv queue messages", print_msgs, "Receive", 0 },
	['s'] = { RDS6_INFO_SEND_MESSAGES, RDS_INFO_SEND_MESSAGES,
		"send queue messages", print_msgs, "Send", 0 },
	['t'] = { RDS6_INFO_RETRANS_MESSAGES, RDS_INFO_RETRANS_MESSAGES,
		"retransmit queue messages", print_msgs, "Retransmit", 0 },
	['T'] = { RDS6_INFO_TCP_SOCKETS, RDS_INFO_TCP_SOCKETS,
		"TCP transport sockets", print_tcp_socks, NULL, 0 },
	['I'] = { RDS6_INFO_IB_CONNECTIONS, RDS_INFO_IB_CONNECTIONS,
		"IB transport connections", print_ib_conns, NULL, 0 },
};

static void print_usage(int rc)
{
	FILE *output = rc ? stderr : stdout;
	int i;

	fprintf(stderr, "rds-info version %s\n", RDS_VERSION);

	verbosef(0, output, "The following options limit output to the given "
		 "sources:\n");

	printf("    -a include both IPv6 and IPv4 RDS connections\n");
	for (i = 0; i < array_size(infos); i++) {
		if (!infos[i].opt_val_v6)
			continue;
		printf("    -%c %s\n", i, infos[i].description);
	}

	verbosef(0, output,
		"\n\nIf no options are given then all sources are used.\n");
	exit(rc);
}

int main(int argc, char **argv)
{
	char optstring[258] = "ao:v+";
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
	bool v4andv6;

	/* Default is to print out IPv4 RDS connection info only. */
	v4andv6 = false;

	/* quickly append all our info options to the optstring */
	last = &optstring[strlen(optstring)];
	for (i = 0; i < array_size(infos); i++) {
		if (!infos[i].opt_val_v6)
			continue;
		*last = (char)i;
		last++;
		*last = '\0';
	}

	while ((c = getopt(argc, argv, optstring)) != EOF) {
		switch (c) {
		case 'o':
			strncpy(add_fields, optarg, (ADD_FIELD_STR_LEN - 1));
			opt_add++;
			continue;
		case 'v':
			opt_verbose++;
			continue;
		case 'a':
			v4andv6 = true;
			continue;
		}

		if (c >= array_size(infos) || !infos[c].opt_val_v6) {
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
		int opt_val;
		bool prt_ipv6;

		if (v4andv6) {
			opt_val = infos[i].opt_val_v6;
			prt_ipv6 = true;
		} else {
			opt_val = infos[i].opt_val_v4;
			prt_ipv6 = false;
		}

		if (!opt_val || (given_options && !infos[i].option_given))
			continue;

		/* read in the info until we get a full snapshot */
		while ((each = getsockopt(fd, sol, opt_val, data, &len)) < 0) {
			/* If -a option is specified but kernel does not
			 * support IPv6 option, switch to IPv4 only mode.
			 * But note that this error can also happen if
			 * rds_tcp/rds_rdma module info is requested but the
			 * rds_tcp/rds_rdma module is not loaded.  So switch
			 * temporarily only for this option by setting
			 * prt_ipv6 to false.
			 */
			if (errno == ENOPROTOOPT && prt_ipv6) {
				opt_val = infos[i].opt_val_v4;
				prt_ipv6 = false;
				continue;
			}

			if (errno != ENOSPC) {
				verbosef(0, stderr,
					 "%s: Unable to get statistics to process the \"%s\" info request: %s\n",
					 progname, infos[i].description, strerror(errno));
				invalid_opt = 1;
				break;
			}
			if (data)
				data = realloc(data, len);
			else
				data = malloc(len);

			if (data == NULL) {
				verbosef(0, stderr,
					 "%s: Unable to allocate %u bytes of memory "
					 "to process the \"%s\" info request: %s\n",
					 progname, len, infos[i].description,
					 strerror(errno));
				return 1;
			}
		}

		if (invalid_opt)
			continue;

		infos[i].print(data, each, len, infos[i].extra, prt_ipv6);

		if (given_options && --given_options == 0)
			break;
	}

	return 0;
}
