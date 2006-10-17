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
		 "	-c	connections\n"
		 "	-s	global statistic counters\n",
		 progname);

	exit(rc);
}
void print_version()
{
}

struct rds_info_counter {
	uint8_t		name[32];
	uint64_t	value;
};

#define RDS_INFO_CONNECTION_FLAG_SEND_PENDING           0x01
#define RDS_INFO_CONNECTION_FLAG_RETRANS_PENDING        0x02
#define RDS_INFO_CONNECTION_FLAG_ACK_GENERATION_PENDING 0x04
#define RDS_INFO_CONNECTION_FLAG_ACK_MSG_PENDING        0x08
#define RDS_INFO_CONNECTION_FLAG_CONNECTED              0x10
#define RDS_INFO_CONNECTION_FLAG_CONNECTING             0x20

struct rds_info_connection {
        uint64_t	next_tx_seq;
        uint64_t	next_rx_seq;
	uint32_t	laddr;
	uint32_t	faddr;
        uint8_t		transport[15];           /* null term ascii */
        uint8_t		flags;
};

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

	while ((c = getopt(argc, argv, "+cs")) != EOF) {
		switch (c) {
			case 'c':
				info = RDS_INFO_CONNECTIONS;
				break;
			case 's':
				info = RDS_INFO_COUNTERS;
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
			printf("%c%c%c%c%c%c\n",
			      rds_conn_flag(conn, SEND_PENDING, 's'),
			      rds_conn_flag(conn, RETRANS_PENDING, 'r'),
			      rds_conn_flag(conn, ACK_GENERATION_PENDING, 'a'),
			      rds_conn_flag(conn, ACK_MSG_PENDING, 'A'),
			      rds_conn_flag(conn, CONNECTING, 'c'),
			      rds_conn_flag(conn, CONNECTED, 'C'));
		}
		break;
	}
	}

	status = 0;

out:
	return status;
}
