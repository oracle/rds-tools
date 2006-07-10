/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * rds-gen.c: Spew some RDS packets
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

#include "rdstool.h"

#define ARRAY_LEN(foo) (sizeof(foo) / sizeof(foo[0]))

/* 
 * parse_options() wants these linked in.
 */
void print_usage(int unused)
{
}
void print_version()
{
}

/*
 * :%s/^.*unsigned long.*\(s_[a-z_]*\);/^I"\1",/
 */
static char *names[] = {
	"s_ack_entry_hit",
	"s_ack_entry_miss",
	"s_ack_message_full",
	"s_ack_message_fast",
	"s_ack_message_deadline",
	"s_ack_message_received",
	"s_ack_alloc_fail",
	"s_conn_reset",
	"s_recv_drop_old_seq",
	"s_recv_drop_no_sock",
	"s_recv_drop_dead_sock",
	"s_recv_deliver_raced",
	"s_recv_delivered",
	"s_recv_queued",
	"s_send_queue_full",
};

int main(int argc, char **argv)
{
	int rc, fd, status = 1;
	socklen_t optlen;
	uint64_t vals[ARRAY_LEN(names)];
	size_t i;

	fd = socket(PF_RDS, SOCK_SEQPACKET, 0);
	if (fd < 0) {
		rc = -errno;
		verbosef(0, stderr, "%s: Unable to create socket: %s\n",
			 progname, strerror(-rc));
		goto out;
	}

	optlen = sizeof(vals);
	rc = getsockopt(fd, SOL_RDS, RDS_STATS_GLOBAL, &vals, &optlen);
	if (rc) {
		rc = -errno;
		verbosef(0, stderr, "%s: Unable get statistics: %s\n",
			 progname, strerror(-rc));
		goto out;
	}

	for (i = 0; i < optlen / sizeof(uint64_t); i++)
		printf("%-25s: %"PRIu64"\n", names[i], vals[i]);

	status = 0;

out:
	return status;
}
