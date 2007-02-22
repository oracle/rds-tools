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
 *
 * stats.c - Print stats at an interval
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "kernel-list.h"
#include "rdstool.h"

static int stats_delay = 0;  /* Delay in seconds */
static int print_extended = 0; /* Print read/write stats? */
static sig_atomic_t time_to_print = 0;

struct rds_tool_stats {
	uint64_t rs_send_bytes;
	uint64_t rs_send_bytes_interval;
	uint64_t rs_send_packets;
	uint64_t rs_send_packets_interval;
	uint64_t rs_recv_bytes;
	uint64_t rs_recv_bytes_interval;
	uint64_t rs_recv_packets;
	uint64_t rs_recv_packets_interval;
	uint64_t rs_read_bytes;
	uint64_t rs_read_bytes_interval;
	uint64_t rs_write_bytes;
	uint64_t rs_write_bytes_interval;
} tool_stats;

#define inc_net_stat(type, val)  do { \
	tool_stats.rs_##type##_bytes += val; \
	tool_stats.rs_##type##_bytes_interval += val; \
	tool_stats.rs_##type##_packets += 1; \
	tool_stats.rs_##type##_packets_interval += 1; \
} while (0)

#define inc_io_stat(type, val)  do { \
	tool_stats.rs_##type##_bytes += val; \
	tool_stats.rs_##type##_bytes_interval += val; \
} while (0)

#define clear_interval() do { \
	tool_stats.rs_send_bytes_interval = 0; \
	tool_stats.rs_recv_bytes_interval = 0; \
	tool_stats.rs_send_packets_interval = 0; \
	tool_stats.rs_recv_packets_interval = 0; \
	tool_stats.rs_read_bytes_interval = 0; \
	tool_stats.rs_write_bytes_interval = 0; \
} while (0)

static void handler(int signum)
{
	time_to_print = 1;
}

static int setup_alarm(void)
{
	int rc = 0;
	struct sigaction act;

	sigemptyset(&act.sa_mask);
	act.sa_handler = handler;
	act.sa_flags = 0;

	rc = sigaction(SIGALRM, &act, NULL);
	if (rc) {
		rc = -errno;
		verbosef(0, stderr,
			 "%s: Unable to initialize timer: %s\n",
			 progname, strerror(-rc));
	}
	
	return rc;
}

void stats_add_read(uint64_t bytes)
{
	inc_io_stat(read, bytes);
}

void stats_add_write(uint64_t bytes)
{
	inc_io_stat(write, bytes);
}

void stats_add_send(uint64_t bytes)
{
	inc_net_stat(send, bytes);
}

uint64_t stats_get_send(void)
{
	return tool_stats.rs_send_bytes;
}

void stats_add_recv(uint64_t bytes)
{
	inc_net_stat(recv, bytes);
}

static void stats_arm(void)
{
	time_to_print = 0;
	alarm(stats_delay);
}

int stats_init(int delay)
{
	int rc = 0;

	stats_delay = delay;
	if (stats_delay)
		rc = setup_alarm();

	return rc;
}

void stats_extended(int extendedp)
{
	print_extended = !!extendedp;
}

void stats_start(void)
{
	if (stats_delay) {
		verbosef(1, stderr,
			 "%19s %19s %19s %19s\n",
			 "Bytes sent/s", "Packets sent/s",
			 "Bytes recv/s", "Packets recv/s");
		if (print_extended)
			verbosef(1, stderr, " %19s %19s",
				 "Bytes read/s", "Bytes written/s");
		verbosef(1, stderr, "\n");

		stats_arm();
	}
}

static void stats_output(void)
{
	verbosef(0, stderr,
		 "%19"PRIu64" %19"PRIu64" %19"PRIu64" %19"PRIu64,
		 tool_stats.rs_send_bytes_interval / stats_delay,
		 tool_stats.rs_send_packets_interval / stats_delay,
		 tool_stats.rs_recv_bytes_interval / stats_delay,
		 tool_stats.rs_recv_packets_interval / stats_delay);
	if (print_extended)
		verbosef(0, stderr, " %19"PRIu64" %19"PRIu64,
			 tool_stats.rs_read_bytes_interval / stats_delay,
			 tool_stats.rs_write_bytes_interval / stats_delay);
	verbosef(0, stderr, "\n");
}

void stats_print(void)
{
	/* Are stats on? */
	if (stats_delay && time_to_print) {
		stats_output();
		clear_interval();
		stats_arm();
	}
}

void stats_total(void)
{
	if (!stats_delay)
		return;

	verbosef(0, stderr,
		 "Total:\n"
		 "%19"PRIu64" %19"PRIu64" %19"PRIu64" %19"PRIu64,
		 tool_stats.rs_send_bytes,
		 tool_stats.rs_send_packets,
		 tool_stats.rs_recv_bytes,
		 tool_stats.rs_recv_packets);
	if (print_extended)
		verbosef(0, stderr, " %19"PRIu64" %19"PRIu64,
			 tool_stats.rs_read_bytes,
			 tool_stats.rs_write_bytes);

	verbosef(0, stderr, "\n");
}

