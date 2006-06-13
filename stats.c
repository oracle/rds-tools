/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * stats.c - Print stats at an interval
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "kernel-list.h"
#include "rdstool.h"
#include "stats.h"

static struct timeval next_print;
static int stats_delay = 0;  /* Delay in seconds */

struct rds_tool_stats {
	uint64_t rs_send;
	uint64_t rs_send_interval;
	uint64_t rs_recv;
	uint64_t rs_recv_interval;
	uint64_t rs_read;
	uint64_t rs_read_interval;
	uint64_t rs_write;
	uint64_t rs_write_interval;
} tool_stats;

#define inc_stat(type, val)  do { \
	tool_stats.rs_##type += val; \
	tool_stats.rs_##type##_interval += val; \
} while (0)

#define clear_interval() do { \
	tool_stats.rs_send_interval = 0; \
	tool_stats.rs_recv_interval = 0; \
	tool_stats.rs_read_interval = 0; \
	tool_stats.rs_write_interval = 0; \
} while (0)

void stats_add_read(uint64_t num)
{
	inc_stat(read, num);
}

void stats_add_write(uint64_t num)
{
	inc_stat(write, num);
}

void stats_add_send(uint64_t num)
{
	inc_stat(send, num);
}

uint64_t stats_get_send(void)
{
	return tool_stats.rs_send;
}

void stats_add_recv(uint64_t num)
{
	inc_stat(recv, num);
}

uint64_t stats_get_recv(void)
{
	return tool_stats.rs_recv;
}

void stats_init(int delay)
{
	stats_delay = delay;
	if (delay)
		verbosef(1, stderr,
			 "%19s %19s %19s %19s\n",
			 "Bytes sent/s", "Bytes recv/s",
			 "Bytes read/s", "Bytes written/s");
}

static void stats_output(struct timeval *now)
{
	if (timercmp(now, &next_print, <))
		return;

	verbosef(0, stderr,
		 "%19"PRIu64" %19"PRIu64" %19"PRIu64" %19"PRIu64"\n",
		 tool_stats.rs_send_interval / stats_delay,
		 tool_stats.rs_recv_interval / stats_delay,
		 tool_stats.rs_read_interval / stats_delay,
		 tool_stats.rs_write_interval / stats_delay);

	clear_interval();
	next_print = *now;
	next_print.tv_sec += stats_delay;
}

int stats_print(void)
{
	int rc = 0;
	struct timeval now;

	/* Are stats on? */
	if (!stats_delay)
		goto out;

	rc = gettimeofday(&now, NULL);
	if (rc) {
		rc = -errno;
		verbosef(0, stderr, "%s: Error in gettimeofday(): %s\n",
			 progname, strerror(-rc));
		goto out;
	}

	stats_output(&now);

out:
	return rc;
}

void stats_total(void)
{
	if (!stats_delay)
		return;

	verbosef(0, stderr,
		 "Total:\n"
		 "%19"PRIu64" %19"PRIu64" %19"PRIu64" %19"PRIu64"\n",
		 tool_stats.rs_send,
		 tool_stats.rs_recv,
		 tool_stats.rs_read,
		 tool_stats.rs_write);
}

int stats_sleep(int read_fd, int write_fd)
{
	int rc, sleep_fd;
	fd_set sleep_fds;
	fd_set *read_fds, *write_fds;
	struct timeval now, sleep;

	if ((read_fd > 0) && (write_fd > 0)) {
		verbosef(0, stderr, 
			 "%s: Called stats_sleep() with two fds!\n",
			 progname);
		return -EINVAL;
	}

	if (read_fd > 0) {
		read_fds = &sleep_fds;
		write_fds = NULL;
		sleep_fd = read_fd;
	} else {
		write_fds = &sleep_fds;
		read_fds = NULL;
		sleep_fd = write_fd;
	}

	FD_ZERO(&sleep_fds);

	while (1) {
		FD_SET(sleep_fd, &sleep_fds);
		rc = gettimeofday(&now, NULL);
		if (rc) {
			rc = -errno;
			verbosef(0, stderr,
				 "%s: Error in gettimeofday(): %s\n",
				 progname, strerror(-rc));
			break;
		}

		if (stats_delay)
			stats_output(&now);

		timersub(&next_print, &now, &sleep);
		rc = select(sleep_fd + 1, read_fds, write_fds, NULL,
			    stats_delay ? &sleep : NULL);

		if (rc < 0) {
			rc = -errno;
			if ((rc != -EAGAIN) && (rc != -EINTR)) {
				verbosef(0, stderr,
					 "%s: Error from select(): %s\n",
					 progname, strerror(-rc));
				break;
			}
			
			continue;
		}

		if (rc && FD_ISSET(sleep_fd, &sleep_fds))
			break;
	}

	return (rc < 0) ? rc : 0;
}

