/*
 * rds-ping utility
 *
 * Test reachability of a remote RDS node by sending a packet to port 0.
 *
 * Copyright (C) 2008 Oracle.  All rights reserved.
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
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include "rds.h"

#include "pfhack.h"

#define die(fmt...) do {		\
	fprintf(stderr, fmt);		\
	exit(1);			\
} while (0)

#define die_errno(fmt, args...) do {				\
	fprintf(stderr, fmt ", errno: %d (%s)\n", ##args , errno,\
		strerror(errno));				\
	exit(1);						\
} while (0)

static struct timeval	opt_wait = { 1, 1 };		/* 1s */
static unsigned long	opt_count;
static struct in_addr	opt_srcaddr;
static struct in_addr	opt_dstaddr;
static unsigned long	opt_tos = 0;

/* For reasons of simplicity, RDS ping does not use a packet
 * payload that is being echoed, the way ICMP does.
 * Instead, we open a number of sockets on different ports, and
 * match packet sequence numbers with ports.
 */
#define NSOCKETS	8	

struct socket {
	int fd;
	unsigned int sent_id;
	struct timeval sent_ts;
	unsigned int nreplies;
};


static int	do_ping(void);
static void	report_packet(struct socket *sp, const struct timeval *now,
			const struct in_addr *from, int err);
static void	usage(const char *complaint);
static int	rds_socket(struct in_addr *src, struct in_addr *dst);
static int	parse_timeval(const char *, struct timeval *);
static int	parse_long(const char *ptr, unsigned long *);
static int	parse_addr(const char *ptr, struct in_addr *);

int
main(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "c:i:I:Q:")) != -1) {
		switch (c) {
		case 'c':
			if (!parse_long(optarg, &opt_count))
				die("Bad packet count <%s>\n", optarg);
			break;

		case 'I':
			if (!parse_addr(optarg, &opt_srcaddr))
				die("Unknown source address <%s>\n", optarg);
			break;

		case 'i':
			if (!parse_timeval(optarg, &opt_wait))
				die("Bad wait time <%s>\n", optarg);
			break;

		case 'Q':
			if (!parse_long(optarg, &opt_tos))
				die("Bad tos <%s>\n", optarg);
			break;
		default:
			usage("Unknown option");
		}
	}

	if (optind + 1 != argc)
		usage("Missing destination address");
	if (!parse_addr(argv[optind], &opt_dstaddr))
		die("Cannot parse destination address <%s>\n", argv[optind]);

	return do_ping();
}

/* returns a - b in usecs */
static inline long
usec_sub(const struct timeval *a, const struct timeval *b)
{
	return ((long)(a->tv_sec - b->tv_sec) * 1000000UL) + a->tv_usec - b->tv_usec;
}

static int
do_ping(void)
{
	struct sockaddr_in sin;
	unsigned int	sent = 0, recv = 0;
	struct timeval	next_ts;
	struct socket	socket[NSOCKETS];
	struct pollfd	pfd[NSOCKETS];
	int             pending[NSOCKETS];
	int		i, next = 0;

	for (i = 0; i < NSOCKETS; ++i) {
		int fd;

		fd = rds_socket(&opt_srcaddr, &opt_dstaddr);

		socket[i].fd = fd;
		pfd[i].fd = fd;
		pfd[i].events = POLLIN;
		pending[i] = 0;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr = opt_dstaddr;

	gettimeofday(&next_ts, NULL);
	while (1) {
		struct timeval	now;
		struct sockaddr_in from;
		socklen_t	alen = sizeof(from);
		long		deadline;
		int		ret;

		/* Fast way out - if we have received all packets, bail now.
		 * If we're still waiting for some to come back, we need
		 * to do the poll() below */
		if (opt_count && recv >= opt_count)
			break;

		gettimeofday(&now, NULL);
		if (timercmp(&now, &next_ts, >=)) {
			struct socket *sp = &socket[next];
			int err = 0;

			if (opt_count && sent >= opt_count)
				break;

			timeradd(&now, &opt_wait, &next_ts);
			if (!pending[next]) {
				memset(&sin, 0, sizeof(sin));
				sin.sin_family = AF_INET;
				sin.sin_addr = opt_dstaddr;

				if (sendto(sp->fd, NULL, 0, 0, (struct sockaddr *) &sin, sizeof(sin)))
					err = errno;
				sp->sent_id = ++sent;
				sp->sent_ts = now;
				sp->nreplies = 0;
				if (!err)
					pending[next] = 1;
				next = (next + 1) % NSOCKETS;
			}

			if (err) {
				static unsigned int nerrs = 0;

				report_packet(sp, NULL, NULL, err);
				if (err == EINVAL && nerrs++ == 0)
					printf("      Maybe your kernel does not support rds ping yet\n");
			}
		}

		deadline = usec_sub(&next_ts, &now);
		ret = poll(pfd, NSOCKETS, deadline / 1000);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			die_errno("poll");
		}
		if (ret == 0)
			continue;

		for (i = 0; i < NSOCKETS; ++i) {
			struct socket *sp = &socket[i];

			if (!(pfd[i].revents & POLLIN))
				continue;

			ret = recvfrom(sp->fd, NULL, 0, MSG_DONTWAIT,
					(struct sockaddr *) &from, &alen);
			gettimeofday(&now, NULL);

			if (ret < 0) {
				if (errno != EAGAIN &&
				    errno != EINTR)
					report_packet(sp, &now, NULL, errno);
			} else {
				report_packet(sp, &now, &from.sin_addr, 0);
				pending[i] = 0;
				recv++;
			}
		}
	}

	/* Program exit code: signal success if we received any response. */
	return recv == 0;
}

static void
report_packet(struct socket *sp, const struct timeval *now,
		const struct in_addr *from_addr, int err)
{
	printf(" %3u:", sp->sent_id);
	if (now)
		printf(" %ld usec", usec_sub(now, &sp->sent_ts));
	if (from_addr && from_addr->s_addr != opt_dstaddr.s_addr)
		printf(" (%s)", inet_ntoa(*from_addr));
	if (sp->nreplies)
		printf(" DUP!");
	if (err)
		printf(" ERROR: %s", strerror(err));
	printf("\n");

	sp->nreplies++;
}

static int
rds_socket(struct in_addr *src, struct in_addr *dst)
{
	struct sockaddr_in sin;
	int fd;
	int pf;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;

#ifdef DYNAMIC_PF_RDS
        pf = discover_pf_rds();
#else
        pf = PF_RDS;
#endif
	fd = socket(pf, SOCK_SEQPACKET, 0);
	if (fd < 0)
		die_errno("unable to create RDS socket");

	/* Guess the local source addr if not given. */
	if (src->s_addr == 0) {
		socklen_t alen;
		int ufd;

		ufd = socket(PF_INET, SOCK_DGRAM, 0);
		if (ufd < 0)
			die_errno("unable to create UDP socket");
		sin.sin_addr = *dst;
		sin.sin_port = htons(1);
		if (connect(ufd, (struct sockaddr *) &sin, sizeof(sin)) < 0)
			die_errno("unable to connect to %s",
					inet_ntoa(*dst));

		alen = sizeof(sin);
		if (getsockname(ufd, (struct sockaddr *) &sin, &alen) < 0)
			die_errno("getsockname failed");

		*src = sin.sin_addr;
		close(ufd);
	}

	sin.sin_addr = *src;
	sin.sin_port = 0;

	if (bind(fd, (struct sockaddr *) &sin, sizeof(sin)))
		die_errno("bind() failed");

	if (opt_tos && ioctl(fd, SIOCRDSSETTOS, &opt_tos)) 
		die_errno("ERROR: failed to set TOS\n");

	return fd;
}

static void
usage(const char *complaint)
{
        fprintf(stderr, "rds-ping version %s\n", RDS_VERSION);

	fprintf(stderr,
		"%s\nUsage: rds-ping [options] dst_addr\n"
		"Options:\n"
		" -c count      limit packet count\n"
		" -I interface  source IP address\n"
		" -Q tos	type of service\n",
		complaint);
	exit(1);
}

static int
parse_timeval(const char *ptr, struct timeval *ret)
{
	double	seconds;
	char *endptr;

	seconds = strtod(ptr, &endptr);
	if (!strcmp(endptr, "ms")
	 || !strcmp(endptr, "msec")) {
		seconds *= 1e-3;
	} else
	if (!strcmp(endptr, "us")
	 || !strcmp(endptr, "usec")) {
		seconds *= 1e-6;
	} else if (*endptr)
		return 0;

	ret->tv_sec = (long) seconds;
	seconds -= ret->tv_sec;

	ret->tv_usec = (long) (seconds * 1e6);
	return 1;
}

static int
parse_long(const char *ptr, unsigned long *ret)
{
	unsigned long long val;
	char *endptr;

	val = strtoull(ptr, &endptr, 0);
	switch (*endptr) {
	case 'k': case 'K':
		val <<= 10;
		endptr++;
		break;

	case 'm': case 'M':
		val <<= 20;
		endptr++;
		break;

	case 'g': case 'G':
		val <<= 30;
		endptr++;
		break;
	}

	if (*endptr)
		return 0;

	*ret = val;
	return 1;
}

static int
parse_addr(const char *ptr, struct in_addr *ret)
{
        struct hostent *hent;

        hent = gethostbyname(ptr);
        if (hent &&
            hent->h_addrtype == AF_INET && hent->h_length == sizeof(*ret)) {
		memcpy(ret, hent->h_addr, sizeof(*ret));
		return 1;
	}

	return 0;
}

