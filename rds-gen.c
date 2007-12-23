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
 * rds-gen.c: Spew some RDS packets
 */

#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "kernel-list.h"
#include "rdstool.h"

void print_usage(int rc)
{
	int namelen = strlen(progname);
	FILE *output = rc ? stderr : stdout;

	verbosef(0, output,
		 "Usage: %s -s <source_ip>:<source_port> [[-d <dest_ip>:<dest_port>] ...]\n"
		 "       %*s [-f <input_file>] [-m <msg_size>]\n"
		 "       %*s [-l <total_bytes>] [-i <interval>]\n"
		 "       %*s [-v ...] [-q ...]\n"
		 "       %s -h\n"
		 "       %s -V\n",
		 progname, namelen, "", namelen, "", namelen, "", progname,
		 progname);

	exit(rc);
}

void print_version()
{
	verbosef(0, stdout, "%s version VERSION\n", progname);

	exit(0);
}

/*
 * Pick the next destination.
 * Currently round-robin, but could be made fancy
 */
static struct rds_endpoint *pick_dest(struct rds_context *ctxt,
				      struct rds_endpoint *de)
{
	struct list_head *next;

	if (!de || (de->re_item.next == &ctxt->rc_daddrs))
		next = ctxt->rc_daddrs.next;
	else
		next = de->re_item.next;

	return list_entry(next, struct rds_endpoint, re_item);
}

static ssize_t fill_stdin(struct rds_context *ctxt, char *bytes,
			  ssize_t len)
{
	ssize_t ret = 0;
	char *ptr = bytes;

	static int first = 1;

	if (!first)
		return ret;

	if (ctxt->rc_filename && strcmp(ctxt->rc_filename,"-"))
		first = 0;

	while (len && runningp()) {
		stats_print();
		ret = read(STDIN_FILENO, ptr, len);
		if (!ret) {
			if (ptr != bytes) {
				verbosef(0, stderr,
					 "%s: Unexpected end of file reading from %s\n",
					 progname, ctxt->rc_filename);
				ret = -EPIPE;
			}
			break;
		}
		if (ret < 0) {
			ret = -errno;
			if (ret == -EINTR)
				continue;

			verbosef(0, stderr,
				 "%s: Error reading from %s: %s\n",
				 progname, ctxt->rc_filename,
				 strerror(-ret));
			break;
		}

		stats_add_read(ret);
		ptr += ret;
		len -= ret;
		ret = 0;  /* If this filled the buffer, we return success */
	}
	verbosef(3, stderr, "Read %zd bytes from stdin\n",
		 ptr - bytes);
	
	return ret;
}

static ssize_t fill_pattern(struct rds_context *ctxt, char *bytes,
			    ssize_t len)
{
	static int first = 1;

	stats_print();

	if (first) {
		memset(bytes, 0, len);
		first = 0;
	}

	return 0;
}

static ssize_t fill_buff(struct rds_context *ctxt, char *bytes, ssize_t len)
{
	ssize_t ret;

	/* Each possible method must handle calling stats_print() */
	if (ctxt->rc_filename)
		ret = fill_stdin(ctxt, bytes, len);
	else
		ret = fill_pattern(ctxt, bytes, len);

	return ret;
}

static ssize_t send_buff(struct rds_endpoint *se, struct msghdr *msg)
{
	ssize_t ret = 0;

	while (runningp()) {
		stats_print();

		ret = sendmsg(se->re_fd, msg, 0);
		if (ret < 0) {
			ret = -errno;
			if (ret == -EINTR)
				continue;

			verbosef(0, stderr,
				 "%s: Error from sendmsg: %s\n",
				 progname, strerror(-ret));
		}

		/* Success */
		break;
	}

	return ret;
}


static int wli_do_send(struct rds_context *ctxt)
{
	char bytes[ctxt->rc_msgsize];
	int ret = 0;
	struct rds_endpoint *de = NULL, *se = ctxt->rc_saddr;
	struct iovec iov = {
		.iov_base = bytes,
		.iov_len = ctxt->rc_msgsize,
	};
	struct msghdr msg = {
		.msg_name = NULL,  /* Picked later */
		.msg_namelen = sizeof(struct sockaddr_in),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};

	verbosef(2, stderr, "Starting send loop\n");

	stats_start();

	while (runningp()) {
		/* Calls stats_print() */
		ret = fill_buff(ctxt, bytes, ctxt->rc_msgsize);
		if (ret) {
			if (ret == -EINTR)
				continue;
			else
				break;
		}

		de = pick_dest(ctxt, de);
		verbosef(2, stderr, "Destination %s\n", de->re_name);

		msg.msg_name = &de->re_addr;
		if (ctxt->rc_total &&
		    ((stats_get_send() + ctxt->rc_msgsize) > ctxt->rc_total))
			iov.iov_len = ctxt->rc_total - stats_get_send();

		/* Calls stats_print() */
		ret = send_buff(se, &msg);
		if (ret < 0)
			break;

		stats_add_send(ret);

		if (ctxt->rc_total && (stats_get_send() >= ctxt->rc_total))
			break;
	}
	verbosef(2, stderr, "Stopping send loop\n");

	stats_total();

	return ret;
}


int main(int argc, char *argv[])
{
	int rc;
	char ipbuf[INET_ADDRSTRLEN];
	struct rds_endpoint *e;
	struct rds_context ctxt = {
		.rc_msgsize = RDS_DEFAULT_MSG_SIZE,
	};

	INIT_LIST_HEAD(&ctxt.rc_daddrs);

	rc = parse_options(argc, argv, RDS_TOOL_BASE_OPTS RDS_GEN_OPTS,
			   &ctxt);
	if (rc)
		print_usage(rc);

	if (list_empty(&ctxt.rc_daddrs)) {
		verbosef(0, stderr,
			 "%s: Destination endpoint address required\n",
			 progname);
		print_usage(-EINVAL);
	}

	inet_ntop(PF_INET, &ctxt.rc_saddr->re_addr.sin_addr, ipbuf,
		  INET_ADDRSTRLEN);
	verbosef(2, stderr, "Binding endpoint %s:%d\n",
		 ipbuf, ntohs(ctxt.rc_saddr->re_addr.sin_port));

	rc = rds_bind(&ctxt);
	if (rc)
		goto out;

	if (ctxt.rc_filename) {
		rc = dup_file(&ctxt, STDIN_FILENO, O_RDONLY);
		if (rc)
			goto out;
		if (!strcmp(ctxt.rc_filename, "-"))
			ctxt.rc_filename = "<standard input>";
	}

	list_for_each_entry(e, &ctxt.rc_daddrs, re_item) {
		inet_ntop(PF_INET, &e->re_addr.sin_addr, ipbuf,
			  INET_ADDRSTRLEN);
		verbosef(2, stderr,
			 "Adding destination %s:%d\n", ipbuf,
			 ntohs(e->re_addr.sin_port));
	}

	rc = setup_signals();
	if (rc) {
		verbosef(0, stderr, "%s: Unable to initialize signals\n",
			 progname);
		goto out;
	}

	rc = wli_do_send(&ctxt);

out:
	free(ctxt.rc_saddr->re_name);
	free(ctxt.rc_saddr);

	return rc;
}
