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
 * rds-sink.c: Collect some RDS packets.
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
#include <inttypes.h>

#include "kernel-list.h"
#include "rdstool.h"

void print_usage(int rc)
{
	int namelen = strlen(progname);
	FILE *output = rc ? stderr : stdout;

	verbosef(0, output,
		 "Usage: %s -s <source_ip>:<source_port>\n"
		 "       %*s [-f <output_file>] [-i <interval>]\n"
		 "       %*s [-v ...] [-q ...]\n"
		 "       %s -h\n"
		 "       %s -V\n",
		 progname, namelen, "", namelen, "", progname, progname);

	exit(rc);
}

void print_version()
{
	verbosef(0, stdout, "%s version VERSION\n", progname);

	exit(0);
}

static int empty_buff(struct rds_context *ctxt, char *bytes, ssize_t len)
{
	int ret = 0;
	char *ptr = bytes;

	if (!ctxt->rc_filename)
		len = 0;  /* Throw it away */

	while (len && runningp()) {
		stats_print();

		ret = write(STDOUT_FILENO, ptr, len);
		if (!ret) {
			verbosef(0, stderr,
				 "%s: Unexpected end of file writing to %s\n",
				 progname, ctxt->rc_filename);
			ret = -EPIPE;
			break;
		}
		if (ret < 0) {
			ret = -errno;
			if (ret == -EINTR)
				continue;

			verbosef(0, stderr,
				 "%s: Error writing to %s: %s\n",
				 progname, ctxt->rc_filename,
				 strerror(-ret));
			break;
		}

		stats_add_write(ret);
		ptr += ret;
		len -= ret;
		ret = 0;
	}

	return ret;
}

static ssize_t recv_buff(struct rds_endpoint *e, struct msghdr *msg,
			 int flags)
{
	ssize_t ret = 0;

	while (runningp()) {
		stats_print();

		ret = recvmsg(e->re_fd, msg, flags);
		if (ret < 0) {
			ret = -errno;
			if (ret == -EINTR)
				continue;

			verbosef(0, stderr,
				 "%s: Error from recvmsg: %s\n",
				 progname, strerror(-ret));
		}

		/* Success */
		break;
	}

	return ret;
}

static int wli_do_recv(struct rds_context *ctxt)
{
	struct rds_endpoint *e = ctxt->rc_saddr;
	ssize_t alloced = 0;
	ssize_t ret = 0;
	struct iovec iov = {
		.iov_base = NULL,
	};
	struct msghdr msg = {
		.msg_name = &e->re_addr,
		.msg_namelen = sizeof(struct sockaddr_in),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	verbosef(2, stderr, "Starting receive loop\n");

	stats_start();

	while (runningp()) {
		/* Calls stats_print() */
		iov.iov_len = 0;
		ret = recv_buff(e, &msg, MSG_PEEK|MSG_TRUNC);
		if (ret < 0)
			break;

		if (ret > alloced) {
			verbosef(3, stderr,
				 "Growing buffer to %zd bytes\n",
				 ret);
			iov.iov_base = realloc(iov.iov_base, ret);
			if (iov.iov_base == NULL) {
				ret = -ENOMEM;
				break;
			}
			alloced = ret;
		}

		/* Calls stats_print() */
		iov.iov_len = ret;
		ret = recv_buff(e, &msg, 0);
		if (ret < 0)
			break;

		stats_add_recv(ret);

		/* Calls stats_print() */
		ret = empty_buff(ctxt, iov.iov_base, ret);
		if (ret)
			break;
	}
	verbosef(2, stderr, "Stopping receive loop\n");

	stats_total();

	return ret;
}

int main(int argc, char *argv[])
{
	int rc;
	char ipbuf[INET_ADDRSTRLEN];
        struct rds_context ctxt = {
                .rc_filename = "-",
        };


	INIT_LIST_HEAD(&ctxt.rc_daddrs);

	rc = parse_options(argc, argv, RDS_TOOL_BASE_OPTS RDS_SINK_OPTS,
			   &ctxt);
	if (rc)
		print_usage(rc);

	inet_ntop(PF_INET, &ctxt.rc_saddr->re_addr.sin_addr, ipbuf,
		  INET_ADDRSTRLEN);
	verbosef(2, stderr, "Binding endpoint %s:%d\n",
		 ipbuf, ntohs(ctxt.rc_saddr->re_addr.sin_port));

	rc = rds_bind(&ctxt);
	if (rc)
		goto out;

	if (ctxt.rc_filename) {
		rc = dup_file(&ctxt, STDOUT_FILENO, O_CREAT|O_WRONLY);
		if (rc)
			goto out;
		if (!strcmp(ctxt.rc_filename, "-"))
			ctxt.rc_filename = "<standard output>";
	}

	setup_signals();
	if (rc) {
		verbosef(0, stderr, "%s: Unable to initialize signals\n",
			 progname);
		goto out;
	}

	rc = wli_do_recv(&ctxt);

out:
	free(ctxt.rc_saddr->re_name);
	free(ctxt.rc_saddr);

	return rc;
}
