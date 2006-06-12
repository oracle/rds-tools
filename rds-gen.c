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
		 "       %*s [-f <input_file>] [-m <msg_size>] [-b <send_buffer>]\n"
		 "       %*s [-l <total_bytes>]\n"
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

static int wli_do_send(struct rds_context *ctxt)
{
	char bytes[ctxt->rc_msgsize];
	char *ptr;
	ssize_t len, ret = 0;
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
	while (1) {
		len = ctxt->rc_msgsize;
		ptr = bytes;
		while (len) {
			ret = read(STDIN_FILENO, ptr, len);
			if (!ret) {
				if (ptr != bytes) {
					verbosef(0, stderr,
						 "%s: Unexpected end of file reading from %s\n",
						 progname, ctxt->rc_filename);
				}
				break;
			}
			if (ret < 0) {
				ret = -errno;
				verbosef(0, stderr,
					 "%s: Error reading from %s: %s\n",
					 progname, ctxt->rc_filename,
					 strerror(-ret));
				break;
			}

			ptr += ret;
			len -= ret;
		}
		verbosef(3, stderr, "Read %zd bytes from stdin\n",
			 ptr - bytes);

		de = pick_dest(ctxt, de);
		verbosef(2, stderr, "Destination %s\n", de->re_name);

		msg.msg_name = &de->re_addr;
		ret = sendmsg(se->re_fd, &msg, 0);
		if (!ret)
			break;
		if (ret < 0) {
			ret = -errno;
			verbosef(0, stderr,
				 "%s: Error from sendmsg: %s\n",
				 progname, strerror(-ret));
			break;
		}

		if (len)
			break;
	}
	verbosef(2, stderr, "Stopping send loop\n");

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
	} else
		ctxt.rc_filename = "<standard input>";

	list_for_each_entry(e, &ctxt.rc_daddrs, re_item) {
		inet_ntop(PF_INET, &e->re_addr.sin_addr, ipbuf,
			  INET_ADDRSTRLEN);
		verbosef(2, stderr,
			 "Adding destination %s:%d\n", ipbuf,
			 ntohs(e->re_addr.sin_port));
	}

	rc = wli_do_send(&ctxt);

out:
	free(ctxt.rc_saddr->re_name);
	free(ctxt.rc_saddr);

	return rc;
}
