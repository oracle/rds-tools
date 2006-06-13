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
		 "       %*s [-f <output_file>] [-m <msg_size>]\n"
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
	char peek_bytes[0]; 
	ssize_t len, ret = 0;
	struct rds_endpoint *e = ctxt->rc_saddr;
	struct iovec peek_iov = {
		.iov_base = peek_bytes,
		.iov_len = 0,
	};
	struct iovec iov;
	struct msghdr peek_msg = {
		.msg_name = &e->re_addr,
		.msg_namelen = sizeof(struct sockaddr_in),
		.msg_iov = &peek_iov,
		.msg_iovlen = 1,
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
		ret = recv_buff(e, &peek_msg, MSG_PEEK|MSG_TRUNC);
		if (ret < 0)
			break;

		if (ret > iov.iov_len) {
			verbosef(3, stderr,
				 "Growing buffer to %zd bytes\n",
				 ret);
			iov.iov_len = ret;
			iov.iov_base = malloc(sizeof(char) *
					      iov.iov_len);
		}

		/* Calls stats_print() */
		ret = recv_buff(e, &msg, 0);
		if (ret < 0)
			break;

		len = ret;
		stats_add_recv(len);

		/* Calls stats_print() */
		ret = empty_buff(ctxt, iov.iov_base, len);
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
		.rc_msgsize = RDS_DEFAULT_MSG_SIZE,
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
