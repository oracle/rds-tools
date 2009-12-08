/*
 * Copyright (c) 2008 Chelsio, Inc. All rights reserved.
 *
 * Author: Jon Mason <jon@opengridcomputing.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* FIXME - this is a hack to getaround RDS not exporting any header files.
 * This is a local copy of the file found at net/rds/
 */
#include "rds.h"
/* These are defined in rds.h....but that file is not happily included */
#define SOL_RDS		272
#define PF_RDS		28


#define TESTPORT	4000
#define BUFSIZE		94

#define NUM_PRINTABLE_CHARS	94
#define PRINTABLE_CHARS_OFFSET	33

#define VERBOSE_FLAG	(1 << 0)
#define RDMA_READ_FLAG	(1 << 1)
#define RDMA_WRITE_FLAG	(1 << 2)

struct rdss_message {
	int count;
	uint32_t flags;
	char msg[BUFSIZE];
};

static void print_orb(int i)
{
	char buf;

	switch (i % 6) {
	case 0:
		buf = '.';
		break;
	case 1:
		buf = 'o';
		break;
	case 2:
		buf = 'O';
		break;
	case 3:
		buf = '0';
		break;
	case 4:
		buf = 'O';
		break;
	case 5:
		buf = 'o';
		break;
	}

	printf("\b%c", buf);
	fflush(stdout);
}

static void create_message(char *buf, uint32_t start)
{
	int i;

	for (i = 0; i < BUFSIZE; i++)
		buf[i] = ((i + start) % NUM_PRINTABLE_CHARS) + PRINTABLE_CHARS_OFFSET;
}

static int do_rdma_read(int sock, struct msghdr *msg, struct rdss_message *buf,
			uint32_t remote_flags)
{
	struct rds_rdma_args *args;
	struct rds_iovec iov;
	struct cmsghdr *cmsg;
	int rc;

	if (remote_flags & RDMA_WRITE_FLAG)
		create_message(buf->msg, buf->count);

	cmsg = CMSG_FIRSTHDR(msg);
	args = (struct rds_rdma_args *)CMSG_DATA(cmsg);

	/* Do a sendmsg call to preform the RDMA */
	cmsg->cmsg_level = SOL_RDS;
	cmsg->cmsg_type = RDS_CMSG_RDMA_ARGS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct rds_rdma_args));

	iov.addr = (uint64_t) buf;
	iov.bytes = sizeof(struct rdss_message);

	args->remote_vec.addr = 0;
	args->remote_vec.bytes = sizeof(struct rdss_message);
	args->local_vec_addr = (uint64_t) &iov;
	args->nr_local = 1;
	args->flags = remote_flags ? (RDS_RDMA_READWRITE | RDS_RDMA_FENCE) : 0;
	args->flags |= RDS_RDMA_NOTIFY_ME;
	args->user_token = 0;

	msg->msg_controllen = CMSG_SPACE(sizeof(struct rds_rdma_args));

	rc = sendmsg(sock, msg, 0);
	if (rc < 0) {
		printf("%s: Error sending message: %d %d\n", __func__, rc, errno);
		return -1;
	}

	/* Spin waiting for the confirmation that the RDMA operation has completed */
	do {
		rc = recvmsg(sock, msg, MSG_DONTWAIT);
	} while (rc < 0 && errno == EAGAIN);

	return 0;
}

static void server(char *address, uint32_t flags)
{
	struct sockaddr_in sin, din;
	struct rdss_message *buf;
	struct msghdr msg;
	struct iovec *iov;
	void *ctlbuf;
	int rc, sock, count = 0;

	buf = calloc(1, sizeof(struct rdss_message));
	if (!buf) {
		printf("%s: calloc failed\n", __func__);
		return;
	}

	sock = socket(PF_RDS, SOCK_SEQPACKET, 0);
	if (sock < 0) {
		printf("%s: Error creating Socket: %d\n", __func__, sock);
		goto out;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(address);
	sin.sin_port = TESTPORT;

	rc = bind(sock, (struct sockaddr *)&sin, sizeof(sin));
	if (rc < 0) {
		printf("%s: Error binding to address: %d %d\n", __func__, rc, errno);
		goto out;
	}

	/* The recv iov could contain a regular RDS packet or an RDMA RDS
	 * packet, so set it up for the worst case for both.
	 */
	iov = calloc(1, sizeof(struct iovec));
	if (!iov) {
		printf("%s: calloc failed\n", __func__);
		goto out;
	}

	ctlbuf = calloc(1, CMSG_SPACE(sizeof(struct rds_rdma_args)));
	if (!ctlbuf) {
		printf("%s: calloc failed\n", __func__);
		goto out1;
	}

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(struct rdss_message);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &din;
	msg.msg_namelen = sizeof(din);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctlbuf;
	msg.msg_controllen = CMSG_SPACE(sizeof(struct rds_rdma_args));

	if (flags & VERBOSE_FLAG)
		printf("server listening on %s\n", inet_ntoa(sin.sin_addr));

	do {
		rc = recvmsg(sock, &msg, 0);
		if (rc < 0) {
			printf("%s: Error receiving message: %d %d\n", __func__, rc, errno);
			goto out2;
		}

		if (flags & VERBOSE_FLAG)
			printf("Received %s packet %d of len %d, cmsg len %d, on port %d\n",
			       msg.msg_controllen ? "RDS RDMA" : "RDS",
			       count,
			       (uint32_t) iov[0].iov_len,
			       (uint32_t) msg.msg_controllen,
			       din.sin_port);

		if (msg.msg_controllen) {
			rc = do_rdma_read(sock, &msg, buf, buf->flags);
			if (rc < 0)
				goto out2;
		}

		count++;

		if (flags & VERBOSE_FLAG && !(buf->flags & RDMA_WRITE_FLAG))
			printf("payload contains: %d  %s\n", buf->count, buf->msg);

		if (!(flags & VERBOSE_FLAG))
			print_orb(count);

	} while (buf->count - 1);

out2:
	free(ctlbuf);
out1:
	free(iov);
out:
	free(buf);

	printf("\n%d packets received\n", count);
}

static int build_rds_rdma_packet(int sock, struct msghdr *msg, void *buf,
				 uint64_t *cookie, uint32_t *flags)
{
	struct rds_get_mr_args mr_args;
	struct cmsghdr *cmsg;
	void *ctlbuf;
	struct iovec *iov;

	mr_args.vec.addr = (uint64_t) buf;
	mr_args.vec.bytes = sizeof(struct rdss_message);
	mr_args.cookie_addr = (uint64_t) cookie;
	mr_args.flags = RDS_RDMA_USE_ONCE;

	ctlbuf = calloc(1, CMSG_SPACE(sizeof(mr_args)));
	if (!ctlbuf) {
		printf("%s: calloc failed\n", __func__);
		return -1;
	}

	msg->msg_control = ctlbuf;
	msg->msg_controllen = CMSG_SPACE(sizeof(mr_args));

	cmsg = CMSG_FIRSTHDR(msg);
	cmsg->cmsg_level = SOL_RDS;
	cmsg->cmsg_type = RDS_CMSG_RDMA_MAP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(mr_args));
	memcpy(CMSG_DATA(cmsg), &mr_args, sizeof(mr_args));

	iov = calloc(1, sizeof(struct iovec));
	if (!iov) {
		printf("%s: calloc failed\n", __func__);
		return -1;
	}

	msg->msg_iov = iov;
	msg->msg_iovlen = 1;

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(struct rdss_message);

	return 0;
}

static int build_rds_packet(struct msghdr *msg, void *buf)
{
	struct iovec *iov;

	iov = calloc(1, sizeof(struct iovec));
	if (!iov) {
		printf("%s: calloc failed\n", __func__);
		return -1;
	}

	msg->msg_iov = iov;
	msg->msg_iovlen = 1;

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(struct rdss_message);

	return 0;
}

static void client(char *localaddr, char *remoteaddr, uint32_t flags, int count)
{
	struct sockaddr_in sin, din;
	int rc, sock, num_mess;
	void *buf;

	buf = calloc(BUFSIZE, sizeof(char));
	if (!buf) {
		printf("%s: calloc failed\n", __func__);
		return;
	}

	sock = socket(PF_RDS, SOCK_SEQPACKET, 0);
	if (sock < 0) {
		printf("%s: Error creating Socket: %d\n", __func__, sock);
		goto out;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(localaddr);

	rc = bind(sock, (struct sockaddr *)&sin, sizeof(sin));
	if (rc < 0) {
		printf("%s: Error binding to address: %d %d\n", __func__, rc, errno);
		goto out;
	}

	for (num_mess = count; num_mess || count == -1; num_mess--) {
		struct rdss_message mess;
		uint64_t cookie = 0;
		struct msghdr msg;

		/* For an RDMA_WRITE, it is not necessary to write anything to the buf.  As
		 * this is going to be over-written when the server performs a RDMA_WRITE into
		 * this buffer
		 */
		if (!(flags & RDMA_WRITE_FLAG))
			create_message((char *)buf, (uint32_t) num_mess);

		memset(&msg, 0, sizeof(msg));
		msg.msg_name = &din;
		msg.msg_namelen = sizeof(din);

		memset(&din, 0, sizeof(din));
		din.sin_family = AF_INET;
		din.sin_addr.s_addr = inet_addr(remoteaddr);
		din.sin_port = TESTPORT;

		mess.count = num_mess;
		mess.flags = flags;
		memcpy(&mess.msg, buf, sizeof(mess.msg));

		if (flags & RDMA_READ_FLAG || flags & RDMA_WRITE_FLAG) {
			rc = build_rds_rdma_packet(sock, &msg, &mess, &cookie, &flags);
			if (rc < 0)
				goto out;

			if (flags & VERBOSE_FLAG)
				printf("Client Sending RDMA message %d from %s to %s\n",
					count - num_mess, localaddr, remoteaddr);
		} else {
			rc = build_rds_packet(&msg, &mess);
			if (rc < 0)
				goto out;

			if (flags & VERBOSE_FLAG)
				printf("client sending %d byte message %s from %s to %s\n",
				       (uint32_t) msg.msg_iov->iov_len,
				       (char *)buf,
				       localaddr,
				       remoteaddr);
		}

		rc = sendmsg(sock, &msg, 0);
		if (rc < 0) {
			printf("%s: Error sending message: %d %d\n", __func__, rc, errno);
			goto out1;
		}

		if (flags & RDMA_READ_FLAG || flags & RDMA_WRITE_FLAG) {
			/* reuse the same msg, as it should no longer be necessary and this incoming
			 * msg should be empty
			 */
			rc = recvmsg(sock, &msg, 0);
			if (rc < 0) {
				printf("%s: Error receiving message: %d %d\n", __func__, rc, errno);
			}
		}

		if (flags & VERBOSE_FLAG && flags & RDMA_WRITE_FLAG)
			printf("payload contains: %d  %s\n", mess.count, mess.msg);

out1:
		if (msg.msg_control)
			free(msg.msg_control);
		if (msg.msg_iov)
			free(msg.msg_iov);
		if (rc < 0)
			break;

		if (!(flags & VERBOSE_FLAG))
			print_orb(count - num_mess);
	}

	printf("\n%d messages sent\n", count - num_mess);
out:
	free(buf);
}

int main(int argc, char **argv)
{
	char *serveraddr = NULL, *clientaddr = NULL;
	uint32_t flags = 0;
	int i, count = -1;

	if (argc < 3) {
		printf("not enough args\n");
		return -1;
	}

	for (i = 1; i < argc; i++) {
		if (!strcmp("-s", argv[i]) || !strcmp("--server", argv[i])) {
			serveraddr = argv[i+1];
			i++;
		} else if (!strcmp("-c", argv[i]) || !strcmp("--client", argv[i])) {
			clientaddr = argv[i+1];
			i++;
		} else if (!strcmp("-C", argv[i]) || !strcmp("--count", argv[i])) {
			count = atoi(argv[i+1]);
			i++;
		} else if (!strcmp("-rr", argv[i]) || !strcmp("--rdma-read", argv[i])) {
			flags |= RDMA_READ_FLAG;
		} else if (!strcmp("-rw", argv[i]) || !strcmp("--rdma-write", argv[i])) {
			flags |= RDMA_WRITE_FLAG;
		} else if (!strcmp("-v", argv[i]) || !strcmp("--verbose", argv[i])) {
			flags |= VERBOSE_FLAG;
		} else
			printf("Invalid param\n");
	}

	if (serveraddr && !clientaddr) {
		server(serveraddr, flags);
	} else if (serveraddr && clientaddr) {
		client(clientaddr, serveraddr, flags, count);
	}

	return 0;
}
