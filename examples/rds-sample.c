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
#include <unistd.h>

/* FIXME - this is a hack to getaround RDS not exporting any header files.
 * This is a local copy.
 */
#include "ib_rds.h"
/* These are defined in rds.h....but that file is not happily included */
#define SOL_RDS		272
#define PF_RDS		28


#define TESTPORT	4000
#define BUFSIZE		94

static int do_rdma_read(int sock, struct msghdr *msg, void *buf)
{
	struct rds_rdma_args *args;
	struct rds_iovec iov;
	struct cmsghdr *cmsg;
	int rc;

	cmsg = CMSG_FIRSTHDR(msg);
	args = (struct rds_rdma_args *)CMSG_DATA(cmsg);

	/* Do a sendmsg call to preform the RDMA */
	cmsg->cmsg_level = SOL_RDS;
	cmsg->cmsg_type = RDS_CMSG_RDMA_ARGS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct rds_rdma_args));

	iov.addr = (uint64_t) buf;
	iov.bytes = BUFSIZE * sizeof(char);

	args->remote_vec.addr = 0;
	args->remote_vec.bytes = BUFSIZE * sizeof(char);
	args->local_vec_addr = (uint64_t) &iov;
	args->nr_local = 1;
	args->flags = RDS_RDMA_NOTIFY_ME;
	args->user_token = 0;

	msg->msg_controllen = CMSG_SPACE(sizeof(struct rds_rdma_args));

	rc = sendmsg(sock, msg, 0);
	if (rc < 0) {
		printf("%s: Error sending message: %d %d\n", __func__, rc, errno);
		return -1;
	}

	sleep(1);

	rc = recvmsg(sock, msg, 0);
	if (rc < 0) {
		printf("%s: Error receiving message: %d %d\n", __func__, rc, errno);
		return -1;
	}

	return 0;
}

static void server(char *address)
{
	struct sockaddr_in sin, din;
	void *buf, *ctlbuf;
	struct msghdr msg;
	struct iovec *iov;
	int rc, sock;

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

	ctlbuf = calloc(1, sizeof(struct rds_rdma_args));
	if (!ctlbuf) {
		printf("%s: calloc failed\n", __func__);
		goto out1;
	}

	iov[0].iov_base = buf;
	iov[0].iov_len = BUFSIZE * sizeof(char);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &din;
	msg.msg_namelen = sizeof(din);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctlbuf;
	msg.msg_controllen = CMSG_SPACE(sizeof(struct rds_rdma_args));

	printf("server listening on %s\n", inet_ntoa(sin.sin_addr));

	rc = recvmsg(sock, &msg, 0);
	if (rc < 0) {
		printf("%s: Error receiving message: %d %d\n", __func__, rc, errno);
		goto out2;
	}

	printf("Received a packet len %d, cmsg len %d, on port %d\n",
	       (uint32_t) iov[0].iov_len,
	       (uint32_t) msg.msg_controllen,
	       din.sin_port);

	if (msg.msg_controllen) {
		rc = do_rdma_read(sock, &msg, buf);
		if (rc < 0)
			goto out2;
	}
	printf("payload contains:  %s\n", (char *)buf);

out2:
	free(ctlbuf);
out1:
	free(iov);
out:
	free(buf);
}

static void create_message(char *buf)
{
	int i;

	for (i = 0; i < BUFSIZE; i++)
		buf[i] = i + 0x21;
}

static int build_rds_rdma_packet(int sock, struct msghdr *msg, void *buf, uint64_t *cookie)
{
	struct rds_get_mr_args mr_args;
	struct cmsghdr *cmsg;
	void *ctlbuf;

	mr_args.vec.addr = (uint64_t) buf;
	mr_args.vec.bytes = BUFSIZE * sizeof(char);
	mr_args.cookie_addr = (uint64_t) cookie;
	mr_args.flags = RDS_RDMA_READWRITE;

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

	msg->msg_iov = NULL;
	msg->msg_iovlen = 0;

	return 0;
}

static int build_rds_packet(struct msghdr *msg, char *buf)
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
	iov[0].iov_len = BUFSIZE * sizeof(char);

	return 0;
}

static void client(char *localaddr, char *remoteaddr, int rdma)
{
	struct sockaddr_in sin, din;
	struct msghdr msg;
	uint64_t cookie = 0;
	int rc, sock;
	void *buf;

	buf = calloc(BUFSIZE, sizeof(char));
	if (!buf) {
		printf("%s: calloc failed\n", __func__);
		return;
	}

	create_message((char *)buf);

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

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &din;
	msg.msg_namelen = sizeof(din);

	memset(&din, 0, sizeof(din));
	din.sin_family = AF_INET;
	din.sin_addr.s_addr = inet_addr(remoteaddr);
	din.sin_port = TESTPORT;

	if (rdma) {
		rc = build_rds_rdma_packet(sock, &msg, buf, &cookie);
		if (rc < 0)
			goto out;

		printf("Client Sending RDMA message from %s to %s\n",
		       localaddr, remoteaddr);
	} else {
		rc = build_rds_packet(&msg, buf);
		if (rc < 0)
			goto out;

		printf("client sending %d byte message %s from %s to %s on port %d\n",
		       (uint32_t) msg.msg_iov->iov_len,
		       (char *)buf,
		       localaddr,
		       remoteaddr,
		       sin.sin_port);
	}

	rc = sendmsg(sock, &msg, 0);
	if (rc < 0) {
		printf("%s: Error sending message: %d %d\n", __func__, rc, errno);
		goto out1;
	}

	if (rdma) {
		/* reuse the same msg, as it should no longer be necessary and this incoming
		 * msg should be empty
		 */
		rc = recvmsg(sock, &msg, 0);
		if (rc < 0) {
			printf("%s: Error receiving message: %d %d\n", __func__, rc, errno);
		}
	}

out1:
	if (msg.msg_control)
		free(msg.msg_control);
	if (msg.msg_iov)
		free(msg.msg_iov);
out:
	free(buf);
}

int main(int argc, char **argv)
{
	char *serveraddr = NULL, *clientaddr = NULL;
	int i, rdma = 0;

	if (argc < 3) {
		printf("not enough args\n");
		return -1;
	}

	for (i = 1; i < argc; i++) {
		if (!strcmp("-s", argv[i])) {
			serveraddr = argv[i+1];
			i++;
		} else if (!strcmp("-c", argv[i])) {
			clientaddr = argv[i+1];
			i++;
		} else if (!strcmp("--rdma", argv[i])) {
			rdma = 1;
		} else
			printf("Invalid param\n");
	}

	if (serveraddr && !clientaddr) {
		server(serveraddr);
	} else if (serveraddr && clientaddr) {
		client(clientaddr, serveraddr, rdma);
	}

	return 0;
}

