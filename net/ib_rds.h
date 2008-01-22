/*
 * Copyright (c) 2008 Oracle.  All rights reserved.
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

#ifndef IB_RDS_H
#define IB_RDS_H

#include <linux/types.h>

/* These sparse annotated types shouldn't be in any user
 * visible header file. We should clean this up rather
 * than kludging around them. */
#ifndef __KERNEL__
#define __be16	u_int16_t
#define __be32	u_int32_t
#define __be64	u_int64_t
#endif

#define RDS_IB_ABI_VERSION		0x300

/*
 * setsockopt/getsockopt for SOL_RDS
 */
#define RDS_CANCEL_SENT_TO      	1
#define RDS_GET_MR			2
#define RDS_FREE_MR			3
#define RDS_BARRIER			4

/*
 * Control message types for SOL_RDS.
 *
 * CMSG_RDMA_ARGS (sendmsg)
 *	Request a RDMA transfer to/from the specified
 *	memory ranges.
 *	The cmsg_data is a struct rds_rdma_args.
 * RDS_CMSG_RDMA_DEST (recvmsg, sendmsg)
 *	Kernel informs application about intended
 *	source/destination of a RDMA transfer
 * RDS_CMSG_RDMA_MAP (sendmsg)
 *	Application asks kernel to map the given
 *	memory range into a IB MR, and send the
 *	R_Key along in an RDS extension header.
 *	The cmsg_data is a struct rds_get_mr_args,
 *	the same as for the GET_MR setsockopt.
 */
#define RDS_CMSG_RDMA_ARGS	1
#define RDS_CMSG_RDMA_DEST	2
#define RDS_CMSG_RDMA_MAP	3

#define RDS_INFO_COUNTERS		10000
#define RDS_INFO_CONNECTIONS		10001
/* 10002 aka RDS_INFO_FLOWS is deprecated */
#define RDS_INFO_SEND_MESSAGES		10003
#define RDS_INFO_RETRANS_MESSAGES       10004
#define RDS_INFO_RECV_MESSAGES          10005
#define RDS_INFO_SOCKETS                10006
#define RDS_INFO_TCP_SOCKETS            10007

struct rds_info_counter {
	u_int8_t	name[32];
	u_int64_t	value;
} __attribute__((packed));

#define RDS_INFO_CONNECTION_FLAG_SENDING	0x01
#define RDS_INFO_CONNECTION_FLAG_CONNECTING	0x02
#define RDS_INFO_CONNECTION_FLAG_CONNECTED	0x04

struct rds_info_connection {
	u_int64_t	next_tx_seq;
	u_int64_t	next_rx_seq;
	__be32		laddr;
	__be32		faddr;
	u_int8_t	transport[15];		/* null term ascii */
	u_int8_t	flags;
} __attribute__((packed));

struct rds_info_flow {
	__be32		laddr;
	__be32		faddr;
	u_int32_t	bytes;
	__be16		lport;
	__be16		fport;
} __attribute__((packed));

#define RDS_INFO_MESSAGE_FLAG_ACK               0x01
#define RDS_INFO_MESSAGE_FLAG_FAST_ACK          0x02

struct rds_info_message {
	u_int64_t	seq;
	u_int32_t	len;
	__be32		laddr;
	__be32		faddr;
	__be16		lport;
	__be16		fport;
	u_int8_t	flags;
} __attribute__((packed));

struct rds_info_socket {
	u_int32_t	sndbuf;
	__be32		bound_addr;
	__be32		connected_addr;
	__be16		bound_port;
	__be16		connected_port;
	u_int32_t	rcvbuf;
} __attribute__((packed));

struct rds_info_tcp_socket {
	__be32		local_addr;
	__be16		local_port;
	__be32		peer_addr;
	__be16		peer_port;
	u_int64_t	hdr_rem;
	u_int64_t	data_rem;
	u_int32_t	last_sent_nxt;
	u_int32_t	last_expected_una;
	u_int32_t	last_seen_una;
} __attribute__((packed));


/*
 * RDMA related types
 */

/*
 * This encapsulates a remote memory location.
 * In the current implementation, it contains the R_Key
 * of the remote memory region, and the offset into it
 * (so that the application does not have to worry about
 * alignment).
 */
typedef u_int64_t	rds_rdma_cookie_t;

struct rds_iovec {
	u_int64_t	addr;
	u_int64_t	bytes;
};

struct rds_get_mr_args {
	struct rds_iovec vec;
	u_int64_t	key_addr;
	u_int8_t	use_once;
	u_int8_t	reserved[7];
};

struct rds_barrier_args {
	__be32		daddr;
	u_int32_t	flags;
	u_int64_t	rdma_id_addr;
	u_int64_t	wait_rdma_id;
};

struct rds_free_mr_args {
	rds_rdma_cookie_t cookie;
	u_int64_t	flags;
};

/* Values for rds_free_mr_args.flags */
#define RDS_FREE_MR_ARGS_INVALIDATE 1

struct rds_rdma_args {
	rds_rdma_cookie_t cookie;
	struct rds_iovec remote_vec;
	u_int64_t	local_vec_addr;
	u_int64_t	nr_local;
	u_int64_t	flags;
	u_int64_t	rdma_id_addr;
};

/* Values for rds_rdma_args.flags */
#define RDS_RDMA_ARGS_WRITE	1  /* read when not set */
#define RDS_RDMA_ARGS_FENCE	2  /* use FENCE for immediate send */

#endif /* IB_RDS_H */
