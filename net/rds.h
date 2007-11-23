/*
 * net/rds.h - user space interface for RDS
 *
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
 */

#ifndef __NET_RDS_H
#define __NET_RDS_H

/*
 * setsockopt/getsockopt for SOL_RDS
 */
#define RDS_CANCEL_SENT_TO      	1
#define RDS_INFO_COUNTERS		10000
#define RDS_INFO_CONNECTIONS		10001
/* 10002 aka RDS_INFO_FLOWS is deprecated */
#define RDS_INFO_SEND_MESSAGES		10003
#define RDS_INFO_RETRANS_MESSAGES       10004
#define RDS_INFO_RECV_MESSAGES          10005
#define RDS_INFO_SOCKETS                10006
#define RDS_INFO_TCP_SOCKETS            10007

struct rds_info_counter {
	uint8_t		name[32];
	uint64_t	value;
};

#define RDS_INFO_CONNECTION_FLAG_SENDING	0x01
#define RDS_INFO_CONNECTION_FLAG_CONNECTING	0x02
#define RDS_INFO_CONNECTION_FLAG_CONNECTED	0x04

struct rds_info_connection {
	uint64_t	next_tx_seq;
	uint64_t	next_rx_seq;
	uint32_t	laddr;
	uint32_t	faddr;
	uint8_t		transport[15];           /* null term ascii */
	uint8_t		flags;
} __attribute__((packed));

struct rds_info_socket {
	uint32_t	sndbuf;
	uint32_t	bound_addr;
	uint32_t	connected_addr;
	uint16_t	bound_port;
	uint16_t	connected_port;
	uint32_t	rcvbuf;
} __attribute__((packed));

#define RDS_INFO_MESSAGE_FLAG_ACK               0x01
#define RDS_INFO_MESSAGE_FLAG_FAST_ACK          0x02

struct rds_info_message {
	uint64_t	seq;
	uint32_t	len;
	uint32_t	laddr;
	uint32_t	faddr;
	uint16_t	lport;
	uint16_t	fport;
	uint8_t		flags; /* currently unused */
} __attribute__((packed));

struct rds_info_tcp_socket {
	/* _addr and _port are network (big) endian */
        uint32_t          local_addr;
        uint16_t          local_port;
        uint32_t          peer_addr;
        uint16_t          peer_port;
        uint64_t             hdr_rem;
        uint64_t             data_rem;
        uint32_t             last_sent_nxt;
        uint32_t             last_expected_una;
        uint32_t             last_seen_una;
} __attribute__((packed));



#endif /* __NET_RDS_H */
