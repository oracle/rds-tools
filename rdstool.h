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
 * tools header stuff
 */

#ifndef __RDS_TOOL_H
#define __RDS_TOOL_H

#include <netinet/in.h>

#include "kernel-list.h"
#include "pfhack.h"

#ifndef AF_RDS
# define AF_RDS OFFICIAL_PF_RDS
#endif
#ifndef PF_RDS
# define PF_RDS AF_RDS
#endif
#ifndef SOL_RDS
# define SOL_RDS OFFICIAL_SOL_RDS
#endif

#define RDS_TOOL_BASE_OPTS ":s:m:f:i:-:vqhV"
#define RDS_SINK_OPTS
#define RDS_GEN_OPTS "d:b:l:"

#define RDS_DEFAULT_MSG_SIZE 4096

#define verbosef(lvl, f, fmt, a...) do { \
	if (verbose >= (lvl)) \
		fprintf((f), fmt, ##a); \
} while (0)

struct rds_endpoint {
    struct list_head re_item;
    char *re_name;
    struct sockaddr_in re_addr;
    int re_fd;
};

struct rds_context {
	struct rds_endpoint *rc_saddr;
	struct list_head rc_daddrs;
	const char *rc_filename;
	uint32_t rc_msgsize;
	uint64_t rc_total;
};

/* Set by parse_options() */
extern char *progname;
extern unsigned int verbose;

extern int parse_options(int argc, char *argv[], const char *opts,
			 struct rds_context *ctxt);
extern int rds_bind(struct rds_context *ctxt);
extern int dup_file(struct rds_context *ctxt, int fd, int flags);
extern int setup_signals(void);
extern int runningp(void);

/* stats.c */
extern int stats_init(int delay);
extern void stats_extended(int extendedp);
extern void stats_start(void);
extern void stats_print(void);
extern void stats_total(void);

extern void stats_add_recv(uint64_t bytes);
extern void stats_add_send(uint64_t bytes);
extern uint64_t stats_get_send(void);
extern void stats_add_read(uint64_t bytes);
extern void stats_add_write(uint64_t bytes);


/* Provided by C files with main() */
extern void print_usage(int rc);
extern void print_version(void);
#endif  /* __RDS_TOOL_H */
