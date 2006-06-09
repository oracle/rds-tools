/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * tools header stuff
 */

#ifndef __RDS_TOOL_H
#define __RDS_TOOL_H

#define AF_RDS 32
#define PF_RDS AF_RDS
#define SOL_RDS 272
#define RDS_SNDBUF 2

#define RDS_TOOL_BASE_OPTS ":s:m:f:-:vqhV"
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
    uint32_t re_sndbuf;
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

/* Provided by C files with main() */
extern void print_usage(int rc);
extern void print_version(void);
#endif  /* __RDS_TOOL_H */
