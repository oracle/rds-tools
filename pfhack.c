/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * pfhack.c - discover the RDS constants 
 *
 * PF_RDS and SOL_RDS should be assigned constants.  However, we don't have
 * official values yet.  There is a hack to overload an existing PF_ value
 * (21).  This dynamic code detects what the running kernel is using.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "kernel-list.h"
#include "pfhack.h"
#include "rdstool.h"

#define PF_RDS_PATH	"/proc/sys/net/rds/pf_rds"
#define SOL_RDS_PATH	"/proc/sys/net/rds/sol_rds"

/* We don't allow any system that can't read pf_rds */
static void explode(const char *reason)
{
	fprintf(stderr,
	       	"%s: Unable to determine RDS constant: %s\n",
	       	progname, reason);

	exit(1);
}

static int discover_constant(const char *path, int official)
{
	int fd;
	ssize_t ret, total = 0;
	char buf[PATH_MAX];
	char *ptr;
	long val;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		explode("Can't open address constant");

	while (total < sizeof(buf)) {
		ret = read(fd, buf + total, sizeof(buf) - total);
		if (ret > 0)
			total += ret;
		else
			break;
	}

	close(fd);

	if (ret < 0)
		explode("Error reading address constant");

	val = strtoul(buf, &ptr, 0);
	if ((val > INT_MAX) || !ptr || (*ptr && (*ptr != '\n')))
		explode("Invalid address constant");

	return (int)val;
}

int discover_pf_rds()
{
	return discover_constant(PF_RDS_PATH, OFFICIAL_PF_RDS);
}

int discover_sol_rds()
{
	return discover_constant(SOL_RDS_PATH, OFFICIAL_SOL_RDS);
}
