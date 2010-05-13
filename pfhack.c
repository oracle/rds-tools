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

#define PF_RDS_PATH	"/proc/sys/net/rds/pf_rds"
#define SOL_RDS_PATH	"/proc/sys/net/rds/sol_rds"

static int discover_constant(const char *path, int official, int *found)
{
	int fd;
	ssize_t ret, total = 0;
	char buf[PATH_MAX];
	char *ptr;
	long val;

	if (*found >= 0)
		return *found;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		/* hmm, no more constants in /proc. we must not need it anymore
		 * so use official values.
		 */
		*found = official;
		return official;
	}

	while (total < sizeof(buf)) {
		ret = read(fd, buf + total, sizeof(buf) - total);
		if (ret > 0)
			total += ret;
		else
			break;
	}

	close(fd);

	val = strtoul(buf, &ptr, 0);
	if ((val > INT_MAX) || !ptr || (*ptr && (*ptr != '\n'))) {
		fprintf(stderr, "Unable to determine RDS constant: invalid address constant\n");
		exit(1);
	}

	*found = val;
	return (int)val;
}

int discover_pf_rds()
{
	static int	pf_rds = -1;

	return discover_constant(PF_RDS_PATH, PF_RDS, &pf_rds);
}

int discover_sol_rds()
{
	static int	sol_rds = -1;

	return discover_constant(SOL_RDS_PATH, SOL_RDS, &sol_rds);
}
