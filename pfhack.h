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
 * pfhack.h - discover the RDS constants 
 *
 * PF_RDS and SOL_RDS should be assigned constants.  However, we don't have
 * official values yet.  There is a hack to overload an existing PF_ value
 * (21).  This dynamic code detects what the running kernel is using.
 */

#ifndef __PF_HACK_H
#define __PF_HACK_H

#define OFFICIAL_PF_RDS		21
#define OFFICIAL_SOL_RDS	276


#ifdef DYNAMIC_PF_RDS
extern int discover_pf_rds();
extern int discover_sol_rds();

#define AF_RDS discover_pf_rds()
#define PF_RDS AF_RDS
#define SOL_RDS discover_sol_rds()
#endif  /* DYNAMIC_PF_RDS */

#endif  /* __PF_HACK_H */
