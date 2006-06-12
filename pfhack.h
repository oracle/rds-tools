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

#define OFFICIAL_PF_RDS		32
#define OFFICIAL_SOL_RDS	272


#ifdef DYNAMIC_PF_RDS
extern int discover_pf_rds();
extern int discover_sol_rds();

#define AF_RDS discover_pf_rds()
#define SOL_RDS discover_sol_rds()
#endif  /* DYNAMIC_PF_RDS */

#endif  /* __PF_HACK_H */
