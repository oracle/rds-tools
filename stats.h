/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * stats.h - Print stats at an interval
 */

#ifndef __RDS_TOOL_STATS_H
#define __RDS_TOOL_STATS_H

extern void stats_init(int delay);
extern int stats_print(void);
extern int stats_sleep(int read_fd, int write_fd);

extern void stats_recv(uint64_t num);
extern void stats_send(uint64_t num);
extern void stats_read(uint64_t num);
extern void stats_write(uint64_t num);

#endif  /* __RDS_TOOL_STATS_H */
