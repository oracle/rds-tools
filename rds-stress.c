#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <netdb.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <inttypes.h>
#include <syscall.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <sched.h>

/*
 *
 * TODO
 *  - checksum the data some day.
 *  - use poll to wait instead of blocking recvmsg?  doesn't seem great.
 *  - measure us/call of nonblocking recvmsg
 *  - do something about receiver congestion
 *  - notice when parent tcp socket dies
 *  - should the parent be at a higher priority?
 *  - catch ctl-c
 *  - final stats summary page
 */

struct options {
	uint32_t	req_depth;
	uint32_t	req_size;
	uint32_t	ack_size;
	uint32_t	send_addr;
	uint32_t	receive_addr;
	uint16_t	starting_port;
	uint16_t	nr_tasks;
	uint32_t	run_time;
	uint8_t		summary_only;
	uint8_t		rtprio;

	/* At 1024 tasks, printing warnings about
	 * setsockopt(SNDBUF) allocation is rather
	 * slow. Cut that */
	uint8_t		suppress_warnings;
} __attribute__((packed));

struct counter {
	uint64_t	nr;
	uint64_t	sum;
	uint64_t	min;
	uint64_t	max;
};

enum {
	S_REQ_TX_BYTES = 0,
	S_REQ_RX_BYTES,
	S_ACK_TX_BYTES,
	S_ACK_RX_BYTES,
	S_SENDMSG_USECS,
	S_RTT_USECS,
	S__LAST
};

#define NR_STATS S__LAST

/*
 * Parents share a mapped array of these with their children.  Each child
 * gets one.  It's used to communicate between the child and the parent
 * simply.
 */
struct child_control {
	pid_t pid;
	int ready;
	struct timeval start;
	struct counter cur[NR_STATS];
	struct counter last[NR_STATS];
} __attribute__((aligned (256))); /* arbitrary */

struct soak_control {
	pid_t		pid;
	uint64_t	per_sec;
	uint64_t	counter;
	uint64_t	last;
	struct timeval	start;
} __attribute__((aligned (256))); /* arbitrary */

void stop_soakers(struct soak_control *soak_arr);

/*
 * Requests tend to be larger and we try to keep a certain number of them
 * in flight at a time.  Acks are sent in response to requests and tend
 * to be smaller.
 */
#define OP_REQ 1
#define OP_ACK 2

/*
 * Every message sent with sendmsg gets a header.  This lets the receiver
 * verify that it got what was sent.
 */
struct header {
	uint32_t	seq;
	uint32_t	from_addr;
	uint32_t	to_addr;
	uint16_t	from_port;
	uint16_t	to_port;
	uint16_t	index;
	uint8_t		op;
	uint8_t		data[0];
} __attribute__((packed));

#define MIN_MSG_BYTES (4 * sizeof(struct header))
#define die(fmt...) do {		\
	fprintf(stderr, fmt);		\
	exit(1);			\
} while (0)

#define die_errno(fmt, args...) do {				\
	fprintf(stderr, fmt ", errno: %d (%s)\n", ##args , errno,\
		strerror(errno));				\
	exit(1);						\
} while (0)

#define min(a,b) (a < b ? a : b)
#define max(a,b) (a > b ? a : b)

/* zero is undefined */
static inline uint64_t minz(uint64_t a, uint64_t b)
{
	if (a == 0)
		return b;
	if (b == 0)
		return a;
	return min(a, b);
}

static unsigned long long parse_ull(char *ptr, unsigned long long max)
{
	unsigned long long val;
	char *endptr;

	val = strtoull(ptr, &endptr, 0);
	if (*ptr && !*endptr && val <= max)
		return val;

	die("invalid number '%s'\n", ptr);
}

static uint32_t parse_addr(char *ptr)
{
	uint32_t addr;
        struct hostent *hent;

        hent = gethostbyname(ptr);
        if (hent && 
            hent->h_addrtype == AF_INET && hent->h_length == sizeof(addr)) {
		memcpy(&addr, hent->h_addr, sizeof(addr));
		return ntohl(addr);
	}

	die("invalid host name or dotted quad '%s'\n", ptr);
}

static void usage(void)
{
	printf(
	"Required parameters, no defaults:\n"
	" -p [port]         starting port number\n"
	" -r [addr]         receive on this host or dotted quad\n"
	" -s [addr]         send to this passive dotted quad\n"
	"\n"
	"Optional parameters, with defaults:\n"
	" -a [bytes, %u]    ack message length\n"
	" -q [bytes, 1024]  request message length\n"
	" -d [depth, 1]     request pipeline depth, nr outstanding\n"
	" -t [nr, 1]        number of child tasks\n"
	" -T [seconds, 0]   runtime of test, 0 means infinite\n"
	"\n"
	"Optional behavioural flags:\n"
	" -c                measure cpu use with per-cpu soak processes\n"
	" -z                print a summary at end of test only\n"
	"\n"
	"Example:\n"
	"  recv$ rds-stress -r recv -p 4000\n"
	"  send$ rds-stress -r send -s recv -p 4000 -q 4096 -t 2 -d 2\n"
	"\n", (int) MIN_MSG_BYTES);

	exit(2);
}

static void set_rt_priority(void)
{
	struct sched_param	param;

	memset(&param, 0, sizeof(param));
	param.sched_priority = 1;

	if (sched_setscheduler(0, SCHED_RR, &param) < 0)
		die_errno("sched_setscheduler(SCHED_RR) failed");
}

/* This hack lets children notice when their parents die.
 * We could also use kill(0), but that results in false
 * positives when the parent is a zombie (and that happens
 * if you have a script parsing the output of rds-stress,
 * and the parent dies).
 */
static void check_parent(pid_t pid)
{
	if (pid != getppid())
		die("parent %u exited\n", pid);
}

/*
 * put a pattern in the message so the remote side can verify that it's
 * what was expected.  For now we put a little struct at the beginning,
 * end, and middle of the message.  We made sure that all three could fit
 * by making the min message size 128.
 */
static void fill_hdr(unsigned char *message, uint32_t bytes, struct header *hdr)
{
	uint32_t off[3] = { 0, bytes / 2, bytes - sizeof(struct header) };
	int i;

	for (i = 0; i < 3; i++)
		memcpy(message + off[i], hdr, sizeof(struct header));
}

static char *inet_ntoa_32(uint32_t val)
{
	struct in_addr addr = { .s_addr = val };
	return inet_ntoa(addr);
}

static int check_hdr(void *message, uint32_t bytes, struct header *hdr)
{
	struct header *chk;
	uint32_t off[3] = { 0, bytes / 2, bytes - sizeof(struct header) };
	int i;

	for (i = 0; i < 3; i++) {
		chk = message + off[i];
		if (!memcmp(chk, hdr, sizeof(struct header)))
			continue;

#define bleh(var, disp)					\
		disp(hdr->var),				\
		chk->var == hdr->var ? " =" : "!=",	\
		disp(chk->var)

		/* 
		 * This is printed as one GIANT printf() so that it serializes
		 * with stdout() and we don't get things stomping on each
		 * other
		 */
		printf( "An incoming message had a header at offset %u which\n"
			"didn't contain the fields we expected:\n"
			"    member        expected eq             got\n"
			"       seq %15u %s %15u\n"
			" from_addr %15s %s %15s\n"
			" from_port %15u %s %15u\n"
			"   to_addr %15s %s %15s\n"
			"   to_port %15u %s %15u\n"
			"     index %15u %s %15u\n"
			"        op %15u %s %15u\n",
			off[i],
			bleh(seq, ntohl),
			bleh(from_addr, inet_ntoa_32),
			bleh(from_port, ntohs),
			bleh(to_addr, inet_ntoa_32),
			bleh(to_port, ntohs),
			bleh(index, ntohs),
			bleh(op, (uint8_t)));
#undef bleh

		return 1;
	}

	return 0;
}

void stat_inc(struct counter *ctr, uint64_t val)
{
	ctr->nr++;
	ctr->sum += val;
	ctr->min = minz(val, ctr->min);
	ctr->max = max(val, ctr->max);
}

int64_t tv_cmp(struct timeval *a, struct timeval *b)
{
	int64_t a_usecs = ((uint64_t)a->tv_sec * 1000000ULL) + a->tv_usec;
	int64_t b_usecs = ((uint64_t)b->tv_sec * 1000000ULL) + b->tv_usec;

	return a_usecs - b_usecs;
}

/* returns a - b in usecs */
uint64_t usec_sub(struct timeval *a, struct timeval *b)
{
	return ((uint64_t)(a->tv_sec - b->tv_sec) * 1000000ULL) + 
		a->tv_usec - b->tv_usec;
}

static int bound_socket(int domain, int type, int protocol,
			struct sockaddr_in *sin)
{
	int fd;
	int opt;

	fd = socket(domain, type, protocol);
	if (fd < 0)
		die_errno("socket(%d, %d, %d) failed", domain, type, protocol);

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
		die_errno("setsockopt(SO_REUSEADDR) failed");

	if (bind(fd, (struct sockaddr *)sin, sizeof(struct sockaddr_in)))
		die_errno("bind() failed");

	return fd;
}

static int rds_socket(struct options *opts, struct sockaddr_in *sin)
{
	char str[32] = {0, };
	int bytes;
	int fd;
	int val;
	socklen_t optlen;

	fd = open("/proc/sys/net/rds/pf_rds", O_RDONLY);
	if (fd < 0)
		die_errno("open(/proc/sys/net/rds/pf_rds) failed");

	read(fd, str, sizeof(str));

	sscanf(str, "%d", &val);
	close(fd);

	fd = bound_socket(val, SOCK_SEQPACKET, 0, sin);

	bytes = opts->nr_tasks * opts->req_depth * 
		(opts->req_size + opts->ack_size) * 2;

	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes)))
		die_errno("setsockopt(SNDBUF, %d) failed", bytes);
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)))
		die_errno("setsockopt(RCVBUF, %d) failed", bytes);

	optlen = sizeof(val);
	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, &optlen))
		die_errno("getsockopt(SNDBUF) failed");
	if (val / 2 < bytes && !opts->suppress_warnings)
		fprintf(stderr,
			"getsockopt(SNDBUF) returned %d, we wanted %d * 2\n",
			val, bytes);

	optlen = sizeof(val);
	if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, &optlen))
		die_errno("getsockopt(RCVBUF) failed");
	if (val / 2 < bytes && !opts->suppress_warnings)
		fprintf(stderr,
			"getsockopt(RCVBUF) returned %d, we need %d * 2\n",
			val, bytes);

	fcntl(fd, F_SETFL, O_NONBLOCK);

	return fd;
}

struct task {
	unsigned int		pending;
	unsigned int		unacked;
	struct sockaddr_in	src_addr;	/* same for all tasks */
	struct sockaddr_in	dst_addr;
	uint32_t		send_seq;
	uint32_t		recv_seq;
	uint16_t		send_index;
	uint16_t		recv_index;
	struct timeval *	send_time;
};

static int send_packet(int fd, struct task *t, unsigned int op,
		unsigned int qindex, unsigned int size)
{
	unsigned char buf[size];
	struct header hdr;
	ssize_t ret;

	hdr.op = op;
	hdr.seq = htonl(t->send_seq);
	hdr.from_addr = t->src_addr.sin_addr.s_addr;
	hdr.from_port = t->src_addr.sin_port;
	hdr.to_addr = t->dst_addr.sin_addr.s_addr;
	hdr.to_port = t->dst_addr.sin_port;
	hdr.index = htons(qindex);

	fill_hdr(buf, size, &hdr);

	ret = sendto(fd, buf, size, 0,
		     (struct sockaddr *) &t->dst_addr,
		     sizeof(t->dst_addr));
	if (ret < 0) {
		if (errno != EAGAIN)
			die_errno("sendto() failed");
		return ret;
	}
	if (ret != size)
		die("sendto() truncated - %zd", ret);
	t->send_seq++;
	return ret;
}

static int send_one(int fd, struct task *t,
		struct options *opts,
		struct child_control *ctl)
{
	struct timeval start;
	struct timeval stop;
	int ret;

	gettimeofday(&start, NULL);
	ret = send_packet(fd, t, OP_REQ, t->send_index, opts->req_size);
	gettimeofday(&stop, NULL);

	if (ret < 0)
		return ret;

	t->send_time[t->send_index] = start;
	stat_inc(&ctl->cur[S_REQ_TX_BYTES], ret);
	stat_inc(&ctl->cur[S_SENDMSG_USECS],
		 usec_sub(&stop, &start));

	t->send_index = (t->send_index + 1) % opts->req_depth;
	t->pending++;
	return ret;
}

static int send_ack(int fd, struct task *t, unsigned int qindex,
		struct options *opts,
		struct child_control *ctl)
{
	ssize_t ret;

	/* send an ack in response to the req we just got */
	ret = send_packet(fd, t, OP_ACK, qindex, opts->ack_size);
	if (ret < 0)
		return ret;
	if (ret != opts->ack_size)
		die_errno("sendto() returned %zd", ret);

	stat_inc(&ctl->cur[S_ACK_TX_BYTES], ret);
	return ret;
}

static int recv_one(int fd, struct task *tasks,
	       	struct options *opts,
		struct child_control *ctl)
{
	char buf[max(opts->req_size, opts->ack_size)];
	struct sockaddr_in sin;
	struct header hdr, *in_hdr;
	socklen_t socklen;
	struct timeval tstamp;
	struct task *t;
	uint16_t expect_index;
	int task_index;
	ssize_t ret;

	socklen = sizeof(struct sockaddr_in);
	ret = recvfrom(fd, buf, max(opts->req_size, opts->ack_size), 0,
			     (struct sockaddr *) &sin, &socklen);
	gettimeofday(&tstamp, NULL);

	if (ret < 0)
		return ret;
	if (ret < sizeof(struct header))
		die("recvfrom() returned short data: %zd", ret);
	if (socklen < sizeof(struct sockaddr_in))
		die("socklen = %d < sizeof(sin) (%zu)\n",
		    socklen, sizeof(struct sockaddr_in));

	/* check the incoming sequence number */
	task_index = ntohs(sin.sin_port) - opts->starting_port - 1;
	if (task_index >= opts->nr_tasks)
		die("received bad task index %u\n", task_index);
	t = &tasks[task_index];

	/* make sure the incoming message's size matches is op */
	in_hdr = (void *)buf;
	switch(in_hdr->op) {
	case OP_REQ:
		stat_inc(&ctl->cur[S_REQ_RX_BYTES], ret);
		if (ret != opts->req_size)
			die("req size %zd, not %u\n", ret,
			    opts->req_size);
		expect_index = t->recv_index;
		break;
	case OP_ACK:
		stat_inc(&ctl->cur[S_ACK_RX_BYTES], ret);
		if (ret != opts->ack_size)
			die("ack size %zd, not %u\n", ret,
			    opts->ack_size);

		/* This ACK should be for the oldest outstanding REQ */
		expect_index = (t->send_index - t->pending + opts->req_depth) % opts->req_depth;
		break;
	default:
		die("unknown op %u\n", in_hdr->op);
	}

	/*
	 * Verify that the incoming header indicates that this
	 * is the next in-order message to us.  We can't predict
	 * op.
	 */
	hdr.op = in_hdr->op;
	hdr.seq = htonl(t->recv_seq);
	hdr.from_addr = sin.sin_addr.s_addr;
	hdr.from_port = sin.sin_port;
	hdr.to_addr = t->src_addr.sin_addr.s_addr;
	hdr.to_port = t->src_addr.sin_port;
	hdr.index = htons(expect_index);

	if (check_hdr(buf, ret, &hdr))
		die("header from %s:%u to id %u bogus\n",
		    inet_ntoa(sin.sin_addr), htons(sin.sin_port),
		    ntohs(t->src_addr.sin_port));

	if (hdr.op == OP_ACK) {
		stat_inc(&ctl->cur[S_RTT_USECS],
			 usec_sub(&tstamp, &t->send_time[expect_index]));
		t->pending -= 1;
	} else {
		t->unacked += 1;
		t->recv_index = (t->recv_index + 1) % opts->req_depth;
	}
	t->recv_seq++;

	return ret;
}

static void run_child(pid_t parent_pid, struct child_control *ctl,
		      struct options *opts, uint16_t id)
{
	struct sockaddr_in sin;
	struct pollfd pfd;
	int fd;
	uint16_t i;
	ssize_t ret;
	struct task tasks[opts->nr_tasks];
	struct timeval start;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(opts->starting_port + 1 + id);
	sin.sin_addr.s_addr = htonl(opts->receive_addr);

	memset(tasks, 0, sizeof(tasks));
	for (i = 0; i < opts->nr_tasks; i++) {
		tasks[i].src_addr = sin;
		tasks[i].dst_addr.sin_family = AF_INET;
		tasks[i].dst_addr.sin_addr.s_addr = htonl(opts->send_addr);
		tasks[i].dst_addr.sin_port = htons(opts->starting_port + 1 + i);
		tasks[i].send_time = alloca(opts->req_depth * sizeof(struct timeval));
	}

	fd = rds_socket(opts, &sin);

	ctl->ready = 1;

	while (ctl->start.tv_sec == 0) {
		check_parent(parent_pid);
		sleep(1);
	}

	/* sleep until we're supposed to start */
	gettimeofday(&start, NULL);
	if (tv_cmp(&start, &ctl->start) < 0)
		usleep(usec_sub(&ctl->start, &start));

	sin.sin_family = AF_INET;

	pfd.fd = fd;
	pfd.events = POLLIN | POLLOUT;
	while (1) {
		struct task *t;

		check_parent(parent_pid);

		ret = poll(&pfd, 1, -1);
		if (ret < 0)
			die_errno("poll failed");

		pfd.events = POLLIN;

		if (pfd.revents & POLLIN) {
			while (recv_one(fd, tasks, opts, ctl) >= 0)
				;
		}

		/* keep the pipeline full */
		for (i = 0, t = tasks; i < opts->nr_tasks; i++, t++) {
			while (t->unacked) {
				uint16_t qindex;

				qindex = (t->recv_index - t->unacked + opts->req_depth) % opts->req_depth;
				ret = send_ack(fd, t, qindex, opts, ctl);
				if (ret < 0) {
					pfd.events = POLLOUT;
					goto sendq_full;
				}
				t->unacked -= 1;
			}
			while (t->pending < opts->req_depth) {
				ret = send_one(fd, t, opts, ctl);
				if (ret < 0) {
					pfd.events = POLLOUT;
					goto sendq_full;
				}
			}
		}
sendq_full: ;
	}
}

static struct child_control *start_children(struct options *opts)
{
	struct child_control *ctl;
	pid_t parent = getpid();
	pid_t pid;
	size_t len;
	uint32_t i;

	len = opts->nr_tasks * sizeof(*ctl);
	ctl = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED,
		   0, 0);
	if (ctl == MAP_FAILED)
		die("mmap of %u child control structs failed", opts->nr_tasks);

	memset(ctl, 0, len);

	for (i = 0; i < opts->nr_tasks; i++) {
		pid = fork();
		if (pid == -1)
			die_errno("forking child nr %u failed", i);
		if (pid == 0) {
			opts->suppress_warnings = (i > 0);
			run_child(parent, ctl + i, opts, i);
			exit(0);
		}
		ctl[i].pid = pid;
	}

	for (i = 0; i < opts->nr_tasks; i++) {
		if (ctl[i].ready)
			continue;
		pid = waitpid(-1, NULL, WNOHANG);
		if (pid)
			die("child %u (pid %u) exited\n", i, pid);
		sleep(1);
		i--; /* try this child again */
	}

	return ctl;
}

static double avg(struct counter *ctr)
{
	if (ctr->nr)
		return (double)ctr->sum / (double)ctr->nr;
	else
		return 0.0;
}

static double throughput(struct counter *disp)
{
	return disp[S_REQ_TX_BYTES].sum + disp[S_REQ_RX_BYTES].sum +
		disp[S_ACK_TX_BYTES].sum + disp[S_ACK_RX_BYTES].sum;
}

void stat_snapshot(struct counter *disp, struct child_control *ctl,
		   uint16_t nr_tasks)
{
	struct counter tmp[NR_STATS];
	uint16_t i;
	uint16_t s;

	memset(disp, 0, sizeof(tmp));

	for (i = 0; i < nr_tasks; i++) {
		memcpy(tmp, ctl[i].cur, sizeof(tmp));

		for (s = 0; s < NR_STATS; s++) {
			disp[s].nr += tmp[s].nr - ctl[i].last[s].nr;
			disp[s].sum += tmp[s].sum - ctl[i].last[s].sum;
			disp[s].min = minz(tmp[s].min, ctl[i].last[s].min);
			disp[s].max = max(tmp[s].max, ctl[i].last[s].max);
		}

		memcpy(ctl[i].last, tmp, sizeof(tmp));
	}
}

void stat_accumulate(struct counter *accum, const struct counter *cur)
{
	uint16_t s;

	for (s = 0; s < NR_STATS; ++s, ++cur, ++accum) {
		accum->nr += cur->nr;
		accum->sum += cur->sum;
		accum->min = minz(accum->min, cur->min);
		accum->max = max(accum->max, cur->max);
	}
}

void stat_total(struct counter *disp, struct child_control *ctl,
		uint16_t nr_tasks)
{
	uint16_t i;
	uint16_t s;

	memset(disp, 0, sizeof(struct counter) * NR_STATS);

	for (i = 0; i < nr_tasks; i++) {
		for (s = 0; s < NR_STATS; s++) {
			disp[s].nr += ctl[i].cur[s].nr;
			disp[s].sum += ctl[i].cur[s].sum;
			disp[s].min = minz(disp[s].min, ctl[i].cur[s].min);
			disp[s].max = max(disp[s].max, ctl[i].cur[s].max);
		}
	}
}

static double cpu_use(struct soak_control *soak_arr)
{
	struct soak_control *soak;
	uint64_t capacity = 0;
	uint64_t soaked = 0;
	uint64_t this;

	if (soak_arr == NULL)
		return -1.0;

	for (soak = soak_arr; soak && soak->per_sec; soak++) {
		capacity += soak->per_sec;
		this = soak->counter;
		soaked += min(soak->per_sec, this - soak->last);
		soak->last = this;
	}

	return (double)(capacity - soaked) * 100 / (double)capacity;
}

static int reap_one_child(int wflags)
{
	pid_t pid;
	int status;

	pid = waitpid(-1, &status, wflags);
	if (pid < 0)
		die("waitpid returned %u", pid);
	if (pid == 0)
		return 0;

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) == 0)
			return 1;
		die("child pid %u exited with status %d\n",
				pid, WEXITSTATUS(status));
	}
	if (WIFSIGNALED(status)) {
		if (WTERMSIG(status) == SIGTERM)
			return 1;
		die("child pid %u exited with signal %d\n",
				pid, WTERMSIG(status));
	}
	die("child pid %u wait status %d\n", pid, status);
}

static void release_children_and_wait(struct options *opts,
				      struct child_control *ctl,
				      struct soak_control *soak_arr)
{
	struct counter disp[NR_STATS];
	struct counter summary[NR_STATS];
	struct timeval start, end, now, first_ts, last_ts;
	double cpu_total = 0;
	uint16_t i, cpu_samples = 0;
	uint16_t nr_running;

	gettimeofday(&start, NULL);
	start.tv_sec += 2;
	for (i = 0; i < opts->nr_tasks; i++)
		ctl[i].start = start;

	/* Allow for a 4 second delay: 2 seconds for the children
	 * to come up, and 2 more of burn-in time
	 */
	printf("Starting up"); fflush(stdout);
	for (i = 0; i < 4; ++i) {
		sleep(1);
		stat_snapshot(disp, ctl, opts->nr_tasks);
		cpu_use(soak_arr);
		printf(".");
		fflush(stdout);
	}
	printf("\n");

	gettimeofday(&first_ts, NULL);
	if (opts->run_time) {
		end = first_ts;
		end.tv_sec += opts->run_time;
	} else {
		timerclear(&end);
	}

	nr_running = opts->nr_tasks;
	memset(summary, 0, sizeof(summary));

	printf("%4s %6s %10s %7s %8s %5s\n",
		"tsks", "tx/s", "tx+rx K/s", "tx us/c", "rtt us", "cpu %");

	if (opts->rtprio)
		set_rt_priority();

	last_ts = first_ts;
	while (nr_running) {
		double cpu;

		sleep(1);

		/* XXX big bug, need to mark some ctl elements dead */
		stat_snapshot(disp, ctl, nr_running);
		gettimeofday(&now, NULL);
		cpu = cpu_use(soak_arr);

		if (!opts->summary_only) {
			double scale;

			/* Every loop takes a little more than one second;
			 * and system load can actually introduce latencies.
			 * So try to measure the actual time elapsed as precise
			 * as possible, and scale all values by its inverse.
			 */
			scale = 1e6 / usec_sub(&now, &last_ts);

			printf("%4u %6"PRIu64" %10.2f %7.2f %8.2f %5.2f\n",
				nr_running,
				disp[S_REQ_TX_BYTES].nr,
				scale * throughput(disp) / 1024.0,
				scale * avg(&disp[S_SENDMSG_USECS]),
				scale * avg(&disp[S_RTT_USECS]),
				scale * cpu);
		}

		stat_accumulate(summary, disp);
		cpu_total += cpu;
		cpu_samples++;
		last_ts = now;

		if (timerisset(&end)) {
			if (timercmp(&now, &end, >=)) {
				for (i = 0; i < opts->nr_tasks; i++)
					kill(ctl[i].pid, SIGTERM);
				stop_soakers(soak_arr);
				break;
			}
		}

		/* see if any children have finished or died.
		 * This is a bit touchy - we should really be
		 * able to tell an exited soaker from an exiting
		 * RDS child. */
		if (reap_one_child(WNOHANG))
			nr_running--;
	}

	while (nr_running && reap_one_child(0))
		nr_running--;

	stat_total(disp, ctl, opts->nr_tasks);
	if (!opts->summary_only)
		printf("---------------------------------------------\n");
	{
		double scale;

		scale = 1e6 / usec_sub(&last_ts, &first_ts);

		printf("%4u %6lu %10.2f %7.2f %8.2f %5.2f  (average)\n",
			opts->nr_tasks,
			(long) (scale * summary[S_REQ_TX_BYTES].nr),
			scale * throughput(summary) / 1024.0,
			avg(&summary[S_SENDMSG_USECS]),
			avg(&summary[S_RTT_USECS]),
			soak_arr? scale * cpu_total : -1.0);
	}
}	

static int active_parent(struct options *opts, struct soak_control *soak_arr)
{
	struct child_control *ctl;
	struct sockaddr_in sin;
	int fd;
	ssize_t ret;
	uint8_t ok;

	ctl = start_children(opts);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(opts->starting_port);
	sin.sin_addr.s_addr = htonl(opts->receive_addr);

	fd = bound_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sin);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(opts->starting_port);
	sin.sin_addr.s_addr = htonl(opts->send_addr);

	printf("connecting to %s:%u\n", inet_ntoa(sin.sin_addr),
		ntohs(sin.sin_port));

	if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)))
		die_errno("connect() failed");

	printf("connected to %s:%u\n", inet_ntoa(sin.sin_addr),
		ntohs(sin.sin_port));

	ret = write(fd, opts, sizeof(struct options));
	if (ret != sizeof(struct options))
		die_errno("option write returned %zd", ret);

	ret = read(fd, &ok, sizeof(ok));
	if (ret != sizeof(ok))
		die_errno("ok read returned %zd", ret);

	printf("negotiated options, tasks will start in 2 seconds\n");

	release_children_and_wait(opts, ctl, soak_arr);

	return 0;
}

static int passive_parent(uint32_t addr, uint16_t port,
			  struct soak_control *soak_arr)
{
	struct options remote, *opts = &remote;
	struct child_control *ctl;
	struct sockaddr_in sin;
	socklen_t socklen;
	int fd;
	ssize_t ret;
	uint8_t ok;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(addr);

	fd = bound_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sin);

	if (listen(fd, 255))
		die_errno("listen() failed");

	fd = accept(fd, (struct sockaddr *)&sin, &socklen);
	if (fd < 0)
		die_errno("accept() failed");

	printf("accepted connection from %s:%u\n", inet_ntoa(sin.sin_addr),
		ntohs(sin.sin_port));

	ret = read(fd, opts, sizeof(struct options));
	if (ret != sizeof(struct options))
		die_errno("remote option read returned %zd\n", ret);

	/* 
	 * The sender gave us their send and receive addresses, we need
	 * to swap them.
	 */
	opts->send_addr = opts->receive_addr;
	opts->receive_addr = addr;

	ctl = start_children(opts);

	ret = write(fd, &ok, sizeof(ok));
	if (ret != sizeof(ok))
		die_errno("remote option read returned %zd\n", ret);

	printf("negotiated options, tasks will start in 2 seconds\n");

	release_children_and_wait(opts, ctl, soak_arr);

	return 0;
}

/*
 * The soaker *constantly* spins calling getpid().  It tries to execute a
 * second's worth of calls before checking that it's parent is still alive.  It
 * uses gettimeofday() to figure out the per-second rate of the series it just
 * executed.  It always tries to work from the highest rate it ever saw.  
 */
static void run_soaker(pid_t parent_pid, struct soak_control *soak)
{
	uint64_t i;
	uint64_t per_sec;
	struct timeval start;
	struct timeval stop;
	uint64_t usecs;

	soak->per_sec = 1000;

	while (1) {
		gettimeofday(&start, NULL);
		for (i = 0; i < soak->per_sec; i++) {
			syscall(SYS_getpid);
			soak->counter++;
		}
		gettimeofday(&stop, NULL);

		usecs = usec_sub(&stop, &start);
		per_sec = (double)soak->per_sec * 1000000.0 / (double)usecs;

		if (per_sec > soak->per_sec)
			soak->per_sec = per_sec;

		check_parent(parent_pid);
	}
}

struct soak_control *start_soakers(void)
{
	struct soak_control *soak_arr;
	pid_t parent = getpid();
	pid_t pid;
	size_t len;
	long nr_soak = sysconf(_SC_NPROCESSORS_ONLN);
	long i;

	/* an extra terminating entry which will be all 0s */
	len = (nr_soak + 1) * sizeof(struct soak_control);
	soak_arr = mmap(NULL, len, PROT_READ|PROT_WRITE,
			MAP_ANONYMOUS|MAP_SHARED, 0, 0);
	if (soak_arr == MAP_FAILED)
		die("mmap of %ld soak control structs failed", nr_soak);

	memset(soak_arr, 0, len);

	printf("started %ld cycle soaking processes\n", nr_soak);

	for (i = 0; i < nr_soak; i++) {
		pid = fork();
		if (pid == -1)
			die_errno("forking soaker nr %lu failed", i);
		if (pid == 0) {
			run_soaker(parent, soak_arr + i);
			exit(0);
		}
		soak_arr[i].pid = pid;
	}

	return soak_arr;
}

void stop_soakers(struct soak_control *soak_arr)
{
	unsigned int i, nr_soak = sysconf(_SC_NPROCESSORS_ONLN);

	if (!soak_arr)
		return;
	for (i = 0; i < nr_soak; ++i) {
		kill(soak_arr[i].pid, SIGTERM);
		waitpid(soak_arr[i].pid, NULL, 0);
	}
}

void check_size(uint32_t size, uint32_t unspec, uint32_t max, char *desc,
		char *opt)
{
	if (size == ~0)
		die("specify %s with %s\n", desc, opt);
	if (size < max)
		die("%s must be at least %u bytes\n", desc, max);
}

int main(int argc, char **argv)
{
	struct options opts;
	struct soak_control *soak_arr = NULL;

	/* We really want to see output when we redirect
	 * stdout to a pipe. */
	setlinebuf(stdout);

	memset(&opts, 0xff, sizeof(opts));

	if (argc == 1)
		usage();

	opts.ack_size = MIN_MSG_BYTES;
	opts.req_size = 1024;
	opts.run_time = 0;
	opts.summary_only = 0;

        while(1) {
		int c;

                c = getopt(argc, argv, "+a:cd:hp:q:Rr:s:t:T:z");
                if (c == -1)
                        break;

                switch(c) {
                        case 'a':
				opts.ack_size = parse_ull(optarg, (uint32_t)~0);
                                break;
                        case 'c':
				soak_arr = start_soakers();
                                break;
                        case 'd':
				opts.req_depth = parse_ull(optarg,(uint32_t)~0);
                                break;
                        case 'p':
				opts.starting_port = parse_ull(optarg,
							       (uint16_t)~0);
                                break;
                        case 'q':
				opts.req_size = parse_ull(optarg, (uint32_t)~0);
                                break;
			case 'R':
				opts.rtprio = 1;
				break;
                        case 'r':
				opts.receive_addr = parse_addr(optarg);
                                break;
                        case 's':
				opts.send_addr = parse_addr(optarg);
                                break;
                        case 't':
				opts.nr_tasks = parse_ull(optarg,
							  (uint16_t)~0);
                                break;
			case 'T':
				opts.run_time = parse_ull(optarg, (uint32_t)~0);
				break;
			case 'z':
				opts.summary_only = 1;
				break;
                        case 'h':
                        case '?':
                        default:
				usage();
				break;
                }
        }

	if (opts.starting_port == (uint16_t)~0)
		die("specify starting port with -p\n");
	if (opts.receive_addr == ~0)
		die("specify receiving addr with -r\n");

	/* the passive parent will read options off the wire */
	if (opts.send_addr == ~0)
		return passive_parent(opts.receive_addr, opts.starting_port,
				      soak_arr);

	/* the active parent verifies and sends its options */
	check_size(opts.ack_size, ~0, MIN_MSG_BYTES, "ack size", "-a");
	check_size(opts.req_size, ~0, MIN_MSG_BYTES, "req size", "-q");

	/* defaults */
	if (opts.req_depth == ~0)
		opts.req_depth = 1;
	if (opts.nr_tasks == (uint16_t)~0)
		opts.nr_tasks = 1;

	return active_parent(&opts, soak_arr);
}

/*
 * This are completely stupid.  options.c should be removed.
 */
void print_usage(int durr) { }
void print_version() { }
