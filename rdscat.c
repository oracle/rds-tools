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

/*
 * todo:
 * 	make an argument that sizes reads and writes
 */

#define AF_RDS 32
#define PF_RDS AF_RDS
#define SOL_RDS 272
#define RDS_SNDBUF 2

#define die(fmt...) do {		\
	fprintf(stderr, fmt);		\
	exit(1);			\
} while (0)

static uint16_t parse_port(char *ptr)
{
	unsigned long port;
	char *endptr;

	port = strtoul(ptr, &endptr, 0);
	if (*ptr && !*endptr && port <= (uint16_t)~0)
		return port;

	die("invalid port '%s'\n", ptr);
}

static ssize_t parse_ssize_t(char *ptr)
{
	unsigned long long val;
	char *endptr;

	val = strtoull(ptr, &endptr, 0);
	if (*ptr && !*endptr && val <= SSIZE_MAX)
		return val;

	die("invalid ssize_t value '%s'\n", ptr);
}

static struct in_addr parse_addr(char *ptr)
{
	struct in_addr addr;
        struct hostent *hent;

        hent = gethostbyname(ptr);
        if (hent && 
            hent->h_addrtype == AF_INET &&
            hent->h_length == sizeof(addr.s_addr)) {
		memcpy(&addr.s_addr, hent->h_addr, sizeof(addr.s_addr));
		return addr;
	}

	die("invalid host name or dots-and-numbers ipv4 address '%s'\n", ptr);
}

static void byte_scale(double *value, char **units)
{
	char *unit[] = {"B", "KB", "MB", "GB", "TB"};
	int index;

	for(index = 0; *value > 1024; (*value) /= 1024)
		index++;

	*units = unit[index];
}

static void stats_report(size_t bytes)
{
	static struct timeval last;
	static double total;
	struct timeval now;
	char *units;

	total += bytes;
	gettimeofday(&now, NULL);

	if (now.tv_sec != last.tv_sec) {
		fprintf(stderr, "%f ", total);
		byte_scale(&total, &units);
		fprintf(stderr, "%f %s/s\n", total, units);
		total = 0;
		last = now;
	}
}

static void recv_loop(int fd, ssize_t msg_size)
{
	char bytes[msg_size];
	ssize_t len, ret;
	struct sockaddr_in from;
	struct iovec iov = {
		.iov_base = bytes,
		.iov_len = msg_size,
	};
	struct msghdr msg = {
		.msg_name = &from,
		.msg_namelen = sizeof(from),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};

	while (1) {
		ret = recvmsg(fd, &msg, 0);
		if (ret < 0)
			die("recvmsg failed: %d: %s\n",
			    errno, strerror(errno));
		if (ret == 0)
			break;
		len = ret;

		stats_report(ret);

		ret = write(STDOUT_FILENO, bytes, len);
		if (ret < 0) 
			die("write failed: %d: %s\n", errno, strerror(errno));
		if (ret != len)
			die("stdout write of %zd gave %zd\n", len, ret);
	}
}

static void send_loop(int fd, struct sockaddr_in *sin, ssize_t msg_size)
{
	char bytes[msg_size];
	ssize_t len, ret;
	struct iovec iov = {
		.iov_base = bytes,
	};
	struct msghdr msg = {
		.msg_name = sin,
		.msg_namelen = sizeof(*sin),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};


	while (1) {
		ret = read(STDIN_FILENO, bytes, msg_size);
		if (ret < 0)
			die("read from stdin failed: %d: %s\n",
			    errno, strerror(errno));
		if (ret == 0)
			break;
		len = ret;
		iov.iov_len = len;
		ret = sendmsg(fd, &msg, 0);
		if (ret < 0) 
			die("sendmsg failed: %d: %s\n", errno, strerror(errno));
		if (ret != len)
			die("sendmsg of %zd gave %zd\n", len, ret);

		stats_report(ret);
	}
}

#define DEFAULT_MSG_SIZE 4096
#define DEFAULT_BUF_SIZE (DEFAULT_MSG_SIZE * 4)

int main(int argc, char **argv)
{
	int fd, c;
	unsigned sending = 1;
	ssize_t msg_size = DEFAULT_MSG_SIZE;
	ssize_t buf_size = DEFAULT_BUF_SIZE;
	int debug = 0, optval;
	uint32_t u32val;
	struct sockaddr_in sin_src = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = INADDR_ANY,
		.sin_port = htons(0),
	};
	struct sockaddr_in sin_dest = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = INADDR_ANY,
		.sin_port = htons(0),
	};

        while(1) {
                c = getopt(argc, argv, "+Dlb:m:s:p:");
                if (c == -1)
                        break;

                switch(c) {
                        case 'D':
                                debug = 1;
                                break;
                        case 'l':
                                sending = 0;
                                break;
                        case 'b':
                                buf_size = parse_ssize_t(optarg);
                                break;
                        case 'm':
                                msg_size = parse_ssize_t(optarg);
                                break;
                        case 's':
				sin_src.sin_addr = parse_addr(optarg);
                                break;
                        case 'p':
				sin_src.sin_port = parse_port(optarg);
                                break;
                        case 'h':
                        case '?':
                        default:
                                printf("usage\n");
				exit(1);
				break;
                }
        }

	if (optind == argc)
		die("port argument required\n");

	if (optind < argc - 1) {
		if (sending)
			sin_dest.sin_addr = parse_addr(argv[optind]);
		else
			sin_src.sin_addr = parse_addr(argv[optind]);
	}

	if (sending)
		sin_dest.sin_port = htons(parse_port(argv[argc - 1]));
	else
		sin_src.sin_port = htons(parse_port(argv[argc - 1]));

	fd = socket(PF_RDS, SOCK_SEQPACKET, 0);
	if (fd < 0)
		die("socket failed: %d: %s\n", errno, strerror(errno));

	if (debug) {
		optval = 1;
		setsockopt(fd, SOL_SOCKET, SO_DEBUG, &optval, sizeof(optval));
	}

	u32val = buf_size;
	if (setsockopt(fd, SOL_RDS, RDS_SNDBUF, &u32val, sizeof(u32val)))
		die("couldnt set RDS_SNDBUF to %zd: %d: %s\n", buf_size, errno,
		    strerror(errno));

	if ((sin_src.sin_addr.s_addr != INADDR_ANY) &&
	     bind(fd, (struct sockaddr *)&sin_src, sizeof(sin_src)))
		die("bind failed: %d: %s\n", errno, strerror(errno));

	if (sending)
		send_loop(fd, &sin_dest, msg_size);
	else
		recv_loop(fd, msg_size);

	return 0;
}
