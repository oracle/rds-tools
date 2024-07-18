RDS (Reliable Datagram Sockets) Tools:
======================================

rds-tools repo contains utilities like rds-ping, rds-info, rds-stress used
with RDS sockets. Use help form each utilities for additional information
on the options one can use with them.


RDS (Reliable Datagram Sockets)
======================================

RDS are a high-performance, low-latency reliable connectionless protocol for
delivering datagrams. It provides reliable, ordered datagram delivery 
by using a single reliable connection between any two nodes in the cluster.
This allows applications to use a single socket to talk to any other process
in the cluster - so in a cluster with N processes you need N sockets, in contrast
to NxN if you use a connection-oriented socket transport like TCP.
RDS may be built over any transport that provides reliable datagram
delivery such as TCP or IB Verbs Reliable Connected connections.

From the application's point of view, the RDS connection is set up using
IP addresses that uniquely identify the sending and receiving nodes, and
16-bit port numbers to identify the RDS socket end-points at each node.
The RDS port space is entirely independent of TCP, UDP or any other
port-based protocol.


More details on addressing, socket interfaces, sysctls etc can be
found in Linux kernel documentation directory.
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/networking/rds.txt

Wire Specifications are located here:
https://oss.oracle.com/projects/rds/dist/documentation/rds-3.1-spec.html

== Short build instructions ==

	autoconf
	./configure
	make rpm

This should result in an rds-tools rpm which is versioned by the VERSION
in the Makefile and the subversion rev that was checked out.

## Contributing

This project welcomes contributions from the community. Before submitting a pull request, please [review our contribution guide](./CONTRIBUTING.md)

## Security

Please consult the [security guide](./SECURITY.md) for our responsible security vulnerability disclosure process

## License

Copyright (c) 2006, 2024 Oracle and/or its affiliates.
