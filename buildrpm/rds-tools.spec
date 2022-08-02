%define RELEASE 1
%{?el7:%define uektag uek4}

Name:		rds-tools
Summary:	RDS support tools 
Version:	2.3.7
Release:	%{RELEASE}%{?dist}%{?uektag}
License:	GPLv2 or BSD
Group:		Applications/System
URL:		https://github.com/oracle/%{name}
Source0:	%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
ExcludeArch:	s390 s390x

%description
Various tools for support of the RDS (Reliable Datagram Socket) API.  RDS
is specific to InfiniBand and iWARP networks and does not work on non-RDMA
hardware.

%package -n rds-devel
Summary: Header files for RDS development
Group: Development/Libraries

%description -n rds-devel
Header file and manpages for rds and rds-rdma that describe
how to use the socket interface.

%prep
%setup -q

%build
%configure
make CFLAGS="$CFLAGS -Iinclude" %{?_smp_mflags}

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install


%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc docs examples
%{_bindir}/*
%{_mandir}/*/*

%files -n rds-devel
%{_includedir}/*
%{_mandir}/*/*
%doc README docs examples

%changelog
* Tue Aug 02 2022 Mark Haywood <mark.haywood@oracle.com> - 2.3.7-1
- Revert "rds-stress: add transport option" (Mark Haywood) [Orabug: 34334685]
- rds-stress: Remove "cancel-sent-to"/"abort-after" as negotiated options (Mark Haywood) [Orabug: 34390186]

* Wed Jul 13 2022 Mark Haywood <mark.haywood@oracle.com> - 2.3.6-1
- rds-stress: Add options "cancel-sent-to" + "abort-after"(Gerd Rausch) [Orabug: 34290668]
- rds-info: Userspace change to display congested socket on rds-info -k (Rohit Nair) [Orabug: 34281731]
- rds-ping: add transport option (Rohit Nair) [Orabug: 34325392]
- rds-stress: add transport option (Rohit Nair) [Orabug: 34334685]

* Tue Mar 08 2022 Mark Haywood <mark.haywood@oracle.com> - 2.3.5-1
- rds-info: Add pid and comm fields to rds-info (Rohit Nair) [Orabug: 33505033]
- rds-info: Fixed missing documentation for rds-info -I (Rohit Nair) [Orabug: 33771195]
- rds-info: extend rds-info -Iv functionality (Rohit Nair) [Orabug: 33754436]

* Thu Apr 08 2021 Mark Haywood <mark.haywood@oracle.com> - 2.3.4-1
- rds-stress: Add long option syntax to usage output (Mark Haywood) [Orabug: 32229141]
- rds-stress: Add long options for the options missing them (Mark Haywood) [Orabug: 32229207]
- rds-stress: Fix usage to match getopt options (Mark Haywood) [Orabug: 32229225]

* Mon Nov 16 2020 Mark Haywood <mark.haywood@oracle.com> - 2.3.3-1
- rds-stress: Fix compiler warnings (Manjunath Patil) [Orabug: 31393110]
- rds-info: Display destination qp number (Praveen Kumar Kannoju) [Orabug: 31940569]
- rds-tools: Added '-p' option to rds-info to show paths (Rao Shoaib) [Orabug: 31991789]

* Fri May 22 2020 Mark Haywood <mark.haywood@oracle.com> - 2.3.2-2
- rds-tools: Update URL and Source tags in the spec (Mark Haywood) [Orabug: 30847027]

* Tue Mar 03 2020 Mark Haywood <mark.haywood@oracle.com> - 2.3.2-1
- rds-stress: SIGSEGV on OL8 when running IPv4 (Mark Haywood) [Orabug: 30935289]]

* Mon Feb 03 2020 Mark Haywood <mark.haywood@oracle.com> - 2.3.1-1
- rds-info: error messages need context (Mark Haywood) [Orabug 30822264]

* Fri Jan 10 2020 Mark Haywood <mark.haywood@oracle.com> - 2.3.0-2
- rds-ping: Allow rds-ping to set the number of RDS sockets used (Ka-Cheong Poon) [Orabug: 30375512]
- rds-tools: avoid netlink calls in getaddrinfo (Wengang Wang) [Orabug: 30652283]

* Thu Jan 17 2019 Aron Silverton <aron.silverton@oracle.com> - 2.2.0-1
- rds-info: Display QP Number (Divya Indi) [Orabug: 29201281]

* Fri May 18 2018 Aron Silverton <aron.silverton@oracle.com> - 2.1.1-2
- Add "uek4" token for OL7 package builds (Aron Silverton) [Orabug: 27934606]

* Thu Apr 19 2018 Aron Silverton <aron.silverton@oracle.com> - 2.1.1-1
- rds-stress: Continue sending for other tasks when one task fails (Avinash Repaka) [Orabug: 23093216]
- rds-stress: SW fence for RDMA Rd when HW fence is disabled (Shamir Rabinovitch) [Orabug: 27154692]

* Wed Apr 18 2018 Aron Silverton <aron.silverton@oracle.com> - 2.1.0-1
- Fix package version (Aron Silverton) [Orabug: 27887569]

* Fri Jan 19 2018 Aron Silverton <aron.silverton@oracle.com> - 2.0.7-1.19
- Add support for IPv6 (Ka-Cheong Poon) [Orabug: 26646596]

* Fri Jul 08 2016 Mukesh Kacker <mukesh.kacker@oracle.com> - 2.0.7-1.18
- Delete reference to experimental features in man pages

* Tue Jun 07 2016 Guanglei Li <guanglei.li@oracle.com> - 2.0.7-1.17
- Change rds-stress memory allocation to heap [orabug: 23312910]

* Tue Mar 01 2016 Qing Huang <qing.huang@oracle.com> - 2.0.7-1.16
- Consolidate changes from x86 and sparc [orabug: 22862753]

* Thu Nov 19 2015 Wengang Wang <wen.gang.wang@oracle.com> - 2.0.7-1.15
- Correct SOL_RDS & PF_RDS in rds-sample [orabug: 22190972]

* Tue Oct 27 2015 Shamir Rabinovitch <shamir.rabinovitch@oracle.com> - 2.0.7-1.14
- Orabug: 21873217

* Mon Oct 26 2015 Lidza Louina <lidza.louina@oracle.com> - 2.0.7-1.13.el5
- Adds --E to rds-info manpage.

* Fri Sep 13 2013 Bang Nguyen <bang.nguyen@oracle.com> - 2.0.7-1.12.el5
- Support backward compatibility (2.0.7 <-> 2.0.6)

* Mon Aug 12 2013 Chien-Hua Yen <chien.eyn@oracle.com> - 2.0.7-1.11.el5
- Add rds-devel rpm

* Thu Jul 18 2013 Bang Nguyen <bang.nguyen@oracle.com> - 2.0.7-1.10.el5
- Don't check for msg_namelen for Control msgs

* Tue Jun 25 2013 Bang Nguyen <bang.nguyen@oracle.com> - 2.0.7-1.9.el5
- Fix stuck rds-ping

* Thu Jun  6 2013 Bang Nguyen <bang.nguyen@oracle.com> - 2.0.7-1.8.el5
- Wait for PONG on initial PING

* Wed May 29 2013 Joe Jin <joe.jin@oracle.com> - 2.0.7-1.7.el5
- Don't show histogram data if no --show-histogram [orabug 16870737]

* Thu Mar 21 2013 Bang Nguyen <bang.nguyen@oracle.com> - 2.0.7-1.6.el5
- Remove rds.conf

* Tue Feb 26 2013 Bang Nguyen <bang.nguyen@oracle.com> - 2.0.7-1.5.el5
- Remove RDS_RDMA_REMOTE_COMPLETE

* Fri Feb 22 2013 Bang Nguyen <bang.nguyen@oracle.com> - 2.0.7-1.3.el5
- support QoS, Async send, connection reset and etc.
