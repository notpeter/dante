Summary: A free Socks v4/v5 client implementation
Name: dante
%define version 1.1.7
%define prefix /usr
Version: %{version}
Release: 1
Copyright: BSD-type
Group: Networking/Utilities
URL: http://www.inet.no/dante/
Source: ftp://ftp.inet.no/pub/socks/dante-%{version}.tar.gz
Buildroot: %{_tmppath}/dante-root


%description
Dante is a free implementation of the proxy protocols socks version 4,
socks version 5 (rfc1928) and msproxy. It can be used as a firewall
between networks. It is being developed by Inferno Nettverk A/S, a
Norwegian consulting company. Commercial support is available.

This package contains the dynamic libraries required to "socksify"
existing applications to become socks clients.

%package server
Summary: A free Socks v4/v5 server implementation
Group: Networking/Daemons
Requires: dante

%description server
This package contains the socks proxy daemon and its documentation.
The sockd is the server part of the Dante socks proxy package and
allows socks clients to connect through it to the network.

%package devel
Summary: development libraries for socks
Group: Development/Libraries
Requires: dante

%description devel
Additional libraries required to compile programs that use socks.

%prep
%setup

# This file is embedded here instead of being another source in order
# to the prefix directory
cat >sockd.init <<EOF
#!/bin/sh
#
# sockd         This shell script takes care of starting and stopping
#               the Dante server.
#
# chkconfig: 2345 65 35
# description: sockd implements a socks v4/v5 proxy server

# Source function library.
. /etc/rc.d/init.d/functions

# Source networking configuration.
. /etc/sysconfig/network

# Check that networking is up.
[ \${NETWORKING} = "no" ] && exit 0

[ -f %{_sbindir}/sockd ] || exit 0
[ -f %{_sysconfdir}/sockd.conf ] || exit 0

# See how we were called.
case "\$1" in
  start)
	# Start daemons.
	echo -n "Starting sockd: "
	daemon %{_sbindir}/sockd -D
	echo
	touch %{_localstatedir}/lock/subsys/sockd
	;;
  stop)
	# Stop daemons.
	echo -n "Shutting down sockd: "
	killproc sockd
	echo
	rm -f ${_localstatedir}/lock/subsys/sockd
	;;
  restart)
	\$0 stop
	\$0 start
	;;
  status)
	status sockd
	;;
  *)
	echo "Usage: sockd {start|stop|restart|status}"
	exit 1
esac

exit 0
EOF

%build
CFLAGS="${RPM_OPT_FLAGS}" ./configure --prefix=%{prefix} --mandir=%{_mandir}
%{__make}

%install
%{__rm} -rf ${RPM_BUILD_ROOT}
%{__make} install DESTDIR=${RPM_BUILD_ROOT}

#set library as executable - prevent ldd from complaining
%{__chmod} +x ${RPM_BUILD_ROOT}%{prefix}/lib/*.so.*.*

%{__install}  -d ${RPM_BUILD_ROOT}/etc/rc.d/init.d ${RPM_BUILD_ROOT}%{prefix}/bin

%{__install} -m 644 example/socks-simple.conf ${RPM_BUILD_ROOT}/etc/socks.conf
%{__install} -m 644 example/sockd.conf ${RPM_BUILD_ROOT}/etc

%{__install} -m 755 sockd.init ${RPM_BUILD_ROOT}/etc/rc.d/init.d/sockd

%clean
%{__rm} -rf $RPM_BUILD_ROOT

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%post server
/sbin/chkconfig --add sockd

%preun server
if [ $1 = 0 ]; then
   /sbin/chkconfig --del sockd
fi

%files
%defattr(-,root,root)
%doc BUGS CREDITS INSTALL LICENSE NEWS README SUPPORT TODO doc/README* doc/rfc* doc/SOCKS4.protocol doc/faq.tex example/socks.conf example/socks-simple-withoutnameserver.conf example/sockd.conf example/socks-simple.conf
%{_libdir}/libsocks.so.0.1.0
%{_libdir}/libsocks.so.0
%{_libdir}/libsocks.so
%{_libdir}/libdsocks.so.0.1.0
%{_libdir}/libdsocks.so.0
%{_libdir}/libdsocks.so
%{_bindir}/socksify
%{_mandir}/man5/socks.conf.5*
%config %{_sysconfdir}/socks.conf

%files server
%defattr(-,root,root)
%{_mandir}/man8/sockd.8*
%{_sbindir}/sockd
%{_mandir}/man5/sockd.conf.5*
%config %{_sysconfdir}/sockd.conf
%config %{_sysconfdir}/rc.d/init.d/sockd

%files devel
%{_libdir}/libsocks.la
%{_libdir}/libsocks.a
%{_libdir}/libdsocks.la
%{_includedir}/socks.h

%changelog
* Thu Oct 12 2000 Karl-Andre' Skevik <karls@inet.no>
-use of macros for directory locations/paths
-explicitly name documentation files
-run chkconfig --del before files are deleted on uninstall

* Wed Mar 10 1999 Karl-Andre' Skevik <karls@inet.no>
- Integrated into CVS
- socksify patch no longer needed

* Thu Mar 04 1999 Oren Tirosh <oren@hishome.net>
- configurable %{prefix}, fixed daemon init script
- added /lib/libdl.so to socksify

* Wed Mar 03 1999 Oren Tirosh <oren@hishome.net>
- First spec file for Dante
