Summary: A free Socks v4/v5 client implementation 
Name: dante
%define version 1.0.0-pre1
%define prefix /usr
Version: %{version}
Release: 1
Copyright: BSD-type
Group: Networking/Utilities
URL: http://www.inet.no/dante/
Source: ftp://ftp.inet.no/pub/socks/dante-%{version}.tar.gz
Buildroot: /var/tmp/dante-root


%description
Dante is a free implementation of the socks protocol (version 4 and 
version 5; rfc1928) which can be used as a firewall between networks. 
It is being developed by Inferno Nettverk A/S, a Norwegian software 
company. Commercial support is available. 

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

[ -f %{prefix}/sbin/sockd ] || exit 0
[ -f /etc/sockd.conf ] || exit 0

# See how we were called.
case "\$1" in
  start)
	# Start daemons.
	echo -n "Starting sockd: "
	daemon %{prefix}/sbin/sockd -D
	echo
	touch /var/lock/subsys/sockd
	;;
  stop)
	# Stop daemons.
	echo -n "Shutting down sockd: "
	killproc sockd
	echo
	rm -f /var/lock/subsys/sockd
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
CFLAGS="${RPM_OPT_FLAGS}" ./configure --prefix=%{prefix}
make

%install
rm -rf ${RPM_BUILD_ROOT}
make install DESTDIR=${RPM_BUILD_ROOT}

#set library as executable - prevent ldd from complaining
chmod +x ${RPM_BUILD_ROOT}%{prefix}/lib/*.so.*.*

install -d ${RPM_BUILD_ROOT}/etc/rc.d/init.d ${RPM_BUILD_ROOT}%{prefix}/bin

install -m 644 example/socks.conf ${RPM_BUILD_ROOT}/etc
install -m 644 example/sockd.conf ${RPM_BUILD_ROOT}/etc

install -m 755 sockd.init ${RPM_BUILD_ROOT}/etc/rc.d/init.d/sockd

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%post server
/sbin/chkconfig --add sockd

%postun server
if [ $1 = 0 ]; then
   /sbin/chkconfig --del sockd
fi

%files
%defattr(-,root,root)
#files beginning with two capital letters are docs: BUGS, README.foo etc.
%doc [A-Z][A-Z]*
%{prefix}/lib/libsocks.so.0.0.9
%{prefix}/lib/libsocks.so.0
%{prefix}/lib/libsocks.so
%{prefix}/lib/libdsocks.so.0.0.9
%{prefix}/lib/libdsocks.so.0
%{prefix}/lib/libdsocks.so
%{prefix}/bin/socksify
%{prefix}/man/man5/socks.conf.5
%config /etc/socks.conf

%files server
%defattr(-,root,root)
%{prefix}/man/man8/sockd.8
%{prefix}/sbin/sockd
%{prefix}/man/man5/sockd.conf.5
%config /etc/sockd.conf
%config /etc/rc.d/init.d/sockd

%files devel
%{prefix}/lib/libsocks.la
%{prefix}/lib/libsocks.a
%{prefix}/lib/libdsocks.la

%changelog
* Wed Mar 10 1999 Karl-Andre' Skevik <karls@inet.no>
- Integrated into CVS
- socksify patch no longer needed

* Thu Mar 04 1999 Oren Tirosh <oren@hishome.net>
- configurable %{prefix}, fixed daemon init script 
- added /lib/libdl.so to socksify

* Wed Mar 03 1999 Oren Tirosh <oren@hishome.net>
- First spec file for Dante
