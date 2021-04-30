Summary: A free SOCKS v4/v5 client implementation
Name: dante
%define fullversion 1.4.3
%define prefix /usr
Prefix: %{prefix}
Version: 1.4.3
Release: 1%{?dist}
License: BSD-type
Group: Networking/Utilities
URL: http://www.inet.no/dante/
Vendor: Inferno Nettverk A/S
Source: ftp://ftp.inet.no/pub/socks/dante-%{fullversion}.tar.gz
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires: glibc-devel

BuildRequires: pam-devel
BuildRequires: bison
BuildRequires: flex

%description
Dante is a free implementation of the SOCKS proxy protocol, version 4,
and version 5 (rfc1928). It can be used as a firewall between
networks. It is being developed by Inferno Nettverk A/S, a Norwegian
consulting company. Commercial support is available.

This package contains the dynamic libraries required to "socksify"
existing applications, allowing them to automatically use the SOCKS
protocol.

%package server
Summary: A free SOCKS v4/v5 server implementation
Group: System Environment/Daemons
Requires: dante

%description server
This package contains "sockd", the SOCKS proxy daemon and its
documentation.  This is the server part of the Dante SOCKS proxy
package and allows SOCKS clients to connect through it to the external
network.

%package devel
Summary: development libraries for SOCKS
Group: Development/Libraries
Requires: dante

%description devel
Additional libraries required to compile programs that use SOCKS.

%prep
%setup -n dante-1.4.3

# This file is embedded here instead of being another source in order
# to the prefix directory
%{__cat} >sockd.init <<'EOF'
#!/bin/sh
#
# Init file for the Dante Socks server
#
# Written by Dag Wieers <dag@wieers.com>.
#
# chkconfig: 2345 65 35
# description: Dante SOCKS v4/v5 proxy server
#
# processname: sockd
# config: %{_sysconfdir}/sockd.conf
# pidfile: %{_localstatedir}/run/sockd.pid
# # NOTE: if running with user.privileged as non-root, manually create
# #       pidfile owned by the user.privileged user before starting sockd.
# #       e.g., 'touch /var/run/sockd.pid; chown sockd /var/run/sockd.pid'

source %{_initrddir}/functions
source %{_sysconfdir}/sysconfig/network

# Check that networking is up.
if test x"$NETWORKING" != x; then
    [ ${NETWORKING} = "no" ] && exit 1
fi

[ -x %{_sbindir}/sockd ] || exit 1
[ -r %{_sysconfdir}/sockd.conf ] || exit 1

RETVAL=0
prog="sockd"
progpath="%{_sbindir}/$prog"
desc="Dante Socks server"

start() {
    echo -n $"Starting $desc ($prog): "
    daemon $progpath -D
    RETVAL=$?
    echo
    [ $RETVAL -eq 0 ] && touch %{_localstatedir}/lock/subsys/$prog
    return $RETVAL
}

stop() {
    echo -n $"Shutting down $desc ($prog): "
    killproc $prog
    RETVAL=$?
    echo
    [ $RETVAL -eq 0 ] && rm -f %{_localstatedir}/lock/subsys/$prog
    return $RETVAL
}

restart() {
    stop
    start
}

reload() {
    echo -n $"Reloading $desc ($prog): "
    killproc $prog -HUP
    RETVAL=$?
    echo
}

case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  reload)
    reload
    ;;
  restart)
    stop
    start
    ;;
  condrestart)
    [ -e %{_localstatedir}/lock/subsys/$prog ] && restart
    RETVAL=$?
    ;;
  status)
    status $prog
    RETVAL=$?
    ;;
  *)
    echo $"Usage: $0 {start|stop|restart|reload|condrestart|status}"
    RETVAL=1
esac

exit $RETVAL
EOF

%build
#%serverbuild
%configure --without-glibc-secure \
  %{?_without_libwrap} \
  %{?_without_upnp} \
  %{?_extraflags}

%{__make}

%install
%makeinstall

#set library as executable - prevent ldd from complaining
%{__chmod} +x ${RPM_BUILD_ROOT}%{_libdir}/*.so.*.*
%{__install} -d ${RPM_BUILD_ROOT}/%{_initrddir} ${RPM_BUILD_ROOT}/%{_bindir}
%{__install} -d ${RPM_BUILD_ROOT}/%{_unitdir}
%{__install} -m 0644 example/socks-simple.conf ${RPM_BUILD_ROOT}/%{_sysconfdir}/socks.conf
%{__install} -m 0644 example/sockd.conf ${RPM_BUILD_ROOT}/%{_sysconfdir}
%{__install} -m 0755 sockd.init ${RPM_BUILD_ROOT}/%{_initrddir}/sockd
%{__install} -m 0644 SPECS/dante.service ${RPM_BUILD_ROOT}/%{_unitdir}/sockd.service

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
%defattr(-, root, root, 0755)
%doc BUGS CREDITS NEWS README SUPPORT doc/README* example/socks.conf example/socks-simple-withoutnameserver.conf example/sockd.conf example/socks-simple.conf
%config %{_sysconfdir}/socks.conf
%{_libdir}/libsocks.so.0.1.1
%{_libdir}/libsocks.so.0
%{_libdir}/libsocks.so
%{_libdir}/libdsocks.so
%{_bindir}/socksify
%{_mandir}/man1/socksify.1*
%{_mandir}/man5/socks.conf.5*

%files server
%defattr(-, root, root, 0755)
%config %{_sysconfdir}/sockd.conf
%config %{_initrddir}/sockd
%{_sbindir}/sockd
%{_mandir}/man5/sockd.conf.5*
%{_mandir}/man8/sockd.8*
%{_unitdir}/sockd.service

%files devel
%defattr(-, root, root, 0755)
%doc INSTALL doc/rfc* doc/SOCKS4.protocol
%{_libdir}/libsocks.la
%{_libdir}/libsocks.a
%{_libdir}/libdsocks.la
%{_includedir}/socks.h

%changelog
* Tue Jul  21 2015 Karl-Andre' Skevik <karls@inet.no>
-Add glibc-devel Requires entry for librt, used by socksify.
 Noted by ealogar@gmail.com.

* Sun Feb  3 2013 Karl-Andre' Skevik <karls@inet.no>
-Add reload() and comment about pidfile creation when starting as non-root.

* Tue May 10 2011 Karl-Andre' Skevik <karls@inet.no>
-Integrate some changes from Dag Wieers spec file at:
 http://svn.rpmforge.net/svn/trunk/rpms/dante/dante.spec

* Sat Dec 19 2009 Karl-Andre' Skevik <karls@inet.no>
-Minor tweaking for fedora + add socksify manual page.

* Wed Mar 26 2003 Karl-Andre' Skevik <karls@inet.no>
-Integrated changes from spec file by <dag@wieers.com>, located
 at <URL:ftp://dag.wieers.com/home-made/dante/dante.spec>.

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
