%define	name	gtime

%define _unpackaged_files_terminate_build 0

Summary: Command-line access to Guardtime Keyless Signature services
Name: %{name}
Version: 1.0
%define upstream_release 12
Release: 0%{dist} 
Source:  http://download.guardtime.com/%{name}-%{version}-%{upstream_release}.tar.gz
License: Apache 2.0
Group: Applications/Security
URL: http://www.guardtime.com/
Vendor: Guardtime
Packager: Guardtime <info@guardtime.com>
Distribution: Guardtime utilities
BuildRoot: %{_tmppath}/%{name}-%{version}-%{upstream_release}-build

Requires: openssl, curl, libgtbase
%if 0%{?fedora} || 0%{?rhel_version} || 0%{?centos_version}
BuildRequires:  openssl-devel
%else
BuildRequires:  libopenssl-devel
%endif
%if 0%{?fedora} || 0%{?rhel_version} > 599 || 0%{?centos_version} > 599 || 0%{?suse_version} >= 1100
BuildRequires:  libcurl-devel
%else
BuildRequires:  curl-devel
%endif
BuildRequires: libgt-devel

%description
Guardtime signing and verification tool. Execute 
gtime -h
to view brief usage instructions.

%prep
%setup -q -n %{name}-%{version}-%{upstream_release}

%build
%configure
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install


%files
%defattr (-,root,root)

/usr/bin/gtime*
/usr/share/doc/gtime/*
/usr/share/man/man1/gtime.1.gz
/usr/share/man/man1/gtime-test.1.gz

%changelog

