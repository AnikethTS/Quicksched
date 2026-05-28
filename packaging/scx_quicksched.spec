Name:           scx_quicksched
Version:        0.2.0
Release:        1%{?dist}
Summary:        Latency-optimized sched_ext CPU scheduler
License:        GPL-2.0-only
URL:            https://github.com/AnikethTS/Quicksched

Source0:        %{name}-%{version}.tar.gz

BuildRequires:  clang
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  pkgconf-pkg-config
BuildRequires:  libbpf-devel
BuildRequires:  ncurses-devel
BuildRequires:  bpftool
BuildRequires:  kernel-devel

Requires:       libbpf
Requires:       ncurses-libs

%description
Quicksched (scx_quicksched) is a BPF-based CPU scheduler built on the
sched_ext framework (kernel >= 6.12). It separates tasks into interactive
and batch tiers, giving latency-sensitive work short 5ms slices at full CPU
frequency while throttling background tasks to reduce power use.

Features: wakeup-driven preemption, per-CPU interactive DSQs, work-stealing,
memory-pressure demotion (PF_MEMALLOC), adaptive CPU frequency scaling,
slice-utilisation EWMA, and an ncurses TUI with live latency histograms.

Requires kernel >= 6.12 with CONFIG_SCHED_CLASS_EXT=y.

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
%make_install PREFIX=%{_prefix} UNITDIR=%{_unitdir}

%post
%systemd_post scx_quicksched.service

%preun
%systemd_preun scx_quicksched.service

%postun
%systemd_postun_with_restart scx_quicksched.service

%files
%license LICENSE
%doc README.md
%{_bindir}/scx_quicksched
%{_mandir}/man1/scx_quicksched.1*
%{_unitdir}/scx_quicksched.service

%changelog
* Wed May 28 2026 Aniketh T S <anikethtsts@gmail.com> - 0.2.0-1
- Initial RPM package
- Full rename to Quicksched/scx_quicksched
- BPF verifier fixes for kernel 6.17
- Work-stealing, CPU hotplug, adaptive cpuperf, per-CPU TUI, SLO alerting
