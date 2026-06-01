CC      := gcc
BPF_CC  := clang

UNAME_ARCH := $(shell uname -m)
ifeq ($(UNAME_ARCH),x86_64)
  BPF_ARCH := x86
else ifeq ($(UNAME_ARCH),aarch64)
  BPF_ARCH := arm64
else ifeq ($(UNAME_ARCH),armv7l)
  BPF_ARCH := arm
else ifeq ($(UNAME_ARCH),riscv64)
  BPF_ARCH := riscv
else ifeq ($(UNAME_ARCH),s390x)
  BPF_ARCH := s390
else
  BPF_ARCH := $(UNAME_ARCH)
endif

KVER := $(shell uname -r)

CFLAGS    := -O2 -g -Wall -Wextra
BPF_FLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -fno-stack-protector

# bpftool (from linux-tools) bundles libbpf 1.7 which generates skeletons with
# a 32-byte bpf_map_skeleton stride (4 fields, including link).  Ubuntu 24.04
# ships libbpf 1.3.0 whose binary still uses the old 24-byte stride, causing a
# segfault when the skeleton is opened.  Prefer the kernel-bundled libbpf.a
# (same version as bpftool) when the system copy is older than 1.4.
KLIBBPF_DIR := /usr/src/linux-headers-$(KVER)/tools/bpf/resolve_btfids/libbpf

# Version check: "yes" if system libbpf >= 1.4, else "no"
LIBBPF_VERSION_OK := $(shell \
  pkg-config --modversion libbpf 2>/dev/null | \
  awk -F. '{ok=($$1>1)||($$1==1&&$$2>=4); print (ok?"yes":"no")}')

ifeq ($(LIBBPF_VERSION_OK),yes)
  LIBBPF_CFLAGS  := $(shell pkg-config --cflags libbpf  2>/dev/null)
  LIBBPF_LDFLAGS := $(shell pkg-config --libs   libbpf  2>/dev/null || echo "-lbpf")
else ifneq ($(wildcard $(KLIBBPF_DIR)/libbpf.a),)
  LIBBPF_CFLAGS  := -I$(KLIBBPF_DIR)/include
  LIBBPF_LDFLAGS := $(KLIBBPF_DIR)/libbpf.a -lelf -lz -lzstd
else
  # System libbpf too old, no fallback available — proceed and warn at link time
  LIBBPF_CFLAGS  := $(shell pkg-config --cflags libbpf  2>/dev/null)
  LIBBPF_LDFLAGS := $(shell pkg-config --libs   libbpf  2>/dev/null || echo "-lbpf")
  $(warning System libbpf < 1.4 detected and no kernel-bundled fallback found.)
  $(warning Install linux-headers-$(KVER) or upgrade libbpf to fix a segfault on load.)
endif

NCURSES_CFLAGS  := $(shell pkg-config --cflags ncurses 2>/dev/null)
NCURSES_LDFLAGS := $(shell pkg-config --libs   ncurses 2>/dev/null || echo "-lncurses")

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
MANDIR  ?= $(PREFIX)/share/man/man1
UNITDIR ?= /lib/systemd/system

BUILDDIR      := build
VMLINUX       := $(BUILDDIR)/vmlinux.h
VMLINUX_STAMP := $(BUILDDIR)/.vmlinux-$(KVER).stamp
BPF_OBJ       := $(BUILDDIR)/scx_quicksched.bpf.o
SKEL_H        := $(BUILDDIR)/scx_quicksched.skel.h
TARGET        := scx_quicksched

.PHONY: all clean clean-full install uninstall check-deps

all: check-deps $(TARGET)

check-deps:
	@command -v $(BPF_CC) >/dev/null 2>&1 || \
		{ echo "error: clang not found — run: sudo scripts/install-deps.sh"; exit 1; }
	@command -v bpftool >/dev/null 2>&1 || \
		{ echo "error: bpftool not found — run: sudo scripts/install-deps.sh"; exit 1; }
	@pkg-config --exists libbpf 2>/dev/null || \
		{ echo "error: libbpf not found — run: sudo scripts/install-deps.sh"; exit 1; }
	@pkg-config --exists ncurses 2>/dev/null || \
		{ echo "error: ncurses not found — run: sudo scripts/install-deps.sh"; exit 1; }

$(BUILDDIR):
	mkdir -p $@

$(VMLINUX_STAMP): | $(BUILDDIR)
	@echo "Generating vmlinux.h for kernel $(KVER)"
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
	@find $(BUILDDIR) -name '.vmlinux-*.stamp' ! -name "$(notdir $(VMLINUX_STAMP))" \
		-delete 2>/dev/null; true
	@touch $@

$(VMLINUX): $(VMLINUX_STAMP)

$(BPF_OBJ): src/bpf/scx_quicksched.bpf.c src/bpf/scx_quicksched.h $(VMLINUX) | $(BUILDDIR)
	$(BPF_CC) $(BPF_FLAGS) $(LIBBPF_CFLAGS) -I$(BUILDDIR) -Isrc/bpf -I/usr/include -c $< -o $@

$(SKEL_H): $(BPF_OBJ) | $(BUILDDIR)
	bpftool gen skeleton $< > $@

$(TARGET): src/scx_quicksched.c src/bpf/scx_quicksched.h $(SKEL_H)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $(NCURSES_CFLAGS) \
		-D_DEFAULT_SOURCE -D_XOPEN_SOURCE=600 \
		-I$(BUILDDIR) -Isrc/bpf $< \
		$(LIBBPF_LDFLAGS) $(NCURSES_LDFLAGS) -o $@

install: $(TARGET)
	install -Dm755 $(TARGET)                          $(DESTDIR)$(BINDIR)/$(TARGET)
	install -Dm755 qs                                 $(DESTDIR)$(BINDIR)/qs
	install -Dm755 gui/quicksched-gui                 $(DESTDIR)$(BINDIR)/quicksched-gui
	install -Dm644 man/scx_quicksched.1               $(DESTDIR)$(MANDIR)/scx_quicksched.1
	install -Dm644 packaging/scx_quicksched.service   $(DESTDIR)$(UNITDIR)/scx_quicksched.service

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(BINDIR)/qs
	rm -f $(DESTDIR)$(BINDIR)/quicksched-gui
	rm -f $(DESTDIR)$(MANDIR)/scx_quicksched.1
	rm -f $(DESTDIR)$(UNITDIR)/scx_quicksched.service

clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(TARGET)

clean-full:
	rm -rf $(BUILDDIR) $(TARGET)
