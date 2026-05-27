CC        := gcc
BPF_CC    := clang
CFLAGS    := -O2 -g -Wall -Wextra
BPF_FLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -fno-stack-protector

BUILDDIR  := build
VMLINUX   := $(BUILDDIR)/vmlinux.h
BPF_OBJ   := $(BUILDDIR)/scx_snap.bpf.o
SKEL_H    := $(BUILDDIR)/scx_snap.skel.h
TARGET    := scx_snap

.PHONY: all clean

all: $(TARGET)

$(BUILDDIR):
	mkdir -p $@

$(VMLINUX): | $(BUILDDIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): src/bpf/scx_snap.bpf.c src/bpf/scx_snap.h $(VMLINUX) | $(BUILDDIR)
	$(BPF_CC) $(BPF_FLAGS) -I$(BUILDDIR) -Isrc/bpf -I/usr/include -c $< -o $@

$(SKEL_H): $(BPF_OBJ) | $(BUILDDIR)
	bpftool gen skeleton $< > $@
	# bpftool 7.7 generates code for libbpf 1.7 (map->link) but distro ships 1.3
	# We attach struct_ops manually so drop the auto-link line
	sed -i '/map->link = /d' $@

$(TARGET): src/scx_snap.c src/bpf/scx_snap.h $(SKEL_H)
	$(CC) $(CFLAGS) -I$(BUILDDIR) -Isrc/bpf $< -lbpf -o $@

clean:
	rm -rf $(BUILDDIR) $(TARGET)
