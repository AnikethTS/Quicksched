#!/bin/bash
# Install build dependencies for scx_quicksched on the current distro.
# Must be run as root (or with sudo).
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root or with sudo" >&2
    exit 1
fi

if [ ! -f /etc/os-release ]; then
    echo "error: cannot detect distro (no /etc/os-release)" >&2
    exit 1
fi

. /etc/os-release
DISTRO="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"

# Resolve to a canonical family even when the ID is a derivative
family() {
    for id in "$DISTRO" $DISTRO_LIKE; do
        case "$id" in
            ubuntu|debian|linuxmint|pop|elementary|zorin|kali|raspbian)
                echo debian; return ;;
            fedora)
                echo fedora; return ;;
            rhel|centos|almalinux|rocky|ol|scientific)
                echo rhel; return ;;
            arch|manjaro|endeavouros|garuda|artix)
                echo arch; return ;;
            opensuse*|sles|sle)
                echo opensuse; return ;;
        esac
    done
    echo unknown
}

FAMILY=$(family)
echo "Detected distro: $PRETTY_NAME (family: $FAMILY)"

case "$FAMILY" in

  debian)
    apt-get update -qq
    apt-get install -y \
        clang gcc make pkg-config \
        libbpf-dev libncurses-dev \
        clang-format
    # bpftool lives in a kernel-version package on Ubuntu/Debian
    KVER=$(uname -r)
    apt-get install -y "linux-tools-${KVER}" 2>/dev/null || \
    apt-get install -y linux-tools-generic 2>/dev/null || \
    apt-get install -y bpftool 2>/dev/null || \
    echo "warning: bpftool not found — install manually if needed"
    ;;

  fedora)
    dnf install -y \
        clang gcc make pkgconf-pkg-config \
        libbpf-devel ncurses-devel \
        bpftool clang-tools-extra
    ;;

  rhel)
    # EPEL needed for bpftool and libbpf-devel on older RHEL/CentOS
    dnf install -y epel-release 2>/dev/null || true
    dnf install -y \
        clang gcc make pkgconf-pkg-config \
        libbpf-devel ncurses-devel \
        bpftool clang-tools-extra
    ;;

  arch)
    pacman -Sy --noconfirm \
        clang gcc make pkgconf \
        libbpf ncurses \
        bpf clang
    ;;

  opensuse)
    zypper install -y \
        clang gcc make pkg-config \
        libbpf-devel ncurses-devel \
        bpftool clang-tools
    ;;

  *)
    echo "Unsupported distro: $DISTRO" >&2
    echo "Please install manually: clang gcc make pkg-config libbpf-dev libncurses-dev bpftool" >&2
    exit 1
    ;;

esac

echo ""
echo "All dependencies installed. Run 'make' to build."
