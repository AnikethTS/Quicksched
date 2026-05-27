use std::env;
use std::fs::File;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let vmlinux = out_dir.join("vmlinux.h");

    let f = File::create(&vmlinux).expect("failed to create vmlinux.h");
    let status = Command::new("bpftool")
        .args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
        .stdout(f)
        .status()
        .expect("bpftool not found");
    assert!(status.success(), "bpftool btf dump failed");

    let skel_out = out_dir.join("scx_snap.skel.rs");
    libbpf_cargo::SkeletonBuilder::new()
        .source("src/bpf/scx_snap.bpf.c")
        .clang_args([
            format!("-I{}", out_dir.display()),
            "-I/usr/include".to_string(),
        ])
        .build_and_generate(&skel_out)
        .expect("BPF build failed");

    println!("cargo:rerun-if-changed=src/bpf/scx_snap.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/scx_snap.h");
}
