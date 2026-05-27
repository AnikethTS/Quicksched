use std::{
    mem::{self, MaybeUninit},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore, MapFlags, OpenObject,
};
use plain::Plain;

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/scx_snap.skel.rs"));
}
use bpf::*;

#[derive(Parser, Debug)]
#[command(
    name = "scx_snap",
    about = "Latency-optimized sched_ext scheduler",
    long_about = "Prioritizes interactive tasks (UI, audio, input) over batch work. \
                  Tasks are classified by nice value and observed sleep ratio."
)]
struct Args {
    /// Interactive task time slice (µs)
    #[arg(short = 'i', long, default_value = "5000")]
    interactive_slice_us: u64,

    /// Batch task time slice (µs)
    #[arg(short = 'b', long, default_value = "20000")]
    batch_slice_us: u64,

    /// Tasks with nice <= this are always treated as interactive
    #[arg(short = 'n', long, default_value = "0")]
    nice_interactive_max: i32,

    /// Minimum sleep percentage to classify a task as interactive
    #[arg(short = 'p', long, default_value = "50")]
    interactive_sleep_pct: u32,

    /// Stats interval in seconds (0 to disable)
    #[arg(short = 's', long, default_value = "1")]
    stats_interval: u64,

    #[arg(short = 'v', long)]
    verbose: bool,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SnapStats {
    nr_interactive: u64,
    nr_batch: u64,
    nr_local: u64,
}

unsafe impl Plain for SnapStats {}

fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .init();

    if args.interactive_sleep_pct > 100 {
        bail!("--interactive-sleep-pct must be between 0 and 100");
    }

    let mut skel_builder = ScxSnapSkelBuilder::default();
    if args.verbose {
        skel_builder.obj_builder.debug(true);
    }

    let mut open_object = MaybeUninit::<OpenObject>::uninit();
    let mut open_skel = skel_builder
        .open(&mut open_object)
        .context("failed to open BPF object")?;

    let rd = open_skel
        .maps
        .rodata_data
        .as_mut()
        .context("rodata not available")?;
    rd.slice_interactive_ns  = args.interactive_slice_us * 1_000;
    rd.slice_batch_ns        = args.batch_slice_us * 1_000;
    rd.nice_interactive_max  = args.nice_interactive_max;
    rd.interactive_sleep_pct = args.interactive_sleep_pct;

    let skel = open_skel.load().context("failed to load BPF object")?;

    log::info!("scx_snap started");
    log::info!(
        "slices: interactive={}us batch={}us",
        args.interactive_slice_us, args.batch_slice_us
    );
    log::info!(
        "interactive: nice <= {} or sleep >= {}%",
        args.nice_interactive_max, args.interactive_sleep_pct
    );

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || r.store(false, Ordering::Relaxed))?;
    }

    let mut prev = SnapStats::default();

    while running.load(Ordering::Relaxed) {
        if args.stats_interval == 0 {
            std::thread::sleep(Duration::from_millis(200));
            continue;
        }

        std::thread::sleep(Duration::from_secs(args.stats_interval));

        match read_stats(&skel) {
            Ok(cur) => {
                let d_int   = cur.nr_interactive.saturating_sub(prev.nr_interactive);
                let d_batch = cur.nr_batch.saturating_sub(prev.nr_batch);
                let d_local = cur.nr_local.saturating_sub(prev.nr_local);
                let total   = d_int + d_batch + d_local;

                if total > 0 {
                    log::info!(
                        "interactive={:6} batch={:6} idle-fast={:6} ({}% interactive)",
                        d_int, d_batch, d_local,
                        d_int * 100 / total,
                    );
                }
                prev = cur;
            }
            Err(e) => log::warn!("stats read failed: {e}"),
        }
    }

    log::info!("scx_snap exiting");
    drop(skel);
    Ok(())
}

fn read_stats(skel: &ScxSnapSkel) -> Result<SnapStats> {
    let key = 0u32.to_ne_bytes();
    let per_cpu = skel
        .maps
        .stats
        .lookup_percpu(&key, MapFlags::ANY)
        .context("percpu lookup failed")?
        .context("stats key missing")?;

    let mut agg = SnapStats::default();
    for cpu_bytes in &per_cpu {
        if cpu_bytes.len() < mem::size_of::<SnapStats>() {
            continue;
        }
        let mut s = SnapStats::default();
        plain::copy_from_bytes(&mut s, cpu_bytes).ok();
        agg.nr_interactive += s.nr_interactive;
        agg.nr_batch       += s.nr_batch;
        agg.nr_local       += s.nr_local;
    }
    Ok(agg)
}
