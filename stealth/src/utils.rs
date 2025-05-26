use std::{collections::HashSet, fs::OpenOptions, io::Write, path::Path};

use anyhow::{anyhow, Error};
use aya::{
    programs::{ProgramInfo, TracePoint},
    Ebpf,
};
use libbpf_rs::query::{MapInfoIter, ProgInfoIter};

#[inline]
pub fn list_active_programs() -> Vec<u32> {
    let iter = ProgInfoIter::default();
    let mut active_programs = Vec::<u32>::new();
    for prog in iter {
        active_programs.push(prog.id);
    }
    active_programs
}
#[inline]
pub fn list_active_maps() -> Vec<u32> {
    let iter = MapInfoIter::default();
    let mut active_maps = Vec::<u32>::new();
    for prog in iter {
        active_maps.push(prog.id);
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

pub fn fetch_pids_map_ids(progs_info: Vec<ProgramInfo>) -> Result<BpfProgInfos, Error> {
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

pub fn get_parent_pid(pid: u32) -> u32 {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content =
        std::fs::read_to_string(&stat_path).expect("Failed to read /proc/<pid>/stat");
    let fields: Vec<&str> = stat_content.split_whitespace().collect();
    fields[3].parse::<u32>().expect("Invalid PPID format")
}
