use std::collections::HashSet;

use anyhow::{anyhow, Error};
use aya::{
    programs::{ProgramInfo, TracePoint},
    Ebpf,
};
use log::{info, warn};

/// Attaches probes.

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

impl<'a> Builder<'a> {
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
