#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{
        bpf_attr,
        bpf_cmd::{self, Type},
    },
    helpers::bpf_probe_read,
    macros::{kprobe, map, tracepoint},
    maps::HashMap,
    programs::{ProbeContext, TracePointContext},
    EbpfContext,
};
use aya_log_ebpf::info;

#[map]
static PROG_SKIP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(16, 0);
#[inline]
fn ptr_at<T>(start: usize, offset: usize) -> Result<*const T, ()> {
    Ok((start + offset) as *const T)
}

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
    let ptr = ctx.as_ptr();

    let cmd = unsafe { *((ptr.wrapping_add(16)) as *const i64) };
    info!(&ctx, "cmd: {} ", cmd);

    // if cmd == bpf_cmd::BPF_PROG_GET_NEXT_ID.into() {
    //     let prog_attr = (ptr.wrapping_add(24)) as *const bpf_attr;

    //     let prog_id = unsafe { (*prog_attr).__bindgen_anon_6.__bindgen_anon_1.prog_id };

    //     info!(&ctx, " prog:{}", prog_id);
    // }

    Ok(0)
}

#[kprobe]
fn stealth_probe(ctx: ProbeContext) -> Result<u32, u32> {
    let start_id: *const u32 = ctx.arg(0).ok_or(1u32)?;
    //let cmd: *const Type = ctx.arg(2).ok_or(1u32)?;
    let start_id = unsafe { bpf_probe_read(start_id).map_err(|_| 1u32)? };
    //let cmd = unsafe { bpf_probe_read(cmd).map_err(|_| 1u32)? };

    info!(&ctx, "start id {}   ", start_id);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
