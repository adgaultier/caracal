#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[allow(unused_imports)]
use caracal_ebpf::{
    bpf::caracal_bpf,
    pid::{caracal_pid_enter, caracal_pid_exit},
};
