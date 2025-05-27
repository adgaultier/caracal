#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[allow(unused_imports)]
use stealth_ebpf::{
    bpf::stealth_bpf,
    pid::{stealth_pid_enter, stealth_pid_exit},
};
