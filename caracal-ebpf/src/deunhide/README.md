
[Back to Readme](../../../README.md)

Based by : https://www.unhide-forensics.info/


Here the goal is to counter brute force methods <br>
It's a WIP, here we can test new methods on a hidden process with [tests](#tests)

### Tracepoints
Hooked on syscalls:
- sys_enter_statx
- sys_enter_newfstatat
- sys_enter_chdir
- sys_enter_openat

-> If syscall targets a hidden pid , we replace the filename pointer with a null byte, which will then trigger a `-ESRCH` error in the downstream functions executions

### Kprobes 
> ⚠️ available only on x86_64

> ⚠️ will be activated only if host has `CONFIG_BPF_KPROBE_OVERRIDE=y`

Hooked on "__x64" syscalls generated functions:

- sys_kill (only triggered by kill -0)
- sys_getpgid
- sys_getsid
- sys_getpriority
- sys_sched_getparam
- sys_sched_getscheduler
- sched_rr_get_interval
- sched_getaffinity


-> If function targets  a hidden pid , we use `bpf_override_return` to replace the return with `-ESRCH`   


### Tests
#### Test script
Build:<br>
`gcc caracal-ebpf/src/deunhide/test.c -o test`<br>
Test:<br>
`sudo ./test <pid> ` on a  running pid <br>
You should obtain something like that:
```
stat /proc/157030 return 0
stat /proc/157030/status return 0
stat /chdir/157030 return 0
stat /chdir/157030/task return 0
sid return 0
getpgid return 0
kill return 0
sched_getparam return 0
sched_getscheduler return 0
sched_rr_get_interval return 0
getpriority return 0
```
Meaning each test detected the pid<br>

You can then run the test on a pid hidden by caracal (launch caracal with `RUST_LOG=info sudo -E caracal ..` to see the hidden pids in logs) and verify it only produces `-1` return codes, meaning it hasn't been detected.<br>
You can inspect with strace to confirm you get only -3 (process not found errors) 

### Unhide
You can also install and use [unhide](https://github.com/YJesus/Unhide) directly to run the bruteforce tests and verify no hidden pids has been detected