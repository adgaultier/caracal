[Back to Readme](../README.md)

### Pid hiding
Based on:
- https://eunomia.dev/tutorials/24-hide/
- https://www.acceis.fr/ebpf-in-practice-pid-concealment-part-2/

It's a simple implementation in rust of this code.<br>
Tracepoints are hooked on  `getdents64` syscall


### Bpf objects hiding
Tracepoints are hooked on `bpf` syscall.<br>

-> When bpf command `cmd` is `BPF_(PROG|MAP)_GET_NEXT_ID` (meaning we want to list all bpf objects, maps or programs), we make sure to return full list of bpf objects, minus the bpf objects we are hiding. It is done by tampering with `bpf_attr` structure. It is very similar to what is done with `getdents64` <br>

-> When bpf command is  `BPF_(PROG|MAP)_GET_FD_BY_ID` and targets a hidden object we replace queried object id with `u32::MAX` so it wont be found