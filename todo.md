### user_space:
- load needed ebpf programs, plus the 3 listed below
- fetch current pid with whatever method => loader_pid
- from loader_pid get loader filedescriptor => loader_fd
- from loader_fd get all ebpf programs ids loaded and their maps id => bpf_prog_ids[] bpf_maps_ids[]
- communicate it with maps to the ebpfs program listed below 

### ebpf:
- pid_hider: 
    access to map with pids to hide
    use whatever method provided by bad_bpf
- ebpf_program_hider:
    access to map with program ids to hide: bpf_prog_ids[]
    attached to BPF_PROG_GET_NEXT_ID syscall 
    When expected return is equal to one of bpf_prog_ids[] (e.g. `hidden_id`), we want to send back the result of a new syscall BPF_PROG_GET_NEXT_ID with `hidden_id` as argument. 
    For that we use the process that has loaded the program, as a proxy, because ebpf prog cannot perform syscall on its own. 
    Steps:
    - transmit via a map to userspace a notification to execute  syscall BPF_PROG_GET_NEXT_ID  with `hidden_id` , and output the result in another map
    - read this map in ebpf prog and return the output
    - if the output is another id listed in bpf_prog_ids[] , the operation is repeated, as many times as needed
    
- ebpf_map_hider:
  access to map with maps ids to hide: bpf_maps_ids
  same as ebpf program hider but with BPF_MAP_GET_NEXT_ID syscallq