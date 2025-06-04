<div align="center">
  <h1>Caracal</h1>
  <h3>Make your (eBPF🐝)  programs stealthier </h3>
  <img src="https://github.com/user-attachments/assets/089060da-1a14-475d-8aa3-e1bfae15e8f7" style="width: 60%; height: auto;">
    <p><small><i>The caracal cat is one of Africa's ultimate hunters,<br> a stealthy cat with an exceptional ability to hunt out prey on the savanna</i></small></p>

</div>


Caracal is a rust implementation of known eBPF techniques that: 
- hide target bpf programs & maps   → won't be visible with `bpftop`, `bpftool` ...
- hide target procesess             → won't be visible with `ps`, `top`, `procs`, `ls /proc` ...

<br>

It targets specifically `bpf` and `getdents64` syscalls



## 🚀 Setup

You need a Linux based OS.

### ⚒️ Build from source

To build from source, make sure you have:

- [bpf-linker](https://github.com/aya-rs/bpf-linker) installed.
- [rust](https://www.rust-lang.org/tools/install) installed with `nightly` toolchain.


#### 1. Build ebpf program

```
cd caracal-ebpf && cargo build  --release
```

#### 2. Build user space program
```
cargo build --release 
```
This command will produce  `caracal` executable in `target/release` that you can add to your`$PATH`


### 📥 Binary release

You can download the pre-built binaries from the release page [release page](https://github.com/adgaultier/caracal/releases)
<br>

## 🪄 Usage
Run `caracal` with  root privileges:

```
caracal --pid <pids> --bpf-prog-id <bpf-ids>
```
- `<pids>`: List of process IDs to hide (comma-separated, e.g., 123,456)
- `<bpf-ids>`: List of eBPF program IDs to hide (comma-separated, e.g., 789,101)


Example:
```
RUST_LOG=info sudo -E caracal --pid $PPID,1337  --bpf-prog-id  23,24,26
```

will hide:
- `caracal` launching process & its children
- 1337 process & its children
- `caracal` eBPF program & maps
- 23,24,26 eBPF programs & maps


## ⚠️ Disclaimer

`caracal` is developed for educational purposes only

<br>



## ✍️ Authors

[Adrien Gaultier](https://github.com/adgaultier)

<br>

## ⚖️ License

GPLv3
