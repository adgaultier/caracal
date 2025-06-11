<div align="center">
  <h1>Caracal</h1>
  <h3>Make your programs stealthier </h3>
  <img src="https://github.com/user-attachments/assets/089060da-1a14-475d-8aa3-e1bfae15e8f7" style="width: 60%; height: auto;">
    <p><small><i>The caracal cat is one of Africa's ultimate hunters,<br> a stealthy cat with an exceptional ability to hunt out prey on the savanna</i></small></p>

</div>

## 💡 Overview
Caracal is a Rust implementation of eBPF techniques that: 
1. hide target bpf programs & maps   → won't be visible with `bpftop`, `bpftool` ...
2. hide target processes             → won't be visible with `ps`, `top`, `procs`, `ls /proc` ...
3. are resilient to some "unhiding" bruteforce techniques


## 📚 Documentation
Jump to:
- [Focus on 1 & 2](caracal/README.md)
- [Focus on 3](caracal-ebpf/src/deunhide/README.md)


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

You can download the pre-built binaries from the [release page](https://github.com/adgaultier/caracal/releases)
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
