<div align="center">
  <h1>Caracal</h1>
  <h3>Make your (eBPF🐝)  programs stealthier </h3>
  <img src="https://github.com/user-attachments/assets/089060da-1a14-475d-8aa3-e1bfae15e8f7" style="width: 60%; height: auto;">
    <p><small><i>The caracal cat is one of Africa's ultimate hunters,<br> a stealthy cat with an exceptional ability to hunt out prey on the savanna</i></small></p>

</div>


Caracal is a rust implementation of ebpf program that enables you to hide: 
- bpf programs and maps
- procesess


## 🚀 Setup

You need a Linux based OS.

### ⚒️ Build from source

To build from source, make sure you have:

- [bpf-linker](https://github.com/aya-rs/bpf-linker) installed.
- [Rust](https://www.rust-lang.org/tools/install) installed with `nightly` toolchain.


#### 1. Build ebpf program

```
cd caracal-ebpf && cargo build  --release
```

#### 2. Build user space program
```
cargo build --release 
```
This command will produce  `caracal` executable in `target/release` that you can add to your`$PATH`

<br>

## 🪄 Usage
To launch caracal, lauch as sudo:

```
caracal --pid <comma-separated list of pids> --bpf-prog-id <comma-separated list of bpf prog ids> 
```

Example:
```
RUST_LOG=info sudo -E caracal \
               --pid $PPID,1337 \
               --bpf-prog-id  23,24,26
```

will hide:
- the current process &  its child processes
- 1337 process & its child processes
- caracal bpf program and maps
- 23,24,26 bpf programs and their associated maps


## ⚠️ Disclaimer

`Caracal` is developed for educational purposes only

<br>



## ✍️ Authors

[Adrien Gaultier](https://github.com/adgaultier)

<br>

## ⚖️ License

GPLv3
