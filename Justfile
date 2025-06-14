set export

_default:
    just --list

build-ebpf:
    cd caracal-ebpf &&  cargo build  --release

run pid="1337" bpf="257,258,259" :
    just build-ebpf
    RUST_BACKTRACE=1 cargo build --release 
    sudo  ./target/release/caracal --pid $PPID,{{pid}} --bpf-prog-id {{bpf}} -v

test:
    strace ps aux 2> test 1>/dev/null && cat test | grep getdents

