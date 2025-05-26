set export

_default:
    just --list



build-ebpf:
    cd stealth-ebpf && RUST_BACKTRACE=1 cargo build  --release

run:
    just build-ebpf
    RUST_BACKTRACE=1 cargo build --release 
    echo $PPID
    RUST_LOG=info sudo -E ./target/release/stealth --pid $PPID



test:
    strace procs 2> test 1>/dev/null && cat test | grep getdents

# Profile
profile:
    CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph  --root --bin stealth

