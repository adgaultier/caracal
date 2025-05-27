set export

_default:
    just --list



build-ebpf:
    cd stealth-ebpf && RUST_BACKTRACE=1 cargo build  --release


run pid="1337":
    just build-ebpf
    RUST_BACKTRACE=1 cargo build --release 
    RUST_LOG=info sudo -E ./target/release/stealth --pid $PPID,{{pid}}



test:
    strace ps aux 2> test 1>/dev/null && cat test | grep getdents

# Profile
profile:
    CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph  --root --bin stealth

