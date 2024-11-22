set export

# List available targets
default:
    just --list



build-ebpf:
    cd stealth-ebpf && RUST_BACKTRACE=1 cargo build  --release

run:
    just build-ebpf
    RUST_BACKTRACE=1 cargo build --release 
    RUST_LOG=info sudo -E ./target/release/stealth --pid $PPID





# Profile
profile:
    CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph  --root --bin stealth

