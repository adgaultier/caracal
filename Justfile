set export

# List available targets
default:
    just --list


# Run debug
run-debug:
    echo "" > log-file
    RUST_LOG=info RUST_BACKTRACE=1 cargo xtask run 2> log-file

run:
    cargo xtask run

# Run oryx release
release:
    cargo xtask run --release

# Build
build:
    cargo xtask build

# Profile
profile:
    CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph  --root --bin oryx

