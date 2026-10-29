FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang cmake pkg-config libssl-dev python3 ripgrep iproute2 curl dnsutils \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add clippy rustfmt

ENV CARGO_HOME=/cargo-cache \
    CARGO_TARGET_DIR=/build \
    CARGO_BUILD_JOBS=2 \
    CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_DEV_DEBUG=0 \
    CARGO_PROFILE_TEST_DEBUG=0

WORKDIR /work
USER 1000:1000
