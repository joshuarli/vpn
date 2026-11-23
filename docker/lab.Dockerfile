FROM debian@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      ca-certificates curl gcc make libc6-dev binutils iproute2 iptables nftables procps \
      iputils-ping iperf3 time valgrind strace python3 qemu-user \
      gcc-x86-64-linux-gnu libc6-dev-amd64-cross git \
    && rm -rf /var/lib/apt/lists/* \
    && update-alternatives --set iptables /usr/sbin/iptables-nft
ARG TOOLCHAIN
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none \
    && rustup toolchain install $TOOLCHAIN --profile minimal -c rust-src,llvm-tools,clippy \
    && rustup default $TOOLCHAIN \
    && rustup target add --toolchain $TOOLCHAIN x86_64-unknown-linux-gnu aarch64-unknown-linux-musl \
    && chmod -R a+rwX /opt/cargo /opt/rustup
WORKDIR /src
