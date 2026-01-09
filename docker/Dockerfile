# ---------- builder ----------
ARG RUST_VERSION=1.92
FROM rust:${RUST_VERSION} AS builder
WORKDIR /app
COPY . .
ENV CARGO_TERM_COLOR=always
RUN cargo build --release

# ---------- rustdesk-api ----------
FROM lejianwen/rustdesk-api:latest AS api

# ---------- s6 downloader ----------
FROM debian:trixie-slim AS s6-downloader
ARG S6_OVERLAY_VERSION=3.2.0.0
ARG S6_ARCH=x86_64
RUN apt-get update && apt-get install -y \
    ca-certificates \
    xz-utils \
    curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp2

ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}.tar.xz /tmp
RUN tar -C /tmp2 -Jxpf /tmp/s6-overlay-noarch.tar.xz && \
    tar -C /tmp2 -Jxpf /tmp/s6-overlay-${S6_ARCH}.tar.xz

# ---------- final image ----------
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/hbbs /usr/bin/hbbs
COPY --from=builder /app/target/release/hbbr /usr/bin/hbbr
COPY --from=builder /app/target/release/rustdesk-utils /usr/bin/rustdesk-utils
COPY --from=api /app .
COPY --from=s6-downloader /tmp2/ /
RUN ln -s /run /var/run

COPY docker/rootfs /

ENV RELAY=relay.example.com
ENV ENCRYPTED_ONLY=0

EXPOSE 21114 21115 21116 21116/udp 21117 21118 21119

HEALTHCHECK --interval=10s --timeout=5s CMD /usr/bin/healthcheck.sh

VOLUME /app/data

VOLUME /data

ENTRYPOINT ["/init"]