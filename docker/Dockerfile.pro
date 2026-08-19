# syntax=docker/dockerfile:1

FROM node:22-alpine AS web-builder
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM rust:1-bookworm AS rust-builder
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates clang cmake libssl-dev pkg-config
WORKDIR /build
COPY . .
COPY --from=web-builder /build/web/dist ./web/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --locked --release --all-features --bins \
    && install -D target/release/hbbs /out/hbbs \
    && install -D target/release/hbbr /out/hbbr \
    && install -D target/release/rustdesk-utils /out/rustdesk-utils

FROM debian:bookworm-slim
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get -o Acquire::Retries=5 update \
    && apt-get install -y --no-install-recommends ca-certificates curl libpq5 netcat-openbsd postgresql-client sqlite3 \
    && groupadd --gid 10001 rustdesk \
    && useradd --uid 10001 --gid rustdesk --home-dir /var/lib/rustdesk --shell /usr/sbin/nologin rustdesk \
    && install -d -o rustdesk -g rustdesk -m 0750 /var/lib/rustdesk /etc/rustdesk-server

COPY --from=rust-builder /out/hbbs /usr/local/bin/hbbs
COPY --from=rust-builder /out/hbbr /usr/local/bin/hbbr
COPY --from=rust-builder /out/rustdesk-utils /usr/local/bin/rustdesk-utils
COPY --chmod=0755 scripts/backup.sh scripts/restore.sh /usr/local/libexec/rustdesk-server/

USER rustdesk:rustdesk
WORKDIR /var/lib/rustdesk
VOLUME ["/var/lib/rustdesk"]
EXPOSE 21114 21115 21116 21116/udp 21117 21118 21119
ENTRYPOINT ["/usr/local/bin/hbbs"]
CMD ["--config", "/etc/rustdesk-server/config.toml"]
