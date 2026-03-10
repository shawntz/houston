# Stage 1: Build admin UI
FROM node:22-slim AS ui-builder
WORKDIR /app/admin-ui
COPY admin-ui/package.json admin-ui/package-lock.json ./
RUN npm ci
COPY admin-ui/ .
RUN npm run build

# Stage 2: Build Rust binary
FROM rust:1.94-bookworm AS rust-builder
RUN apt-get update && apt-get install -y pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl libclang-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY migrations/ migrations/
COPY --from=ui-builder /app/admin-ui/dist admin-ui/dist/
RUN cargo build --release

# Stage 3: Minimal runtime image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libxml2 libxmlsec1 libxmlsec1-openssl && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /usr/sbin/nologin houston
COPY --from=rust-builder /app/target/release/houston /usr/local/bin/houston
RUN mkdir -p /data /keys && chown houston:houston /data /keys
USER houston
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["houston"]
CMD ["serve", "--config", "/data/config.toml"]
