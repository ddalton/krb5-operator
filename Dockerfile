# The operator image.
#
#   docker build -t ghcr.io/ddalton/krb5-operator:dev .
#
# The KDC it runs for each realm is a separate image (images/kdc).

FROM rust:1.96-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --bin krb5-operator \
    && mkdir /out && cp target/release/krb5-operator /out/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/krb5-operator /usr/local/bin/
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/krb5-operator"]
