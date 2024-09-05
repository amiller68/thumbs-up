# Get started with a build env with Rust nightly
FROM --platform=$BUILDPLATFORM rustlang/rust:nightly-bullseye as builder

# Make an /app dir, which everything will eventually live in
WORKDIR /app
COPY . .

# Install cmake and cross-compilation tools
RUN apt-get update && apt-get install -y \
    cmake \
    libclang-dev \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    libc6-dev-arm64-cross

# Set up cross-compilation environment variables
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++

# Build the app
ARG TARGETPLATFORM
RUN case "$TARGETPLATFORM" in \
        "linux/amd64")  TARGET="x86_64-unknown-linux-gnu" ;; \
        "linux/arm64")  TARGET="aarch64-unknown-linux-gnu" ;; \
        *)              TARGET="unknown" ;; \
    esac \
    && if [ "$TARGET" = "unknown" ]; then echo "Unsupported platform: $TARGETPLATFORM"; exit 1; fi \
    && rustup target add $TARGET \
    && cargo build --release --target $TARGET

FROM --platform=$TARGETPLATFORM debian:bullseye-slim as runtime
WORKDIR /app

RUN apt-get update -y \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Copy the server binary to the /app directory
ARG TARGETPLATFORM
RUN case "$TARGETPLATFORM" in \
        "linux/amd64")  TARGET="x86_64-unknown-linux-gnu" ;; \
        "linux/arm64")  TARGET="aarch64-unknown-linux-gnu" ;; \
        *)              TARGET="unknown" ;; \
    esac \
    && if [ "$TARGET" = "unknown" ]; then echo "Unsupported platform: $TARGETPLATFORM"; exit 1; fi

COPY --from=builder /app/target/${TARGET}/release/thumbs-up-http /app/

# Set any required env variables
ENV RUST_LOG="info"
ENV LISTEN_ADDR="0.0.0.0"
ENV LISTEN_PORT="3000"
EXPOSE 3000

# Run the server
CMD ["/app/thumbs-up-http"]