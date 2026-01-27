# ---------------------- BUILD STAGE ----------------------
FROM debian:bookworm-slim AS builder

# Install build tools and Rust
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    make \
    curl \
    ca-certificates \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy sources
COPY . ./elfinspect
COPY ../example.c ./example.c

# Partial hardening build
RUN gcc -o example_partial example.c \
    -fstack-protector \
    -pie -fPIE \
    -O2

# Full hardening build
RUN gcc -o example_full example.c \
    -Wl,-z,relro,-z,now \
    -Wl,-z,noexecstack \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -fPIC -pie \
    -O2

# Build elfinspect
WORKDIR /app/elfinspect
RUN cargo build --release

# ---------------------- FINAL IMAGE ----------------------
FROM debian:bookworm-slim

# Copy only the built binaries
WORKDIR /app
COPY --from=builder /app/example_partial .
COPY --from=builder /app/example_full .
COPY --from=builder /app/elfinspect/target/release/elfinspect ./elfinspect

# Install minimal runtime deps if needed (libssl for Rust binary)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Default command
CMD echo "===== PARTIAL HARDENING =====" && \
    /app/elfinspect /app/example_partial -v && \
    echo "" && \
    echo "===== FULL HARDENING =====" && \
    /app/elfinspect /app/example_full -v
