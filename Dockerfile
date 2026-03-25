FROM golang:1.24-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    gcc-multilib \
    linux-headers-amd64 \
    linux-libc-dev \
    bpftool \
    git \
    curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.17.1

COPY . .

RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > /app/vmlinux.h

RUN GOPACKAGE=main bpf2go \
    -target amd64 \
    -cflags "-D__TARGET_ARCH_x86 -I/app" \
    bpf /app/monitor.c

RUN go build -o monitor .

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/monitor /usr/local/bin/monitor

ENTRYPOINT ["/usr/local/bin/monitor"]