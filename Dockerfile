FROM golang:1.24-bookworm AS builder

# Install LLVM/Clang toolchain
RUN apt-get update && apt-get install -y clang llvm libbpf-dev gcc-multilib make

WORKDIR /app

# Install bpf2go tool
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest

COPY go.mod go.sum ./
RUN go mod download

# Copy your vmlinux.h, bpf/ folder, monitor.c, and main.go
COPY . .

# Generate BPF bytecode and build Go binary
RUN go generate ./...
RUN go build -o monitor .

# Final runtime image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 curl && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/monitor /monitor
ENTRYPOINT ["/monitor"]