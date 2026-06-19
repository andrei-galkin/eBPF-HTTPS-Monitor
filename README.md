# eBPF HTTP/HTTPS Monitor (TLS/SSL Interceptor)

A high-performance **Security Observability** tool that captures both plain **HTTP** and encrypted **HTTPS** traffic at the kernel level using eBPF — no proxying, no private keys required.

> **Scope:** HTTPS interception covers OpenSSL (`libssl.so.3`) only. Plain HTTP is captured via kernel TCP hooks (`tcp_sendmsg` / `tcp_recvmsg`).

---

## What Gets Captured

For every HTTP/HTTPS request and response the monitor extracts:

| Field | Example | Source |
|---|---|---|
| Protocol | `HTTPS` / `HTTP` | uprobe vs kprobe |
| Method | `GET`, `POST` | Request line |
| Host | `www.google.com` | `Host:` header |
| Path | `/search?q=ebpf` | Request line |
| Status | `200`, `404` | Response line |
| PID | `1234` | `bpf_get_current_pid_tgid` |
| Process | `curl`, `chrome` | `bpf_get_current_comm` |

Log output example:
```
[HTTPS] REQ GET www.google.com/ (pid=1234 comm=curl)
[HTTPS] RES 200 host=www.google.com (pid=1234 comm=curl)
[HTTP]  REQ GET httpbin.org/get (pid=1235 comm=curl)
[HTTP]  RES 200 host=httpbin.org (pid=1235 comm=curl)
```

---

## How It Works

```
Plain HTTP                          HTTPS (OpenSSL)
──────────────────────────          ──────────────────────────
tcp_sendmsg  ──► kprobe             SSL_write  ──► uprobe
tcp_recvmsg  ──► kprobe + kretprobe SSL_read   ──► uprobe + uretprobe
                    │                                │
                    └──────────┬─────────────────────┘
                               │
                        BPF Ring Buffer
                               │
                     Go Userspace Agent
                     ┌─────────┴─────────┐
                Prometheus            Loki
                     └─────────┬─────────┘
                             Grafana
```

**Why uretprobe for SSL_read?**
The buffer passed to `SSL_read` is empty on entry — OpenSSL fills it during the call. The uretprobe fires after the function returns, at which point the buffer contains decrypted plaintext data.

**Why Host header parsing?**
The full URL (`https://www.google.com/search`) only exists client-side. On the wire, after TLS handshake, curl sends `GET /search HTTP/1.1` with a separate `Host: www.google.com` header. Both are parsed and combined for logging.

**Self-filtering:**
The monitor writes its own host PID into a BPF map. All probes check this map and skip events from the monitor process itself to avoid feedback loops. Additional processes (loki, prometheus, grafana) are filtered by comm name.

---

## Project Structure

```
.
├── monitor.c          # eBPF kernel-space program (C)
├── main.go            # Userspace loader and event processor (Go)
├── Dockerfile         # Multi-stage build
├── docker-compose.yml # Full stack orchestration
├── prometheus.yml     # Prometheus scrape config
└── README.md
```

> `vmlinux.h` is generated automatically during the Docker build via `bpftool btf dump`. Do not commit it.

---

## Prerequisites

- **Linux** with kernel **5.8+**
  - 5.8+ required for BPF Ring Buffer support
  - BTF must be enabled: `ls /sys/kernel/btf/vmlinux`
- **Docker** with Docker Compose

Verify:
```bash
uname -r                          # Should be 5.8+
ls /sys/kernel/btf/vmlinux        # Should exist
ldd $(which curl) | grep ssl      # Shows which libssl curl uses
```

---

## Running the Stack

### 1. Build and start

```bash
docker compose up -d --build
docker compose ps
```

All four services should show `Up`: `ebpf-monitor`, `prometheus`, `loki`, `grafana`.

### 2. Wait for Loki (~15 seconds)

```bash
curl http://localhost:3100/ready
# Returns: ready
```

### 3. Watch live events

```bash
docker compose logs ebpf-monitor -f
```

---

## Testing

### Generate HTTPS traffic (on the host)
```bash
curl -sk https://www.google.com > /dev/null
curl -sk https://github.com > /dev/null
```

### Generate plain HTTP traffic (on the host)
```bash
curl -s http://httpbin.org/get > /dev/null
curl -s http://example.com > /dev/null
```

### Expected log output
```
[HTTPS] REQ GET www.google.com/ (pid=1234 comm=curl)
[HTTPS] RES 200 host=www.google.com (pid=1234 comm=curl)
[HTTP]  REQ GET httpbin.org/get (pid=1235 comm=curl)
[HTTP]  RES 200 host=httpbin.org (pid=1235 comm=curl)
```

> **Important:** Run curl on the **host machine**, not inside a container. The uprobes attach to the host's libssl — processes inside containers use their own copy of libssl which won't be intercepted.

### Sustained traffic loop
```bash
for i in $(seq 1 20); do
    curl -sk https://www.google.com > /dev/null
    curl -s http://httpbin.org/get > /dev/null
    sleep 2
done
```

---

## Verifying the Full Pipeline

```bash
# Prometheus metrics
curl "http://localhost:9090/api/v1/query?query=ebpf_http_requests_total"

# Loki logs
curl "http://localhost:3100/loki/api/v1/query?query=%7Bjob%3D%22ebpf-monitor%22%7D"
```

---

## Grafana Dashboard

Open `http://localhost:3000` (login: `admin` / `admin`).

**Add Prometheus data source:**
- Connections → Data sources → Add → Prometheus
- URL: `http://host.docker.internal:9090` (Docker Desktop) or `http://localhost:9090` (Linux)
- Save & Test

**Add Loki data source:**
- Connections → Data sources → Add → Loki
- URL: `http://host.docker.internal:3100` (Docker Desktop) or `http://localhost:3100` (Linux)
- Save & Test

**Suggested panels:**

| Panel | Source | Query |
|---|---|---|
| Request rate | Prometheus | `rate(ebpf_http_requests_total[1m])` |
| HTTP vs HTTPS | Prometheus | `sum by (protocol) (ebpf_http_requests_total)` |
| Top hosts | Prometheus | `topk(10, sum by (host) (ebpf_http_requests_total))` |
| Top paths | Prometheus | `topk(10, sum by (path) (ebpf_http_requests_total))` |
| Requests by process | Prometheus | `sum by (comm) (ebpf_http_requests_total)` |
| Live logs | Loki | `{job="ebpf-monitor"}` |
| HTTPS only | Loki | `{job="ebpf-monitor", protocol="HTTPS"}` |
| HTTP only | Loki | `{job="ebpf-monitor", protocol="HTTP"}` |
| By host | Loki | `{job="ebpf-monitor", host="www.google.com"}` |

---

## Configuration Flags

| Flag | Default | Description |
|---|---|---|
| `-lib` | `/usr/lib/x86_64-linux-gnu/libssl.so.3` | OpenSSL library path for HTTPS uprobes |
| `-metrics` | `:9091` | Prometheus metrics endpoint |
| `-loki` | `http://127.0.0.1:3100/loki/api/v1/push` | Loki push URL |
| `-exclude` | `monitor,loki,prometheus,grafana,lifecycle-serve` | Comma-separated process names to ignore |

Override in `docker-compose.yml`:
```yaml
command:
  - "-lib=/usr/lib/x86_64-linux-gnu/libssl.so.3"
  - "-metrics=:9091"
  - "-loki=http://127.0.0.1:3100/loki/api/v1/push"
  - "-exclude=monitor,loki,prometheus,grafana"
```

---

## Troubleshooting

**No events when running curl:**
```bash
# Verify curl uses the same libssl the monitor is attached to
ldd $(which curl) | grep ssl
# Should show: libssl.so.3 => /usr/lib/x86_64-linux-gnu/libssl.so.3

# Run curl on the HOST, not inside a container
curl -sk https://www.google.com > /dev/null
```

**Wrong libssl path:**
```bash
find /usr/lib -name "libssl.so*"
# Use the found path with: -lib=/path/to/libssl.so.3
```

**Noisy processes in logs:**
```yaml
# Add to the exclude flag in docker-compose.yml
- "-exclude=monitor,loki,prometheus,grafana,your-process"
```

**Permission denied on load:**
Ensure `privileged: true` and `pid: "host"` are set in `docker-compose.yml`.

**BTF not available:**
```bash
ls /sys/kernel/btf/vmlinux
# If missing, upgrade kernel to 5.8+ with CONFIG_DEBUG_INFO_BTF=y
```