
# eBPF HTTP/HTTPS Monitor (TLS/SSL Interceptor)

A high-performance **Security Observability** tool that captures both plain **HTTP** and encrypted **HTTPS** traffic at the kernel level using eBPF — no proxying, no private keys required.

> **Scope:** HTTPS interception covers OpenSSL (`libssl.so.3`) only. Plain HTTP is captured via kernel TCP hooks (`tcp_sendmsg` / `tcp_recvmsg`).

---

## How It Works

```
Plain HTTP                        HTTPS (OpenSSL)
──────────────────────────        ──────────────────────────
tcp_sendmsg  ──► kprobe           SSL_write  ──► uprobe
tcp_recvmsg  ──► kprobe/ret       SSL_read   ──► uprobe + uretprobe
                    │                              │
                    └──────────┬───────────────────┘
                               │
                        BPF Ring Buffer
                               │
                          Go Userspace Agent
                          ┌────┴────┐
                     Prometheus   Loki
                          └────┬────┘
                            Grafana
```

**Why uretprobe for SSL_read?** The buffer passed to `SSL_read` is empty on entry — OpenSSL fills it during the call. The uretprobe fires after the function returns, at which point the buffer contains decrypted data and the return value tells us exactly how many bytes were written.

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

> `vmlinux.h` is generated automatically during the Docker build. Do not commit it.

---

## Prerequisites

* **Docker Desktop** with WSL2 backend (Windows) or Docker on Linux
* Kernel **5.8+** with BTF enabled
  ```bash
  # Verify BTF is availablels /sys/kernel/btf/vmlinux
  ```

---

## Running the Stack

### 1. Start everything

```bash
docker compose up -d --build
```

### 2. Verify all services are up

```bash
docker compose ps
```

Expected output:

```
NAME                  SERVICE        STATUS    PORTS
ebpf-xxx-1            ebpf-monitor   Up
ebpf-xxx-1            prometheus     Up        0.0.0.0:9090->9090/tcp
ebpf-xxx-1            loki           Up        0.0.0.0:3100->3100/tcp
ebpf-xxx-1            grafana        Up        0.0.0.0:3000->3000/tcp
```

### 3. Wait for Loki to be ready (~15 seconds)

```bash
curl http://localhost:3100/ready
# Expected: ready
```

### 4. Watch live events

```bash
docker compose logs ebpf-monitor -f
```

Leave this running in a dedicated terminal.

---

## Generating Test Traffic

### HTTPS traffic

```bash
docker compose exec ebpf-monitor curl -sk https://www.google.com
docker compose exec ebpf-monitor curl -sk https://github.com
```

### Plain HTTP traffic

```bash
docker compose exec ebpf-monitor curl -s http://httpbin.org/get
docker compose exec ebpf-monitor curl -s http://example.com
```

### Sustained traffic loop (PowerShell)

```powershell
for ($i = 0; $i -lt 20; $i++) {
    docker compose exec ebpf-monitor curl -sk https://www.google.com | Out-Null
    docker compose exec ebpf-monitor curl -s http://httpbin.org/get | Out-Null
    Start-Sleep -Seconds 2
}
```

### Expected log output

```
2026/03/24 04:39:37 monitoring HTTP and HTTPS (lib: /usr/lib/x86_64-linux-gnu/libssl.so.3)
2026/03/24 04:39:38 [HTTPS] REQ GET / (pid=1234 comm=curl)
2026/03/24 04:39:38 [HTTPS] RES 200 (pid=1234 comm=curl)
2026/03/24 04:39:40 [HTTP]  REQ GET /get (pid=1235 comm=curl)
2026/03/24 04:39:40 [HTTP]  RES 200 (pid=1235 comm=curl)
```

---

## Verifying the Full Pipeline

### Prometheus metrics

```bash
curl "http://localhost:9090/api/v1/query?query=ebpf_http_requests_total"
```

### Loki logs

```bash
curl "http://localhost:3100/loki/api/v1/query?query=%7Bjob%3D%22ebpf-monitor%22%7D"
```

---

## Grafana Dashboard

1. Open **http://localhost:3000** (login: `admin` / `admin`)
2. **Add Prometheus data source**
   * Connections → Data sources → Add → Prometheus
   * URL: `http://host.docker.internal:9090`
   * Save & Test
3. **Add Loki data source**
   * Connections → Data sources → Add → Loki
   * URL: `http://host.docker.internal:3100`
   * Save & Test
4. **Create a dashboard** with these panels:

| Panel         | Data source | Query                                                  |
| ------------- | ----------- | ------------------------------------------------------ |
| Request rate  | Prometheus  | `rate(ebpf_http_requests_total[1m])`                 |
| HTTP vs HTTPS | Prometheus  | `sum by (protocol) (ebpf_http_requests_total)`       |
| Top paths     | Prometheus  | `topk(10, sum by (path) (ebpf_http_requests_total))` |
| Live logs     | Loki        | `{job="ebpf-monitor"}`                               |
| HTTPS only    | Loki        | `{job="ebpf-monitor", protocol="HTTPS"}`             |
| HTTP only     | Loki        | `{job="ebpf-monitor", protocol="HTTP"}`              |

---

## Configuration Flags

| Flag         | Default                                    | Description                            |
| ------------ | ------------------------------------------ | -------------------------------------- |
| `-lib`     | `/usr/lib/x86_64-linux-gnu/libssl.so.3`  | OpenSSL library path for HTTPS uprobes |
| `-metrics` | `:9091`                                  | Prometheus metrics endpoint            |
| `-loki`    | `http://127.0.0.1:3100/loki/api/v1/push` | Loki push URL                          |

Override in `docker-compose.yml` under the `command` key.

---

## Troubleshooting

**No events appearing:**

```bash
# Check the monitor is running without errors
docker compose logs ebpf-monitor

# Verify uprobes are attached (run from inside the container)
docker compose exec ebpf-monitor cat /sys/kernel/debug/tracing/uprobe_events
```

**`permission denied` on load:**
Ensure `privileged: true` and `pid: "host"` are set in `docker-compose.yml`.

**Plain HTTP not captured:**
The `tcp_sendmsg`/`tcp_recvmsg` kprobes fire on all TCP traffic and filter by HTTP method signature. If the server uses HTTP/2 over plain TCP (rare), it won't be captured as HTTP/2 is binary framed.

**Wrong libssl path:**

```bash
# Find the correct path on your system
find /usr/lib -name "libssl.so*" 2>/dev/null
```

Then pass it with `-lib=/path/to/libssl.so.3`.
