//go:build ignore
#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_core_read.h"

#define MAX_PAYLOAD 256
char __license[] SEC("license") = "Dual MIT/GPL";

struct http_event {
    __u32 pid;
    char  comm[16];
    char  payload[MAX_PAYLOAD];
    __u32 len;
    __u8  is_response;
    __u8  is_plain;
};

// Map to store the monitor's own PID for self-filtering
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} self_pid SEC(".maps");

// Temporary storage to bridge uprobe entry and return for SSL_read
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} entry_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int is_self() {
    __u32 key = 0;
    __u32 *spid = bpf_map_lookup_elem(&self_pid, &key);
    if (!spid) return 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    return pid == *spid;
}

static __always_inline int is_http(const char *buf) {
    char b[5] = {};
    bpf_probe_read_user(b, sizeof(b), buf);
    if (b[0]=='G' && b[1]=='E' && b[2]=='T') return 1;
    if (b[0]=='P' && b[1]=='O' && b[2]=='S') return 1;
    if (b[0]=='H' && b[1]=='T' && b[2]=='T') return 1; // Response headers
    return 0;
}

// --- HTTPS: SSL_write (Requests) ---
SEC("uprobe/SSL_write")
int probe_ssl_write(struct pt_regs *ctx) {
    if (is_self()) return 0;
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);
    if (num <= 0 || !is_http(buf)) return 0;

    struct http_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->is_response = 0; e->is_plain = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->len = (num > MAX_PAYLOAD) ? MAX_PAYLOAD : num;
    bpf_probe_read_user(&e->payload, e->len, buf);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// --- HTTPS: SSL_read (Responses) ---
SEC("uprobe/SSL_read")
int probe_ssl_read_entry(struct pt_regs *ctx) {
    if (is_self()) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 buf = PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&entry_args, &pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int probe_ssl_read_return(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int ret = (int)PT_REGS_RC(ctx);
    __u64 *bufp = bpf_map_lookup_elem(&entry_args, &pid_tgid);
    if (ret <= 0 || !bufp || !is_http((const char *)*bufp)) {
        bpf_map_delete_elem(&entry_args, &pid_tgid);
        return 0;
    }
    struct http_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->pid = pid_tgid >> 32;
        e->is_response = 1; e->is_plain = 0;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        e->len = (ret > MAX_PAYLOAD) ? MAX_PAYLOAD : ret;
        bpf_probe_read_user(&e->payload, e->len, (void *)*bufp);
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&entry_args, &pid_tgid);
    return 0;
}

// --- Plain HTTP: tcp_sendmsg ---
SEC("kprobe/tcp_sendmsg")
int probe_tcp_sendmsg(struct pt_regs *ctx) {
    if (is_self()) return 0;
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    const struct iovec *iov_ptr = BPF_CORE_READ(msg, msg_iter.iov);
    if (!iov_ptr) return 0;
    const char *buf = BPF_CORE_READ(iov_ptr, iov_base);
    if (!buf || !is_http(buf)) return 0;

    struct http_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->is_plain = 1; e->is_response = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->len = MAX_PAYLOAD; 
    bpf_probe_read_user(&e->payload, e->len, buf);
    bpf_ringbuf_submit(e, 0);
    return 0;
}