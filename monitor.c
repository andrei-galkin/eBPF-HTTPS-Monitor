//go:build ignore
// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_PAYLOAD 256

struct http_event {
    __u32 pid;
    char  comm[16];
    char  payload[MAX_PAYLOAD];
    __u32 len;
    __u8  is_response;
    __u8  is_plain;      // 1 = plain HTTP, 0 = HTTPS
};

// Stash pointers on entry (shared by SSL_read and tcp_recvmsg)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u64);
} entry_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// ---- HTTP method detection ----

static __always_inline int is_http_request(const char *buf) {
    char b[8] = {};
    bpf_probe_read_user(b, sizeof(b), buf);
    if (b[0]=='G' && b[1]=='E' && b[2]=='T' && b[3]==' ')              return 1;
    if (b[0]=='P' && b[1]=='O' && b[2]=='S' && b[3]=='T' && b[4]==' ') return 1;
    if (b[0]=='P' && b[1]=='U' && b[2]=='T' && b[3]==' ')              return 1;
    if (b[0]=='D' && b[1]=='E' && b[2]=='L' && b[3]=='E')              return 1;
    if (b[0]=='H' && b[1]=='E' && b[2]=='A' && b[3]=='D' && b[4]==' ') return 1;
    if (b[0]=='P' && b[1]=='A' && b[2]=='T' && b[3]=='C' && b[4]=='H') return 1;
    if (b[0]=='O' && b[1]=='P' && b[2]=='T' && b[3]=='I')              return 1;
    return 0;
}

static __always_inline int is_http_response(const char *buf) {
    char b[5] = {};
    bpf_probe_read_user(b, sizeof(b), buf);
    return (b[0]=='H' && b[1]=='T' && b[2]=='T' && b[3]=='P');
}

// ---- HTTPS: SSL_write uprobe ----

SEC("uprobe/SSL_write")
int probe_ssl_write(struct pt_regs *ctx) {
    struct http_event *e;
    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    int num = (int)PT_REGS_PARM3(ctx);

    if (num <= 0) return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(struct http_event), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->is_response = 0;
    e->is_plain = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 len = ((__u32)num) & (MAX_PAYLOAD - 1);
    e->len = len;
    bpf_probe_read_user(&e->payload, len, buf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---- HTTPS: SSL_read uprobe + uretprobe ----

SEC("uprobe/SSL_read")
int probe_ssl_read_entry(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 buf = PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&entry_args, &pid_tgid, &buf, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int probe_ssl_read_return(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *bufp;
    struct http_event *e;

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) goto cleanup;

    bufp = bpf_map_lookup_elem(&entry_args, &pid_tgid);
    if (!bufp) goto cleanup;

    e = bpf_ringbuf_reserve(&events, sizeof(struct http_event), 0);
    if (!e) goto cleanup;

    e->pid = pid_tgid >> 32;
    e->is_response = 1;
    e->is_plain = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 len = ((__u32)ret) & (MAX_PAYLOAD - 1);
    e->len = len;
    bpf_probe_read_user(&e->payload, len, (void *)*bufp);

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&entry_args, &pid_tgid);
    return 0;
}

// ---- Plain HTTP: tcp_sendmsg kprobe ----

SEC("kprobe/tcp_sendmsg")
int probe_tcp_sendmsg(struct pt_regs *ctx) {
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    struct iovec iov = {};
    struct iovec *iov_ptr = NULL;
    struct iov_iter iter = {};

    bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    bpf_probe_read_kernel(&iov_ptr, sizeof(iov_ptr), &iter.iov);
    if (!iov_ptr) return 0;
    bpf_probe_read_kernel(&iov, sizeof(iov), iov_ptr);

    const char *buf = iov.iov_base;
    size_t count    = iov.iov_len;
    if (!buf || count == 0) return 0;

    int req = is_http_request(buf);
    int res = is_http_response(buf);
    if (!req && !res) return 0;

    struct http_event *e = bpf_ringbuf_reserve(&events, sizeof(struct http_event), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->is_response = res ? 1 : 0;
    e->is_plain = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 len = ((__u32)count) & (MAX_PAYLOAD - 1);
    e->len = len;
    bpf_probe_read_user(&e->payload, len, buf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ---- Plain HTTP: tcp_recvmsg kprobe + kretprobe ----

SEC("kprobe/tcp_recvmsg")
int probe_tcp_recvmsg(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 msg = (__u64)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&entry_args, &pid_tgid, &msg, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int probe_tcp_recvmsg_return(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) goto cleanup;

    __u64 *msg_ptr = bpf_map_lookup_elem(&entry_args, &pid_tgid);
    if (!msg_ptr) goto cleanup;

    struct msghdr *msg = (struct msghdr *)*msg_ptr;
    struct iov_iter iter = {};
    struct iovec iov = {};
    struct iovec *iov_ptr = NULL;

    bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter);
    bpf_probe_read_kernel(&iov_ptr, sizeof(iov_ptr), &iter.iov);
    if (!iov_ptr) goto cleanup;
    bpf_probe_read_kernel(&iov, sizeof(iov), iov_ptr);

    const char *buf = iov.iov_base;
    if (!buf) goto cleanup;

    int req = is_http_request(buf);
    int res = is_http_response(buf);
    if (!req && !res) goto cleanup;

    struct http_event *e = bpf_ringbuf_reserve(&events, sizeof(struct http_event), 0);
    if (!e) goto cleanup;

    e->pid = pid_tgid >> 32;
    e->is_response = res ? 1 : 0;
    e->is_plain = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u32 len = ((__u32)ret) & (MAX_PAYLOAD - 1);
    e->len = len;
    bpf_probe_read_user(&e->payload, len, buf);

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&entry_args, &pid_tgid);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";