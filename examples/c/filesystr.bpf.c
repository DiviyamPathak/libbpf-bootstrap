// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct trace_event_raw_sys_enter {
    unsigned long long unused;
    long id;
    unsigned long args[6];
};

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];
    char fname[256];
    bpf_probe_read_user_str(fname, sizeof(fname), filename);
    bpf_printk("openat: %s\n", fname);
    return 0;
}
