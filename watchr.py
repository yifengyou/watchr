#!/usr/bin/python3

from __future__ import print_function

import socket
import struct
from functools import partial
import logging

try:
    from bcc import BPF
except ImportError:
    try:
        from bpfcc import BPF
    except ImportError:
        print("Failed to import BPF from bpfcc module.")
        exit(1)

log = logging.getLogger("watchr")
log.setLevel(logging.INFO)
log_file = "/var/log/watchr.log"
file_handler = logging.FileHandler(log_file)
file_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
file_handler.setFormatter(file_formatter)
log.addHandler(file_handler)
stream_handler = logging.StreamHandler()
stream_formatter = logging.Formatter("%(message)s")
stream_handler.setFormatter(stream_formatter)
log.addHandler(stream_handler)

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/net_namespace.h>
#include <linux/netdevice.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_link.h>
#include <net/ip_fib.h>

struct trace_t {
    u64 ts; // 时间戳
    char funname[32]; // 信息内容
    unsigned char operstate;
    unsigned char transition;
    unsigned long state;
    char devname[32];
    int pid;
    char comm[32];
    int kernel_stack_id;
    int user_stack_id;
    u32 tb_id; // 表ID
    u32 dst;   // 目的地址
    u32 gw;    // 下一跳地址
    u8 dst_len; // 目的地址长度
    u8 fc_oif; // 目的地址长度
};

BPF_PERF_OUTPUT(traces);
BPF_STACK_TRACE(stacks, 2048);

int kprobe__fib_table_delete(struct pt_regs *ctx,
    struct net *net, struct fib_table *tb, struct fib_config *cfg)
{
    struct trace_t data = {};    
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.kernel_stack_id = stacks.get_stackid(ctx, 0);
    data.user_stack_id = stacks.get_stackid(ctx, BPF_F_USER_STACK);

    char funcname[] = "fib_table_delete";
    bpf_probe_read_str(&data.funname, sizeof(data.funname), funcname);



    data.tb_id = tb->tb_id;
    data.dst = cfg->fc_dst;
    data.dst_len = cfg->fc_dst_len;
    data.gw = cfg->fc_gw;
    data.fc_oif = cfg->fc_oif;

    traces.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

/*
int kprobe__fib_table_lookup(struct pt_regs *ctx)
{
    struct trace_t data = {};    
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.kernel_stack_id = stacks.get_stackid(ctx, 0);
    data.user_stack_id = stacks.get_stackid(ctx, BPF_F_USER_STACK);

    char funcname[] = "fib_table_lookup";
    bpf_probe_read_str(&data.funname, sizeof(data.funname), funcname);

    traces.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
*/

int kprobe__fib_table_insert(struct pt_regs *ctx, 
    struct net *net, struct fib_table *tb, struct fib_config *cfg, struct netlink_ext_ack *extack)

{
    struct fib_info *fi;
    struct trace_t data = {};    
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.kernel_stack_id = stacks.get_stackid(ctx, 0);
    data.user_stack_id = stacks.get_stackid(ctx, BPF_F_USER_STACK);

    char funcname[] = "fib_table_insert";
    bpf_probe_read_str(&data.funname, sizeof(data.funname), funcname);


    data.tb_id = tb->tb_id;
    data.dst = cfg->fc_dst;
    data.dst_len = cfg->fc_dst_len;
    data.gw = cfg->fc_gw;
    data.fc_oif = cfg->fc_oif;


    traces.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

/*
int kprobe__fib_table_flush(struct pt_regs *ctx)
{
    struct trace_t data = {};    
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.kernel_stack_id = stacks.get_stackid(ctx, 0);
    data.user_stack_id = stacks.get_stackid(ctx, BPF_F_USER_STACK);

    char funcname[] = "fib_table_flush";
    bpf_probe_read_str(&data.funname, sizeof(data.funname), funcname);

    traces.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
*/

/*
int kprobe__fib_table_dump(struct pt_regs *ctx)
{
    struct trace_t data = {};    
    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.kernel_stack_id = stacks.get_stackid(ctx, 0);
    data.user_stack_id = stacks.get_stackid(ctx, BPF_F_USER_STACK);

    char funcname[] = "fib_table_dump";
    bpf_probe_read_str(&data.funname, sizeof(data.funname), funcname);

    traces.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
*/


"""

"""
kprobe:fib_table_print.isra.20
kprobe:fib_table_lookup
kprobe:fib_table_insert
kprobe:fib_table_delete
kprobe:fib_table_flush_external
kprobe:fib_table_flush
kprobe:fib_table_dump
kprobe:l3mdev_fib_table_rcu
kprobe:l3mdev_fib_table_by_index
"""

b = BPF(text=bpf_text)


def stack_id_err(stack_id):
    # -EFAULT in get_stackid normally means the stack-trace is not available,
    # Such as getting kernel stack trace in userspace code
    return stack_id < 0


def print_stack(bpf, stack_id, stack_type, tgid):
    if stack_id_err(stack_id):
        log.info("    [Missed %s Stack]" % stack_type)
        return
    stack = list(bpf.get_table("stacks").walk(stack_id))
    for addr in stack:
        log.info("  %s" % str(bpf.sym(addr, tgid, show_module=True, show_offset=True).decode('utf8')))


class Enum(set):
    def __getattr__(self, name):
        if name in self:
            return name
        raise AttributeError


StackType = Enum(("Kernel", "User",))


def int_to_ip(v):
    return socket.inet_ntoa(struct.pack("I", v))


def get_dev_name(id):
    try:
        name = socket.if_indextoname(id)
    except:
        return ''
    return name


def print_trace(bpf, cpu, data, size):
    trace = b["traces"].event(data)

    ts = trace.ts
    funname = trace.funname.decode()
    devname = trace.devname.decode()
    operstate = trace.operstate
    state = trace.state
    transition = trace.transition
    pid = trace.pid
    comm = trace.comm.decode()

    log.info("\n[%d] FUN:%-22s NETDEV:%-12s OPERSTATE:0x%-3x STATE:0x%-3x PID:%-7d COMM:%s" %
             (ts, funname, devname, operstate, state, pid, comm)
             )
    if "fib_table_delete" == funname:
        log.info("* DEL ROUTE (%d) parsing:  ip route del %s/%d via %s dev %s [%d]\n",
                 trace.tb_id,
                 int_to_ip(trace.dst),
                 trace.dst_len,
                 int_to_ip(trace.gw),
                 get_dev_name(trace.fc_oif),
                 trace.fc_oif
                 )
    elif "fib_table_insert" == funname:
        log.info("* ADD/CHANGE ROUTE (%d) parsing:  ip route add %s/%d via %s dev %s [%d]\n",
                 trace.tb_id,
                 int_to_ip(trace.dst),
                 trace.dst_len,
                 int_to_ip(trace.gw),
                 get_dev_name(trace.fc_oif),
                 trace.fc_oif
                 )

    log.info(f"-> kernel stack id {trace.kernel_stack_id}")
    print_stack(bpf, trace.kernel_stack_id, StackType.Kernel, -1)
    log.info(f"-> user stack id {trace.user_stack_id}")
    print_stack(bpf, trace.user_stack_id, StackType.User, trace.pid)


print_trace = partial(print_trace, b)
b["traces"].open_perf_buffer(print_trace)

log.info("watching now...")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
