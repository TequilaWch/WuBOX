# Syscall tracer can trace syscall.
#           For Linux, uses BCC, eBPF. Embedded C.
#
#
# Copyright (c) 2022 Wu Changhao
from sys import exit
from bcc import BPF

#   全局BCC program
prog = """
#include <uapi/linux/limits.h>
#include <linux/sched.h>

typedef struct event_data_t {
    u32 pid;
    u64 ts;
    char command[TASK_COMM_LEN];
    char filename[NAME_MAX];  // max of filename
}event;

BPF_PERF_OUTPUT(sysevents);

int trace_syscall(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) 
{
    event evt = {};
  
    evt.pid = bpf_get_current_pid_tgid();
    evt.ts = bpf_ktime_get_ns();
    if(bpf_get_current_comm(&evt.command, sizeof(evt.command))==0)
    {
        bpf_probe_read(&evt.filename, sizeof(evt.filename), (void *)filename);
    }
    
    sysevents.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""
retprog = """
#include <uapi/linux/limits.h>
#include <linux/sched.h>

typedef struct event_data_t{
    u32 pid;
    u32 ret;
    u64 ts;
    char command[TASK_COMM_LEN];
    char filename[NAME_MAX];
}event;

typedef struct hash_val_t{
    u64 id;
    const char* filename;
}val;


BPF_HASH(infomap, u64, val);
BPF_PERF_OUTPUT(sysevents);
// 调用函数
int trace_syscall(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    val v = {};
    u64 id = bpf_get_current_pid_tgid();
    v.id = id;
    v.filename = filename;

    infomap.update(&id, &v);
    return 0;
}

int trace_syscall_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    val *mapv;

    event evt = {};
    evt.ts = bpf_ktime_get_ns();

    mapv = infomap.lookup(&id);
    if(mapv == 0)
    {
        bpf_trace_printk("Error, Map Missing\\n");
        return 0;
    }

    evt.pid = id >> 32;
    evt.ret = PT_REGS_RC(ctx);

    if(bpf_get_current_comm(&evt.command, sizeof(evt.command))==0)
    {
        bpf_probe_read(&evt.filename, sizeof(evt.filename), (void *)mapv->filename);
    }
    
    sysevents.perf_submit(ctx, &evt, sizeof(evt));

    infomap.delete(&id);
    return 0;

}


"""

start = 0
i = 0
b = BPF(text = prog)
rb = BPF(text = retprog)

def print_event(cpu, data, size):
    global start
    event = b["sysevents"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-6d %-18.9f %-16s %-6d %-24s" % (i, time_s, event.command.decode("utf-8"),
     event.pid, event.filename.decode("utf-8")))


def print_event_ret(cpu, data, size):
    global start
    event = rb["sysevents"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-6d %-18.9f %-16s %-6d %-24s %-4d" % (i, time_s, event.command.decode("utf-8"),
     event.pid, event.filename.decode("utf-8"), event.ret))


def systrace(sysname, times, ret=False):
    global prog
    global retprog
    global i
    if ret:
        fnname = rb.get_syscall_fnname(sysname)  # 待解决
        # fnname = "do_sys_open"

        rb.attach_kprobe(event = fnname, fn_name = "trace_syscall")
        rb.attach_kretprobe(event = fnname, fn_name = "trace_syscall_return")


        print("%-6s %-18s %-16s %-6s %-24s RETURN" % ("COUNT", "TIME(s)", "COMM", "PID", "FILE"))

        rb["sysevents"].open_perf_buffer(print_event_ret)
        
        while (i < int(times)):
            try:
                i += 1
                rb.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()

    else:
        fnname = b.get_syscall_fnname(sysname)   # 待解决

        b.attach_kprobe(event = fnname, fn_name = "trace_syscall")

        print("%-6s %-18s %-16s %-6s %-24s" % ("COUNT", "TIME(s)", "COMM", "PID", "FILE"))

        b["sysevents"].open_perf_buffer(print_event)

        while (i < int(times)):
            try:
                i += 1
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()    

   
if __name__ == "__main__":
    systrace("mkdir", 30)


