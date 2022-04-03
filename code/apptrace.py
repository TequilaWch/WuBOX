# Appcall tracer can trace application.
#           For Linux, uses BCC, eBPF. Embedded C.
#
#
# Copyright (c) 2022 Wu Changhao
from asyncio import FastChildWatcher
from sys import exit
from bcc import BPF
import argparse


prog = """
#include <uapi/linux/limits.h>
#include <linux/sched.h>

typedef struct event_data_t {
    u32 pid;
    u64 ts;
    char command[TASK_COMM_LEN];
    char filename[NAME_MAX];  // max of filename

    char syscallname[TASK_COMM_LEN];

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

    FILENAME_FILTER  //用于标记文件名
    // SYSCALL_SET //用于替换SYSCALL

    sysevents.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

examples = """examples:
    ./wubox -a code    # only trace application \"code\" 
"""

b = BPF(text="")

parser = argparse.ArgumentParser(
    description="Trace open() syscalls",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-a", "--appname",
    help="trace this app only")

args = parser.parse_args()
if args.appname:
    prog = prog.replace('FILENAME_FILTER',
        'if (memcmp(evt.command, \"%s\", %d) != 0) { return 0; }' % (args.appname, len(args.appname)))
else:
    prog = prog.replace('FILENAME_FILTER', '')

fnname = b.get_syscall_fnname("read")
b = BPF(text = prog) 
b.attach_kprobe(event = fnname, fn_name = "trace_syscall")
start = 0        
def print_event(cpu, data, size):
    global start
    event = b["sysevents"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-6d %-18.9f %-16s %-6d %-24s" % (i, time_s, event.command.decode("utf-8"),
     event.pid, event.filename.decode("utf-8")))

    
print("%-6s %-18s %-16s %-6s %-24s" % ("COUNT", "TIME(s)", "COMM", "PID", "FILE"))


b["sysevents"].open_perf_buffer(print_event)

i = 0
while (i < 10):
    try:
        i += 1
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()    
