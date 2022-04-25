# Appcall tracer can trace application.
#           For Linux, uses BCC, eBPF. Embedded C.
#
#
# Copyright (c) 2022 Wu Changhao
from asyncio import FastChildWatcher
from socket import socket
from sqlite3 import connect
from sys import exit
from bcc import BPF
import argparse
import pandas as pd
import signal
import os
import sys
from KNN import *
prog1 = """
#include <uapi/linux/limits.h>
#include <linux/sched.h>

typedef struct event_data_t {
    u32 pid;
    u64 ts;
    char command[TASK_COMM_LEN];
    char filename[NAME_MAX];  // max of filename
    char syscallname[TASK_COMM_LEN];
}event;

// BPF_PERF_OUTPUT(sysevents);
BPF_RINGBUF_OUTPUT(sysevents, 8);

int trace_read(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) 
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
    strcpy(evt.syscallname, "read");
    sysevents.ringbuf_output(&evt, sizeof(evt), 0); 
    // sysevents.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
int trace_write(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) 
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
    strcpy(evt.syscallname, "write");
    sysevents.ringbuf_output(&evt, sizeof(evt), 0); 
    // sysevents.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
int trace_execve(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) 
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
    strcpy(evt.syscallname, "execve");
    sysevents.ringbuf_output(&evt, sizeof(evt), 0); 
    // sysevents.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
int trace_open(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) 
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
    strcpy(evt.syscallname, "open");
    sysevents.ringbuf_output(&evt, sizeof(evt), 0); 
    // sysevents.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
int trace_close(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) 
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
    strcpy(evt.syscallname, "close");
    sysevents.ringbuf_output(&evt, sizeof(evt), 0); 
    // sysevents.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
int trace_socket(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) 
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
    strcpy(evt.syscallname, "socket");
    sysevents.ringbuf_output(&evt, sizeof(evt), 0); 
    // sysevents.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
int trace_connect(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) 
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
    strcpy(evt.syscallname, "connect");
    sysevents.ringbuf_output(&evt, sizeof(evt), 0); 
    // sysevents.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
int trace_accept(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) 
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
    strcpy(evt.syscallname, "accept");
    sysevents.ringbuf_output(&evt, sizeof(evt), 0); 
    // sysevents.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
int trace_sendto(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) 
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
    strcpy(evt.syscallname, "send");
    sysevents.ringbuf_output(&evt, sizeof(evt), 0); 
    // sysevents.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
int trace_recvfrom(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) 
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
    strcpy(evt.syscallname, "recv");
    sysevents.ringbuf_output(&evt, sizeof(evt), 0); 
    // sysevents.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
int trace_fork(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) 
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
    strcpy(evt.syscallname, "fork");
    sysevents.ringbuf_output(&evt, sizeof(evt), 0); 
    // sysevents.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

b = BPF(text="")

start = 0
calls = ["fork","execve","read","write","open","close","socket","connect","accept","send","recv"]
counts = [[0,0,0,0,0,0,0,0,0,0,0]]   
total = 0
temp = 0
c = 0
d = 50
point = [[[0,0,0,0,0,0,0,0,0,0,0]]]
abnormal = False
abnormalcount = 0
# 

def kill(pid,name):
    try:
        kill_pid = os.kill(pid, signal.SIGABRT)
        print ("Program(pid=: %s) %s is killed, return : %s" % (pid, name, kill_pid))
    except Exception as e:
        print ("Program not exists, it may be killed")


def print_event(cpu, data, size):
    global start, calls, counts, total, temp, c
    
    event = b["sysevents"].event(data)
    # if start == 0:
    #     start = event.ts
    # time_s = (float(event.ts - start)) / 1000000000
    
    counts[total // 1500][calls.index(event.syscallname.decode("utf-8"))] += 1
    total += 1
    temp += 1
    if temp == 1500:
        counts.append([0,0,0,0,0,0,0,0,0,0,0])
        temp = 0
        c += 1 
    # print("%-18.9f %-16s %-6d %-24s %-8s" % (time_s, event.command.decode("utf-8"),
    #  event.pid, event.filename.decode("utf-8"), event.syscallname.decode("utf-8")))


def deal_event(cpu, data, size):
    global start, calls, counts, total, temp, d, point, abnormal,abnormalcount
     
    event = b["sysevents"].event(data)
    # if start == 0:
    #     start = event.ts
    # time_s = (float(event.ts - start)) / 1000000000

    point[total // 1500][0][calls.index(event.syscallname.decode("utf-8"))] += 1

    total += 1
    temp += 1
    # print(total)
    # print(temp)
    if temp == 1500:
        point.append([[0,0,0,0,0,0,0,0,0,0,0]])
        # print(point)
        # print(point[total // 1500])
        # print(point[(total // 1500)-1])
        inwhitelist = category(point[(total // 1500)-1],distance=d)
        # print(inwhitelist)
        if inwhitelist:
            # print("Nothing wrong")
            temp = 0
        else:
            
            # abnormalcount += 1
            print("Error: Abnormal behavior detected in (%s)." % event.command.decode("utf-8"))
            kill(event.pid, event.command.decode("utf-8"))
            abnormal = True
            temp = 0
    return
# 追踪需要生成白名单的程序使用情况
def app_whitelist(name):
    global prog1
    global b
    global counts
    global total
    global c 
    # prog1 = prog1.replace('FILENAME_FILTER',
    #     'if (memcmp(evt.command, \"%s\", %d) != 0) { return 0; }' % (name, len(name)))

    prog1 = prog1.replace('FILENAME_FILTER',
         'char *temp = \"%s\";for(int i = 0;i < %d; i++){if (evt.command[i] != temp[i]) {return 0;}}' % (name, len(name)))
    

    read = b.get_syscall_fnname("read")
    write = b.get_syscall_fnname("write")
    execve = "__x64_sys_execve"
    open = "do_sys_open"
    close = b.get_syscall_fnname("close")
    sock = b.get_syscall_fnname("socket")
    connect = b.get_syscall_fnname("connect")
    accept = b.get_syscall_fnname("accept") 
    sendto = b.get_syscall_fnname("send")
    recvf = b.get_syscall_fnname("recv")
    fork = b.get_syscall_fnname("fork")
    # cname = "sys_chmod"

    b = BPF(text = prog1) 

    b.attach_kprobe(event = read,   fn_name = "trace_read")
    b.attach_kprobe(event = write,  fn_name = "trace_write")
    b.attach_kprobe(event = execve, fn_name = "trace_execve")
    b.attach_kprobe(event = open,   fn_name = "trace_open")
    b.attach_kprobe(event = close,  fn_name = "trace_close")
    b.attach_kprobe(event = sock,   fn_name = "trace_socket")
    b.attach_kprobe(event = connect,fn_name = "trace_connect")
    b.attach_kprobe(event = accept, fn_name = "trace_accept")
    b.attach_kprobe(event = sendto, fn_name = "trace_sendto")
    b.attach_kprobe(event = recvf,  fn_name = "trace_recvfrom")
    b.attach_kprobe(event = fork,   fn_name = "trace_fork")

    # print("%-18s %-16s %-6s %-24s %-8s" % ("TIME(s)", "COMM", "PID", "FILE", "SYSCALL"))

    # b["sysevents"].open_perf_buffer(print_event)
    b["sysevents"].open_ring_buffer(print_event)
    # 截取1k次
    while True:
        try:    
            try:
                # b.perf_buffer_poll()
                b.ring_buffer_poll()
            except KeyboardInterrupt:
                print("Interrupted by Keyboard Input")
                break
        except:
            break

    index = 0
    print("------------------------------------------------统计信息------------------------------------------------")
    callsoutput = 0
    while callsoutput < len(calls):
        print("%-10s" % calls[callsoutput], end="")
        callsoutput += 1
    print("")
    while index <= c:
        countsoutput = 0 
        while countsoutput < len(counts[0]):
            print("%-10s" % counts[index][countsoutput], end="")
            countsoutput += 1
        print("")
        index += 1            

    print("保存白名单数据......")
    # 保存数据    
    col = calls
    col.append("type")
    data = []
    idx = 0
    for idx in range(c+1):
        temp = []
        temp = counts[idx]
        temp.append(name)
        data.append(temp)
        idx += 1

    if os.path.exists('../whitelist/csv/%s.csv' % name):
        csv = pd.DataFrame(columns = col, data = data)
        csv.to_csv('../whitelist/csv/%s.csv' % name, mode='a', header=0, index=None)
    else:    
        csv = pd.DataFrame(columns = col, data = data)
        csv.to_csv('../whitelist/csv/%s.csv' % name,index=None)

# 监控程序
def app_trace(name,distance = 50):
    global prog1, b, counts, total, c, d,point
    # prog1 = prog1.replace('FILENAME_FILTER',
    #     'if (memcmp(evt.command, \"%s\", %d) != 0) { return 0; }' % (name, len(name)))
    d = distance
    prog1 = prog1.replace('FILENAME_FILTER',
         'char *temp = \"%s\";for(int i = 0;i < %d; i++){if (evt.command[i] != temp[i]) {return 0;}}' % (name, len(name)))
    

    read = b.get_syscall_fnname("read")
    write = b.get_syscall_fnname("write")
    execve = "__x64_sys_execve"
    open = "do_sys_open"
    close = b.get_syscall_fnname("close")
    sock = b.get_syscall_fnname("socket")
    connect = b.get_syscall_fnname("connect")
    accept = b.get_syscall_fnname("accept") 
    sendto = b.get_syscall_fnname("send")
    recvf = b.get_syscall_fnname("recv")
    fork = b.get_syscall_fnname("fork")
    # cname = "sys_chmod"

    b = BPF(text = prog1) 

    b.attach_kprobe(event = read,   fn_name = "trace_read")
    b.attach_kprobe(event = write,  fn_name = "trace_write")
    b.attach_kprobe(event = execve, fn_name = "trace_execve")
    b.attach_kprobe(event = open,   fn_name = "trace_open")
    b.attach_kprobe(event = close,  fn_name = "trace_close")
    b.attach_kprobe(event = sock,   fn_name = "trace_socket")
    b.attach_kprobe(event = connect,fn_name = "trace_connect")
    b.attach_kprobe(event = accept, fn_name = "trace_accept")
    b.attach_kprobe(event = sendto, fn_name = "trace_sendto")
    b.attach_kprobe(event = recvf,  fn_name = "trace_recvfrom")
    b.attach_kprobe(event = fork,   fn_name = "trace_fork")

    # print("%-18s %-16s %-6s %-24s %-8s" % ("TIME(s)", "COMM", "PID", "FILE", "SYSCALL"))

    # b["sysevents"].open_perf_buffer(print_event)
    b["sysevents"].open_ring_buffer(deal_event)
    # 截取1k次
    while True:
        try:    
            try:
                # b.perf_buffer_poll()
                b.ring_buffer_poll()
                if abnormal:
                    break
            except KeyboardInterrupt:
                print("Interrupted by Keyboard Input")
                break
        except:
            break
    print("Trace end")  
    print("保存程序数据......")
    # if abnormalcount / (total // 1500) > 0.05:
    if abnormal:
        print("Error have happened, so %s is killed" % name)
    else:
        print("Nothing wrong")
    # # 保存数据    
    col = calls
    # col.append("type")
    data = []
    idx = 0
    for idx in range(len(point)):
        temp = []
        temp = point[idx][0]
        data.append(temp)
        idx += 1

   
    csv = pd.DataFrame(columns = col, data = data)
    csv.to_csv('../appinfo/%s.csv' % name,index=None)


if __name__ == "__main__":
    # app_whitelist("perlbench_r")
    app_trace("perlbench_s")

