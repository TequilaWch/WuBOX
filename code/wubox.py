# WuBOX, trace specific syscall or application
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: wubox [-h] [-s [-r] syscall name [times]] [-a application name]
#
# Copyright (c) 2022 Wu Changhao

import os
import sys
import argparse
from datetime import datetime, timedelta

# from apptrace import *
from systrace import *

TIMES_DEFAULT = 25

wuboxinfo = """
    WuBOX, trace specific syscall or application
            For Linux, uses BCC, eBPF. Embedded C.

    You can using 'wubox -h' to get help


    Copyright (c) 2022 Wu Changhao, only for study
"""

errorinfo1 = """
    Too many/few parameters, you may try using 'wubox -h' to get help
"""

errorinfo2 = """
    Wrong parameters, you may try using 'wubox -h' to get help
"""

examples = """examples:
    ./wubox                             # print wubox info
    ./wubox -h                          # print wubox manual
    ./wubox -s [-r] open [100]          # trace all open() syscall_enter[return] for [100] times
    ./wubox -a wubox                    # trace all wubox does
"""

def output(args):
    a = len(args)
    if args[1] == "-h":                 # 输出帮助
        print(examples)
    elif args[1] == "-s":               # 追踪syscall -s
        if args[2] == "-r":              # -s -r 
            if a == 5:                  # -s -r syscall times
                systrace(args[3], args[4], ret=True)
            elif a == 4:                # -s -r syscall
                systrace(args[3], TIMES_DEFAULT, ret=True)
        elif a == 4:                    # -s syscall times
            systrace(args[2], args[3])
        elif a == 3:                    # -s syscall
            systrace(args[2], TIMES_DEFAULT)
        else:                           # error too many/few
            print(errorinfo1)
    elif args[1] == "-a": # 追踪application
        pass
    else:
        print(errorinfo2)

    # if args[1] == "-h":
    #     print(examples)
    # elif len(args) == 3:
    #     if args[1] == "-s":
    #         # print(args[1],": ",args[2])
    #         systrace(args[2], 10)
    #     elif args[1] == "-a":
    #         print(args[1],": ",args[2])
    #         # apptrace(args[2])
    #     else:
    #         print(errorinfo2)
    #         return
    # elif len(args) > 3:
    #     print(errorinfo1)
    #     return
    # else:
    #     print(errorinfo2)
    #     return



if __name__ == "__main__":

    if len(sys.argv) > 1:
        output(sys.argv)
    elif len(sys.argv) == 1:    # 没有输入参数
        print(wuboxinfo)
