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

wuboxinfo = """
    WuBOX, trace specific syscall or application
            For Linux, uses BCC, eBPF. Embedded C.

    You can using 'wubox -h' to get help


    Copyright (c) 2022 Wu Changhao, only for study
"""

errorinfo1 = """
    Too many parameters, you may try using 'wubox -h' to get help
"""

errorinfo2 = """
    Wrong parameters, you may try using 'wubox -h' to get help
"""

examples = """examples:
    ./wubox                             # print wubox info
    ./wubox -h                          # print wubox manual
    ./wubox -s open                     # trace all open() syscall
    ./wubox -a wubox                    # trace all wubox does
"""

def output(args):
    if args[1] == "-h":
        print(examples)
    elif len(args) == 3:
        if args[1] == "-s":
            # print(args[1],": ",args[2])
            systrace(args[2], 10)
        elif args[1] == "-a":
            print(args[1],": ",args[2])
            # apptrace(args[2])
        else:
            print(errorinfo2)
            return
    elif len(args) > 3:
        print(errorinfo1)
        return
    else:
        print(errorinfo2)
        return



if __name__ == "__main__":

    if len(sys.argv) > 1 and len(sys.argv) < 4:
        output(sys.argv)
    elif len(sys.argv) == 1:
        print(wuboxinfo)
    else:
        print(errorinfo1)

