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

from apptrace import *
# from systrace import *

TIMES_DEFAULT = 5000
TIMES_MAX = 1000000

wuboxinfo = """
    WuBOX, trace specific application
            For Linux, uses BCC, eBPF. Embedded C.

    You can using 'wubox -h' to get help

    Copyright (c) 2022 Wu Changhao, only for study
"""
 
examples = """examples:
    ./wubox wubox                    # trace wubox 
    ./wubox code -t 100              # trace code for 100 polling
    ./wubox code -t max              # trace code for 10^6 polling, (warning)
    ./wubox -h                       # help infomation    
"""


parser = argparse.ArgumentParser(
    prog="WuBOX",
    description=wuboxinfo,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("appname",
    help="trace this application")
parser.add_argument("-t", "--times",
    help="trace t times")

appname = ""
times = TIMES_DEFAULT
args = parser.parse_args()
if args.appname:
    appname = args.appname
    if args.times:
        times = args.times
        if times == "max":
            times = TIMES_MAX
        times = int(times) 
    else:
        times = TIMES_DEFAULT
    app_whitelist(appname, times)



