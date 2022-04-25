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
from KNN import *
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
    ./wubox -a [-r] perlbench   # trace perlbench(must have a pkl), r is confidence range (default 50) 
    ./wubox -w perlbench        # add perlbench to whitelist
    ./wubox -g a                # generate whitelist packle in WUBOX\\whitelist\\model\\ as whitelist.pkl, a is not important   
"""


parser = argparse.ArgumentParser(
    prog="WuBOX",
    description=wuboxinfo,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

parser.add_argument("-a","--appname",
    help="trace this application")
parser.add_argument("-r","--range",
    help="set confidence range(only can be used with -a ,default 200)")
# parser.add_argument("-t", "--times",
#     help="trace t times")
parser.add_argument("-w", "--whitelist",
    help="add the app to whitelist")
parser.add_argument("-g", "--generate",
    help="generate whitelist model")

appname = ""
times = TIMES_DEFAULT
args = parser.parse_args()
# print(args)
if args.appname:
    d = 50
    if args.whitelist or args.generate:
        print("Error: You can only use on parse at one time")
        sys.exit()
    if args.range:
        d = args.range
    appname = args.appname
    app_trace(appname, int(d))
elif args.whitelist:
    if args.appname or args.generate or args.range:
        print("Error: You can only use on parse at one time")
        sys.exit()
    appname = args.whitelist     
    app_whitelist(appname)
elif args.generate:
    if args.whitelist or args.appname or args.range:
        print("Error: You can only use on parse at one time")
        sys.exit()   
    kNNgen()
else:
    print("Error: You may input no parse or a wrong parse")
    sys.exit()   


