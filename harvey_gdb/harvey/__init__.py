# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)

from . import pygdb
from . import server
from . import main_loop

import gdb


SERVER = None

def start():
    pygdb.set_gdb(gdb)

    global SERVER

    SERVER = server.TcpServer('127.0.0.1', 12345)
    SERVER.run_thread()
    main_loop.MAIN_LOOP.run()
