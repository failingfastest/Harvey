# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)

GDB = None


def get_gdb():

    global GDB

    return GDB


def set_gdb(gdb):

    global GDB

    GDB = gdb
