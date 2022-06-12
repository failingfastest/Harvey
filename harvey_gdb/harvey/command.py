# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)

import sys
import json
from . import result
from . import pygdb
from . import main_loop
from . import breakpoints


class HarveyCmd:

    NAME = None
    HELP = None
    MAIN = False

    def __init__(self):

        pass

    def run(self, client, args):

        pass


class EchoCmd(HarveyCmd):

    NAME = 'echo'
    HELP = 'Echos args.'

    def __init__(self):
        HarveyCmd.__init__(self)

    def run(self, client, input_):

        print(input_)

        r = {
            'success': True,
            'return': input_['args'],
            'type': 'result',
            'id': input_['id'],
        }

        ret = result.HarveyResult(r)

        return ret


class GdbExecCmd(HarveyCmd):

    NAME = 'gdbRaw'
    HELP = 'performs gdb.execute()'

    def __init__(self):
        HarveyCmd.__init__(self)

    def run(self, client, input_):

        gdb = pygdb.get_gdb()
        cmd = input_['args']['cmd']

        try:
            output = gdb.execute(cmd, True, True)
        except Exception as e:
            output = str(e)

        r = {
            'success': True,
            'return': { 
                'output': output,
            },
            'type': 'result',
            'id': input_['id'],
        }

        ret = result.HarveyResult(r)

        return ret


class GdbRunCmd(GdbExecCmd):

    NAME = 'gdbRun'
    HELP = 'Runs run in main loop'
    MAIN = True

    def run(self, client, input_):

        print(input_)

        input_['args']['cmd'] = 'continue'

        return GdbExecCmd.run(self, client, input_)


class GdbSymbolCmd(HarveyCmd):

    NAME = 'gdbSymbol'
    HELP = 'resolves a symbol'

    def __init__(self):
        HarveyCmd.__init__(self)

    def run(self, client, input_):

        gdb = pygdb.get_gdb()
        symbol = input_['args']['symbol']
        success = True

        try:
            output = gdb.execute(f'printf "%x", {symbol}', True, True)
            output = int(output, 16)
        except Exception as e:
            output = str(e)
            success = False

        r = {
            'success': success,
            'return': { 
                'output': output,
            },
            'type': 'result',
            'id': input_['id'],
        }

        ret = result.HarveyResult(r)

        return ret


BREAKPOINTS = {}


class BreakCmd(HarveyCmd):

    NAME = 'break'
    HELP = 'adds a breakpoint'
    MAIN = True

    def __init__(self):
        HarveyCmd.__init__(self)

    def run(self, client, input_):

        gdb = pygdb.get_gdb()
        address = input_['args']['address']

        spec = f'*0x{address:x}'
        try:
            global BREAKPOINTS
            if spec not in BREAKPOINTS:
                bp = breakpoints.HarveyBP(spec)
                BREAKPOINTS[spec] = bp
            output = 'Done'
        except Exception as e:
            output = str(e)

        r = {
            'success': True,
            'return': { 
                'output': output,
            },
            'type': 'result',
            'id': input_['id'],
        }

        ret = result.HarveyResult(r)

        return ret

commands = {}


def add_command(cmd_class):

    global commands

    commands[cmd_class.NAME] = cmd_class()


def on_input(client, input_):
    print(f'on_input: {str(input_)}')

    if input_['type'] == 'result':
        if input_['id'] in current_command:
            lcmd = current_command.pop(input_['id'])
            lcmd.handle_result(client, input_)
    elif input_['type'] == 'command':
        cmd_name = input_['cmd']
        args = input_['args']

        if cmd_name not in commands:
            print('error: command does not exist')
        else:
            command = commands[cmd_name]
            if command.MAIN:
                main_loop.MAIN_LOOP.add_work(command, client, input_)
            else:
                r = command.run(client, input_)
                client.send_result(r)


add_command(EchoCmd)
add_command(GdbExecCmd)
add_command(GdbSymbolCmd)
add_command(GdbRunCmd)
add_command(BreakCmd)
