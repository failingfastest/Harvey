# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)

import sys
import json
from . import result
from . import pygdb


class HarveyCmd:

    NAME = None
    HELP = None

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

        print(input_)

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


commands = {}


def add_command(cmd_class):

    global commands

    commands[cmd_class.NAME] = cmd_class()


def on_input(client, input_):

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
            r = commands[cmd_name].run(client, input_)
            client.send_result(r)


add_command(EchoCmd)
add_command(GdbExecCmd)

