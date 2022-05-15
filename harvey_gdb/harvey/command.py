import sys
import json
from . import result


class HarveyCmd:

    NAME = None
    HELP = None

    def __init__(self):

        pass

    def run(self, args):

        pass


class EchoCmd(HarveyCmd):

    NAME = 'echo'
    HELP = 'Echos args.'

    def __init__(self):
        HarveyCmd.__init__(self)

    def run(self, args):

        print(args)

        r = {
            'success': True,
            'return': args,
        }

        ret = result.HarveyResult(r)

        return ret

commands = {}


def add_command(cmd_class):

    global commands

    commands[cmd_class.NAME] = cmd_class()


def run_command(client, cmd):

    cmd_name = cmd['cmd']
    args = cmd['args']

    if cmd_name not in commands:
        print('error: command does not exist')
    else:
        r = commands[cmd_name].run(args)
        client.send_result(r)


add_command(EchoCmd)

