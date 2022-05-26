# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)

import socket
import struct
from . import command
import json


LENGTH_S = struct.Struct('=Q')


class Client:

    def __init__(self, socket_, addr, server):

        self.s = socket_
        self.addr = addr
        self.buffer = b''
        self.server = server

    def fileno(self):

        return self.s.fileno()

    def on_data(self):

        while True:

            try:
                data = self.s.recv(4096)
            except BlockingIOError:
                break

            if len(data) == 0:
                self.on_close()
                return

            self.buffer = self.buffer + data

            if (len(self.buffer) > LENGTH_S.size):
                json_length = LENGTH_S.unpack_from(self.buffer)[0]
                self.buffer = self.buffer[LENGTH_S.size:]

                if len(self.buffer) >= json_length:

                    cmd = self.buffer[:json_length]
                    self.buffer = self.buffer[json_length:]
                    d = None
                    try:
                        d = json.loads(cmd)
                    except Exception as e:
                        print(e)
                        self.on_close()
                        return
                    self.on_input(d)

    def on_input(self, d):
        command.on_input(self, d)

    def on_close(self):

        self.server.on_del_client(self)

    def send_result(self, result):

        self.s.sendall(result.to_bytes())
