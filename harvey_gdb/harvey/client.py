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

        data = self.s.recv(4096)
        if len(data) == 0:
            self.on_close()
            return

        self.buffer = self.buffer + data

        if (len(self.buffer) > LENGTH_S.size) and (len(self.buffer) == LENGTH_S.unpack_from(self.buffer)[0] + LENGTH_S.size):
            cmd = self.buffer[LENGTH_S.size:]

            d = None
            try:
                d = json.loads(cmd)
            except Exception as e:
                print(e)
                self.on_close()

            command.run_command(self, d)

    def on_close(self):

        self.server.on_del_client(self)

    def send_result(self, result):

        self.s.sendall(result.to_bytes())
