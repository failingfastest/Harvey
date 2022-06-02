# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)
import queue


class MainLoop:

    def __init__(self):

        self.q = queue.Queue()
        self.keep_going = True

    def run(self):

        self.keep_going = True

        command = None
        client = None
        input_ = None

        while self.keep_going:
            try:
                command = None
                client = None
                input_ = None

                command, client, input_ = self.q.get(block=True, timeout=0.1)
            except queue.Empty as e:
                pass
            except KeyboardInterrupt:
                break

            if command is not None and client is not None and input_ is not None:
                r = command.run(client, input_)
                client.send_result(r)
                
    def add_work(self, command, client, input_):

        self.q.put((command, client, input_))

MAIN_LOOP = MainLoop()
