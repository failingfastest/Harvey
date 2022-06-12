# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)

import gdb

from . import server
from . import updates


class HarveyBP(gdb.Breakpoint):

    ID = 1

    @classmethod
    def get_id(cls):

        ret = cls.ID

        cls.ID += 1

        return ret

    def __init__(self, spec):

        gdb.Breakpoint.__init__(self, spec, gdb.BP_BREAKPOINT)

        self.spec = spec

    def stop(self):

        print(f'BP[{self.spec}]: Stop')

        if server.SERVER is not None:

            address = gdb.execute('printf "0x%x", $rip', False, True)

            address = int(address, 16)

            u = {
                'success': True,
                'return': {
                    'address': address,
                },
                'type': 'update',
                'id': '%d' % self.get_id(),
            }

            update = updates.HarveyUpdate(u)

            clients = server.SERVER.get_clients()

            for client in clients:

                client.send_result(update)

        return True
