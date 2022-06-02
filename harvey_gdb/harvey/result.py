# SPDX-License-Identifier: MIT
# Copyright (c) 2022 Daniel Farrell (djfarrell@failingfastest.com)

import json
import struct


class HarveyResult:

    def __init__(self, results):

        self.r = results

    def to_bytes(self):

        r = json.dumps(self.r).encode()
        o = struct.pack('=Q', len(r)) + r

        return o
