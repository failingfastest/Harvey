
import json
import struct
import sys
import socket


def main():

    cmd = sys.argv[1]
    args = {}
    for x in sys.argv[2:]:
        name, value = x.split('=')
        args[name] = value

    hdr = struct.Struct('=Q')

    c = {'cmd': cmd, 'args': args}

    j = json.dumps(c).encode()
    b = hdr.pack(len(j)) + j

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 12345))
    s.sendall(b)

    h = s.recv(hdr.size)
    r = s.recv(hdr.unpack_from(h)[0])
    rr = json.loads(r)

    print(rr)

    return 0


if __name__ == '__main__':
    sys.exit(main())
