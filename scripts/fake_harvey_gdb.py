
import sys
import socket
import json
import struct
import binascii


def serve():

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', 12345))
    s.listen(1)
    ss, a = s.accept()
    print(f'have connection: {a}')
    while True:
        length_bytes = ss.recv(8)
        if len(length_bytes) == 0:
            ss.close()
            break

        print(binascii.b2a_hex(length_bytes))

        length = struct.Struct('=Q').unpack_from(length_bytes)[0]
        j = ss.recv(length)
        if len(j) == 0:
            ss.close()
            break
        d = json.loads(j)
        print(d)
        d['type'] = 'result';
        j = json.dumps(d).encode()
        length_bytes = struct.pack('=Q', len(j))
        print('sending: ' + binascii.b2a_hex(length_bytes).decode())
        ss.sendall(length_bytes + j)
    return 

def main():

    while True:
        serve()

    return 0


if __name__ == '__main__':
    sys.exit(main())
