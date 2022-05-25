import sys
import socket
import threading
import select
from . import client

class Server:

    def __init__(self, socket_):

        self.s = socket_
        self.clients = {}
        self.keep_going = True

    def on_client(self):
        print('new harvey client')
        s, a = self.s.accept()
        s.setblocking(False)
        self.clients[s.fileno()] = client.Client(s, a, self)

    def wait(self):

        r, w, x = select.select([self.s.fileno()] + [x for x in self.clients.keys()], [], [], 1.)
        for fd in r:
            if fd == self.s.fileno():
                self.on_client()
            elif fd in self.clients:
                print('on data')
                self.clients[fd].on_data()

    def on_del_client(self, client):

        self.clients.pop(client.fileno())

    def on_die(self):

        self.keep_going = False

    def run(self):

        print('start harvey listening thread')
        while self.keep_going:
            self.wait()
        print('ending harvey listening thread')
        
    def run_thread(self):
    
        self.t = threading.Thread(target=self.run, args=tuple())
        self.t.daemon = True
        self.t.start()


class TcpServer(Server):

    def __init__(self, addr, port):

        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((addr, port))
        s.listen(5)
        s.setblocking(False)

        Server.__init__(self, s)


