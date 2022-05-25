
from . import pygdb
from . import server
import gdb

pygdb.set_gdb(gdb)

SERVER = server.TcpServer('127.0.0.1', 12345)
SERVER.run_thread()
