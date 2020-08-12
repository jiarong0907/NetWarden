__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'


import socket
import threading
import os
import time
import random
import sys


local_port = 0
block_size = 512
local_ip = "192.168.0.1"

class ThreadedServer():
    def __init__(self):
        self.host = socket.gethostname()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65535)
        self.s.bind((local_ip, local_port))

    def listen(self):
        self.s.listen(25)
        print ("listening...")
        while True:
            c, addr = self.s.accept()
            c.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (c,addr)).start()


    def listenToClient(self, c, addr):
        flag_file = True
        flag_channels = True
        #file_name = "file_l.txt"
        print("[%s:%d]: get connection from: " % (local_ip, local_port))
        print(addr)

        data = c.recv(8)
        print(data)

        if (data.decode() == "download"):
            pass
        elif (data.decode().strip() == "upload"):
            FileName = c.recv(1024)
            file_name = FileName.decode()

            Data = c.recv(block_size)
            i = 1
            while Data:
                if i % 5000 == 0:
                    print('Recieving...%d' %(i))
                Data = c.recv(block_size)
                i += 1

            print("Done Recieving")
            c.close()
            sys.exit()

if __name__ == "__main__":

    if len(sys.argv) != 2:
       print("Usage: python3.7 %s <port>" % (sys.argv[0]))
       exit(1)

    local_port = int(sys.argv[1])
    print("Start listening on port %d" % (local_port))

    ThreadedServer().listen()
