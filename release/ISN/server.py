#!/usr/local/bin/python3.7

__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'

import socket
import threading
import os
import time
import random
import sys

block_size = 1024
local_ip = "192.168.0.1"
local_port = 0
nblocks = 10000000
sleep_time = 0.0002


class ThreadedServer():
    def __init__(self):
        self.host = socket.gethostname()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.s.bind((local_ip, local_port))
        print(self.s)


    def listen(self):
        self.s.listen(5)
        while True:
            c, addr = self.s.accept()
            c.settimeout(120)
            threading.Thread(target = self.listenToClient, \
                             args = (c, addr)).start()

    # the method itself has 100 us delay
    def usleep(self, num):
        start = time.time_ns()
        num = num - 100
        while True:
            end = time.time_ns()
            if (end - start)/1000.0 > num:
                break


    def send(self, c):
        data = ('a' * block_size).encode()
        i = 0

        print("[%s:%d]: start sending data" % (local_ip, local_port))
        while True:
            c.sendall(data)
            time.sleep(sleep_time)

            i += 1
            if i > nblocks:
               print("[%s:%d]: finish sending %d blocks" % \
                     (local_ip, local_port, nblocks))
               break

    def listenToClient(self, c, addr):
        print("[%s:%d]: get connection from: " % (local_ip, local_port))
        print(addr)
        self.send(c)
        c.close()

if __name__ == "__main__":
    if len(sys.argv) <= 1 or len(sys.argv) >= 4:
       print("Usage: python3.7 %s <port> [<nblocks>]" % (sys.argv[0]))
       exit(1)


    if len(sys.argv) >= 2:
       local_port = int(sys.argv[1])

    if len(sys.argv) >= 3:
       nblocks = int(sys.argv[2])

    print("Start listening on port %d, nblocks=%d" % \
          (local_port, nblocks))

    ThreadedServer().listen()
