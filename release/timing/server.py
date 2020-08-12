#!/usr/local/bin/python3.7

__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'


import socket
import threading
import os
import time
import random
import sys

block_size = 512
bit_one_us = 500
bit_zero_us = 200
local_ip = "192.168.0.1"
local_port = 0
covert_start = 100
covert_end = 2060
nblocks = 100000

# 16 Mpbs
sleep_time = 0.0002

covert_data_path = "./covert_data.txt"
covert_start_pkt = 100

class ThreadedServer():
    def __init__(self):
        self.host = socket.gethostname()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.s.bind((local_ip, local_port))
        print(self.s)
        self.covert_bits = []

    def read_covert_data(self):
        res = []
        f = open(covert_data_path, 'r')
        for line in f.readlines():
            for i in range(len(line)):
                res.append(int(line[i:i+1]))
        return res

    def listen(self, malicious):
        self.covert_bits = self.read_covert_data()
        self.s.listen(25)
        while True:
            c, addr = self.s.accept()
            c.settimeout(120)
            threading.Thread(target = self.listenToClient, \
                             args = (c, addr, malicious)).start()

    # the method itself has 100 us delay
    def usleep(self, num):
        start = time.time_ns()
        num = num - 100
        while True:
            end = time.time_ns()
            if (end - start)/1000.0 > num:
                break

    def send(self, c, malicious):
        data = ('a' * block_size).encode()
        i = 0

        index = 0
        print("[%s:%d]: start sending data" % (local_ip, local_port))
        while True:
            c.sendall(data)
            time.sleep(sleep_time)
            #self.usleep(bit_zero_us)

            # sleep extra bit_one_us us so that this flow will be
            # reconized as a malicious flow
            if (malicious and i > covert_start and i < covert_end):
                if self.covert_bits[index] == 1:
                   self.usleep(bit_one_us)
                index += 1
            i += 1
            if i > nblocks:
               print("[%s:%d]: finish sending %d blocks" % \
                     (local_ip, local_port, nblocks))
               break

    def listenToClient(self, c, addr, malicious):
        print("[%s:%d]: get connection from: " % (local_ip, local_port))
        print(addr)
        self.send(c, malicious)
        c.close()

if __name__ == "__main__":
    if len(sys.argv) <= 1 or len(sys.argv) >= 5:
       print("Usage: python3.7 %s <mali> [<port>, <nblocks>]" % (sys.argv[0]))
       exit(1)

    malicious = int(sys.argv[1])

    if len(sys.argv) >= 3:
       local_port = int(sys.argv[2])

    if len(sys.argv) >= 4:
       nblocks = int(sys.argv[3])

    print("Start listening on port %d, malicious=%d, nblocks=%d" % \
          (local_port, malicious, nblocks))

    ThreadedServer().listen(malicious)
