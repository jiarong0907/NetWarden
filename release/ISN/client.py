#!/usr/bin/python3.7

__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'

import socket
import sys
import os
import time
import random

block_size = 1024

server_ip = "192.168.0.1"
server_port = 0

local_ip  = "192.168.0.2"
local_port = 0


def do_receive():
   # open a socket and connect to the file server
   s = socket.socket()
   s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
   s.setsockopt(socket.SOL_TCP, socket.TCP_QUICKACK, 0)
   s.bind((local_ip, local_port))

   try:
       print("connecting to the server %s:%d" % (server_ip, server_port))
       s.connect((server_ip, server_port))
   except Exception as e:
       print("failed to connect to [%s:%d]: %s" % \
             (server_ip, server_port, e))
       exit(2)

   # receive first data block
   print("[%s:%d]: start receving data.." % (server_ip, server_port))
   Data = s.recv(block_size)

   i = 0
   # receive the whole file
   while Data:
      Data = s.recv(block_size)
      i += 1

   print("[%s:%d]: received %d blocks" % (server_ip, server_port, i))
   s.close()


if __name__ == "__main__":
   if len(sys.argv) < 2:
      print("Usage: sudo python3.7 %s <server_port>" % (sys.argv[0]))
      exit(1)

   server_port = int(sys.argv[1])

   print("using server port %d" % server_port)
   do_receive()
