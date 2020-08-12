#!/usr/bin/python3.7

__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'

import socket
import sys
import os
import time
import random

block_size = 512

server_ip = "192.168.0.1"
server_port = 0

local_ip  = "192.168.0.2"
local_port = 0

covert_data_path = "/home/jiarong/covert_data/covert_data.txt"
covert_data_res = "/home/jiarong/covert_data/covert_data_res.txt"

bit_one_thres_us = 350
bit_one_us = 0
covert_start_pkt = 100


def check_error_rate(res):
    stand = read_covert_data()
    print("Error rate: "+str(min(compare_bits(stand, res, 0), compare_bits(stand, res, 1), compare_bits(stand, res, 2))))
   #  print("error rate from 0: "+str(compare_bits(stand, res, 0)))
   #  print("error rate from 1: "+str(compare_bits(stand, res, 1)))
   #  print("error rate from 2: "+str(compare_bits(stand, res, 2)))

def compare_bits(stand, res, begin):
    error = 0
    for i in range(len(stand)):
        if (stand[i] != res[i+begin]):
            error+=1
    return error/2048.0

def read_covert_data():
    res = []
    f = open(covert_data_path,'r')
    for line in f.readlines():
        for i in range(len(line)):
            res.append(int(line[i:i+1]))
    return res

def do_receive():
   # open a socket and connect to the file server
   s = socket.socket()
   s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536);
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
   res = []
   index = 0
   begin_t = time.time_ns() / 1000000.0
   # receive the whole file
   while Data:
      start_time = time.time_ns()
      Data = s.recv(block_size)
      end_time = time.time_ns()
      if(i > covert_start_pkt and index < 2060):
         if((end_time-start_time)/1000.0 > bit_one_thres_us):
            res.append(1)
         else:
            res.append(0)
         index += 1
      # done receiving covert data
      if (index == 2048):
         index+=1
         with open(covert_data_res, 'w') as f:
            for i in range(len(res)):
                  f.write(str(res[i]) + " ")
                  if (i > 0 and i % 50 == 0):
                     f.write(str("\n"))
      i += 1
      # print("[%s:%d]: received block %d" % (server_ip, server_port, i))


   end_t = time.time_ns() / 1000000.0
   print("end, time = %d ms" % end_t)
   print("consumed %d ms" % (end_t - begin_t))

   check_error_rate(res)


   print("[%s:%d]: received %d blocks" % (server_ip, server_port, i))
   s.close()

if __name__ == "__main__":
   if len(sys.argv) < 2:
      print("Usage: sudo python3.7 %s <server_port>" % (sys.argv[0]))
      exit(1)

   server_port = int(sys.argv[1])
   #local_port  = server_port

   print("using server port %d" % server_port)
   do_receive()
