__author__      = 'Jiarong Xing'
__copyright__   = 'Copyright 2020, Rice University'


import socket
import sys
import os
import time

block_size = 512
nblocks = 10000000

server_ip = "192.168.0.1"
server_port = 0

local_ip  = "192.168.0.2"
local_port = 0


def do_send():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((local_ip, local_port))

    try:
        print("try to connect...")
        s.connect((server_ip, server_port))
        print("Connected Successfully!")
    except Exception as e:
        print("something's wrong with %s:%d. Exception is %s" % (server_ip, server_port, e))

    Answer = "upload"

    begin_t = time.time_ns() / 1000000.0
    print("started, time = %d ms" % begin_t)

    if(Answer == "download"):
        pass

    elif(Answer == "upload"):
        block_size = 512
        mssg = "upload"+" "*20 # use two space to fill one byte
        s.send(mssg.encode())
        print(mssg)
        #FileName = raw_input("Enter Filename to Download from server : ")
        file_name = "file_l.txt"
        Data = ""
        s.send(file_name.encode())
        time.sleep(0.2)
        print(file_name)


        Read = 'x'*block_size
        i = 1
        while i < nblocks:
            s.sendall(Read.encode())
            i = i + 1
            time.sleep(0.0002)
        print("Done Sending"+str(i))

    end_t = time.time_ns() / 1000000.0
    print("end, time = %d ms" % end_t)
    print("consumed %d ms" % (end_t - begin_t))
    s.close()


if __name__ == "__main__":
    if len(sys.argv) <= 1 or len(sys.argv) >= 3:
       print("Usage: python3.7 %s <port> [<nblocks>]" % (sys.argv[0]))
       exit(1)


    if len(sys.argv) >= 2:
       server_port = int(sys.argv[1])

    if len(sys.argv) >= 3:
       nblocks = int(sys.argv[2])

    print("Using server port %d, nblocks=%d" % (server_port, nblocks))

    do_send()
