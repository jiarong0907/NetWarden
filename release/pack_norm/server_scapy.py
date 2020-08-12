#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import *


def main():


    iface = "ens3f0"
    sock = conf.L2socket(iface=iface)

    serverIP = "192.168.0.1"
    clientIP = "192.168.0.2"
    serverPort = 32768
    clientPort = 32767
    payload = 'x'*100

    for i in range(10):
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff', type = 0x800)
        pkt = pkt / IP(src=serverIP, dst=clientIP) / TCP(ack = 10000+len(payload)*(i+1), flags = 0x10, sport=serverPort, dport=clientPort) / payload
        sock.send(pkt)


    print "Finish sending packets"

if __name__ == '__main__':
    main()