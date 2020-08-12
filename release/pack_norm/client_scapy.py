#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import *


def handle_pkt(pkt):

    if TCP in pkt:
        print "Received a packet, the ack number = "+str(pkt["TCP"].ack)

    sys.stdout.flush()


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
        pkt = pkt / IP(src=clientIP, dst=serverIP) / TCP(seq = 10000+len(payload)*i, flags = 0x10, sport=clientPort, dport=serverPort) / payload
        sock.send(pkt)
        # pkt.show2()


    print "Finish sending packets, sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()