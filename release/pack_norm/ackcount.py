from scapy.all import *
import math
import sys

server_ip = "192.168.0.1"


def get_ACK(path):
    # rdpcap comes from scapy and loads in our pcap file
    print "Reading pcap from "+path

    packets = rdpcap(path)
    print "The number of packets is "+str(len(packets))
    acks = []
    for i in range(len(packets)):
        pkt = packets[i]
        # pkt.show2()
        if IP in pkt and pkt["IP"].src == server_ip and pkt["IP"].proto == 6:
            acks.append(pkt["TCP"].ack)

    return acks

if __name__ == "__main__":

    if len(sys.argv) < 3 :
		print "Too few arguments\n"
		print "Usage: python "+str(sys.argv[0])+" pcap_server pcap_client\n"
		sys.exit(2)

    pcap_server = sys.argv[1]
    pcap_client = sys.argv[2]

    ack_server = get_ACK(pcap_server)
    ack_client = get_ACK(pcap_client)

    for ack in ack_server:
        if ack not in ack_client:
            print ack

