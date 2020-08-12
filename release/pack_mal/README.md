## TCP Partial ACK (malicious) storage channel

### Attack description
The attacker encodes data directly in the TCP ACK number by acknowledging part of a whole packet.
For example, the sequence number (SEQ) of a packet is 0 and the packet size is 10.
Normally, a receiver will generate an ACK number with ACK=10, but the attacker can control the ACK to 8. In this case, the covert data is 2 (10-8). In this attack, the attacker is uploading a file to a server. In the server, there is a malicious process that generates partial ACK to leak information from the server to the outside attacker.

In our experiments, we use the switch to simulate the attack. Concretely, the switch modifies the ACK number by minusing 10, so that the ACK is partially acknowledging the packet.

### Defense description
NetWarden will detect whether the ACK number is a partial ACK by comparing it with the highwater. If so, it will randomly minus a number to the partial ACK. Note that this will not break the TCP connection, since the next ACK packet will tell the sender the previous packet has been received.


### Experiment setup
- Switch: Wedge 100BF-32X Tofino switch.
- Barefoot SDE: `bf-sde-8.8.0`
- Host OS: Ubuntu 18.04
- TCP congestion control: reno


### Run the code

**Step 1:** Build and run the P4 program:
```
cd ~/bf-sde-8.8.0
source set_sde.bash
./p4_build.sh /home/jiarong/NetWarden/release/pack_mal/pack_mal.p4
./run_switchd.sh -p pack_mal
```


**Step 2:** Enable all ports of the switch.
```
ucli
pm
port-add -/- 25G NONE
port-enb -/-
```

**Step 3:** Run control plane program:
```
# Run in another terminal in the switch
cd ~/bf-sde-8.8.0
source set_sde.bash
~/tools/run_pd_rpc.py -p pack_mal /home/jiarong/NetWarden/release/pack_mal/run_pd_rpc/setup.py
```

**Step 4:** In the server side:
```
sudo python3.7 server.py
```

**Step 5:** In the server side, capture packets using tcpdump:
```
sudo tcpdump -i ens3f0 -G 60 -W 1 -w pack_mal_server.pcap
```

**Step 6:** In the client side, capture packets using tcpdump:
```
sudo tcpdump -i ens3f0 -G 60 -W 1 -w pack_mal_client.pcap
```

**Step 7:** In the client side, open another terminal and simulate the network condition:
```
# setup_net_rate.py is under /NetWarden/release/tools/
sudo python setup_net_rate.py 10 1 0.1 add  #10ms latency, 1ms jitter, and 0.1% loss rate
```

**Step 8:** In the client side, open another terminal and start the connection:
```
sudo python3.7 client.py
```

**Step 9:** From the 6th packet ACK numbers from the server side to the client side should be minused by a number and that number is larger than 10.


**Step 10:** Remove the network configurations:
```
sudo python setup_net_rate.py 10 1 0.1 del
```


**To observe TCP sending rate:**
In the client side, you can capture packets using tcpdump and compute the sending rate yourself:
```
sudo tcpdump -G 60 -W 1 -w pack_mal_client.pcap
```

or you can use our simple netspeed script to see the real time sending rate by:
```
# The script is named netspeed.sh under /NetWarden/release/tools/.
sudo bash netspeed.sh
```
