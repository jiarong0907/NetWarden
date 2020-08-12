## TCP Partial ACK (normal) storage channel

### Attack description
TCP sends data in batch: In one RTT, the sender could send multiple packets continuously. The receiver could choose to acknowledge each of them or use one ACK packet to acknowledge multiple data packets. This non-determinism can be utilized to create a covert channel. For example, the sender sends 10 packets and waits for the ACK packets. The receiver can control the number of ACK packets. If the receiver sends 8 ACK packets, then 8 can be a covert message that the TCP receiver wants to let the TCP sender know.


We do not simulate the attack in switch or the end host, because we find that this could normally happen. Therefore, we regard it as a potential covert channel and mitigate it.

### Defense description
NetWarden will remember the highwater of the batch of packets and compare it with the received ACK numbers. If the ACK is not equal to it, the ACK packet will be dropped. It means that NetWarde only allows one ACK packet for a batch of packets.


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
./p4_build.sh /home/jiarong/NetWarden/release/pack_norm/pack_norm.p4
./run_switchd.sh -p pack_norm
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
~/tools/run_pd_rpc.py -p pack_norm /home/jiarong/NetWarden/release/pack_norm/run_pd_rpc/setup.py
```


**Step 4:** In the server side:
```
sudo python3.7 server.py
```

**Step 5:** In the server side, capture packets using tcpdump:
```
sudo tcpdump -i ens3f0 -G 60 -W 1 -w pack_norm_server.pcap
```

**Step 6:** In the client side, capture packets using tcpdump:
```
sudo tcpdump -i ens3f0 -G 60 -W 1 -w pack_norm_client.pcap
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

**Step 9:** Use ackcount tool to see ACKs in server side but not in client side
```
sudo python ackcount.py server_pcap client_pcap
```


**Step 10:** Remove the network configurations:
```
sudo python setup_net_rate.py 10 1 0.1 del
```

**To observe the TCP sending rate:**
In the client side, you can capture packets using tcpdump and compute the sending rate yourself:
```
sudo tcpdump -i ens3f0 -G 60 -W 1 -w pack_mal_client.pcap
```

or you can use our simple netspeed script to see the real time sending rate by:
```
# The script is named netspeed.sh under /NetWarden/release/tools/.
sudo bash netspeed.sh
```
