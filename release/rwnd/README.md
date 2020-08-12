## TCP receiving window size storage channel

### Attack description
The attacker encodes data in the TCP receiving window size field. Specifically, the attacker in the outside is uploading a file to the server. There is a malicious process running in the server that encodes data in the receiving window size field and leaks data from the server to the attacker in the outside.

### Defense description
#### Naive defense
The defense shrinks the receiving window size field to a constant number. There are two cases: 1) The receiving window is not the bottleneck. In this case, the naive defense will not affect the connection performance. 2) The receiving window is the bottleneck of the connection. In this case, the defense will degrade the connection performance.

#### NetWarden defense
NetWarden also shrinks the receiving window size field to a constant number, but it also enlarges the field to a constant number. Therefore, the performance degradation caused by shrinking can be cancelled out by the enlarging.


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
./p4_build.sh /home/jiarong/NetWarden/release/rwnd/rwnd.p4    # For NetWarden
./p4_build.sh /home/jiarong/NetWarden/release/rwnd/rwnd_naive.p4    # For Naive defense
./run_switchd.sh -p rwnd # For NetWarden
./run_switchd.sh -p rwnd_naive # For Naive defense
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
~/tools/run_pd_rpc.py -p rwnd /home/jiarong/NetWarden/release/rwnd/run_pd_rpc/setup.py # For NetWarden
~/tools/run_pd_rpc.py -p rwnd_naive /home/jiarong/NetWarden/release/rwnd/run_pd_rpc/setup_naive.py # For Naive defense
```


**Step 4:** In the server side:
```
sudo python3.7 server.py
```

**Step 5:** In the server side, capture packets using tcpdump:
```
sudo tcpdump -i ens3f0 -G 60 -W 1 -w rwnd_server.pcap
```

**Step 6:** In the client side, capture packets using tcpdump:
```
sudo tcpdump -i ens3f0 -G 60 -W 1 -w rwnd_client.pcap
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

**Step 9:** Use WireShark observe the receiving window size. You should be able to see the receiving window size of the client side is normalized to constant number.


**Step 10:** Remove the network configurations:
```
sudo python setup_net_rate.py 10 1 0.1 del
```

**To observe the TCP sending rate:**
In the client side, you can capture packets using tcpdump and compute the sending rate yourself:
```
sudo tcpdump -i ens3f0 -G 60 -W 1 -w rwnd_client.pcap
```

or you can use our simple netspeed script to see the real time sending rate by:
```
# The script is named netspeed.sh under /NetWarden/release/tools/.
sudo bash netspeed.sh
```