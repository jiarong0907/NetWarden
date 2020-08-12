## IPv4 Identification storage channel

### Attack description
The attacker encodes data directly in the identification field of the IPv4 header.

### Defense description
NetWarden normalizes the identification of each packet to a constant number---1023 in our experiments.


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
./p4_build.sh /home/jiarong/NetWarden/release/IPID/ipid.p4
./run_switchd.sh -p ipid
```


**Step 2:** Enable all ports of the switch.
```
ucli
pm
port-add -/- 25G NONE
port-enb -/-
```



**Step 3:** In the server side:
```
sudo python3.7 server.py
```

**Step 4:** In the client side, capture packets using tcpdump:
```
sudo tcpdump -i ens3f0 -G 60 -W 1 -w ipid.pcap
```

**Step 5:** In the client side, open another terminal and start the connection:
```
sudo python3.7 client.py
```

**Step 6:** Identification fields of packets (sent by the server) captured in the pcap should be normalized to 1023.

