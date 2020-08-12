## TCP initial sequence number storage channel

### Attack description
The attacker encodes data directly in the TCP initial sequence number.

### Defense description
NetWarden shifts all TCP sequence numbers from the server side by adding 10.


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
./p4_build.sh /home/jiarong/NetWarden/release/ISN/isn.p4
./run_switchd.sh -p isn
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

**Step 4:** In the server side, capture packets using tcpdump:
```
sudo tcpdump -i ens3f0 -G 60 -W 1 -w isn_server.pcap
```

**Step 5:** In the client side, capture packets using tcpdump:
```
sudo tcpdump -i ens3f0 -G 60 -W 1 -w isn_client.pcap
```

**Step 6:** In the client side, open another terminal and start the connection:
```
sudo python3.7 client.py
```

**Step 7:** All TCP sequence numbers from the server side should be added by 10.

