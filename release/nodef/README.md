### No defense

#### Description
This is one of the baseline we use to evaluate NetWarden. No defense only blindly forwards traffic to its destination without any covert channel migitation.


#### Experiment setup
- Same with NetWarden defenses that you want to compare with.


#### Run the code

Step 1: Build and run the P4 program:
```
cd ~/bf-sde-8.8.0
source set_sde.bash
./p4_build.sh /home/jiarong/NetWarden/release/nodef/nodef.p4
./run_switchd.sh -p nodef
```


Step 2: Enable all ports of the switch.
```
ucli
pm
port-add -/- 25G NONE
port-enb -/-
```


Step 3: In the server side, run the same server code with NetWarden.


Step 4: In the client side, run the same client code with NetWarden.


Step 5: In the client side, you can capture packets using tcpdump and compute the sending rate yourself:
```
sudo tcpdump -i ens3f0 -G 60 -W 1 -w nodef.pcap
```

or you can use our simple netspeed script to see the real time sending rate by:
```
# The script is named netspeed.sh under /NetWarden/release/tools/.
sudo bash netspeed.sh
```
