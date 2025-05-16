#!/bin/bash

sudo ip netns delete ns-0
sudo ip netns delete ns-1
sudo ip netns delete ns-2
sudo ip netns delete ns-3
sleep 1

sudo ip link set dev vf0_0 down
sudo ip link set dev vf0_1 down
sudo ip link set dev vf0_2 down
sudo ip link set dev vf0_3 down

sudo ip netns add ns-0
sudo ip netns add ns-1
sudo ip netns add ns-2
sudo ip netns add ns-3

sudo ip link set vf0_0 netns ns-0
sudo ip link set vf0_1 netns ns-1
sudo ip link set vf0_2 netns ns-2
sudo ip link set vf0_3 netns ns-3

sudo ip -n ns-0 addr add 10.0.0.4/24 dev vf0_0
sudo ip -n ns-1 addr add 10.0.0.1/24 dev vf0_1
sudo ip -n ns-2 addr add 10.0.0.2/24 dev vf0_2
sudo ip -n ns-3 addr add 10.0.0.3/24 dev vf0_3

sudo ip -n ns-0 l set dev lo up
sudo ip -n ns-0 l set dev vf0_0 up
sudo ip -n ns-1 l set dev lo up
sudo ip -n ns-1 l set dev vf0_1 up
sudo ip -n ns-2 l set dev lo up
sudo ip -n ns-2 l set dev vf0_2 up
sudo ip -n ns-3 l set dev lo up
sudo ip -n ns-3 l set dev vf0_3 up

sleep 2
sudo ip netns exec ns-0 arp -s 10.0.0.1 00:15:4d:00:00:01
sudo ip netns exec ns-0 arp -s 10.0.0.2 00:15:4d:00:00:02
sudo ip netns exec ns-0 arp -s 10.0.0.3 00:15:4d:00:00:03

sudo ip netns exec ns-1 arp -s 10.0.0.4 00:15:4d:00:00:00
sudo ip netns exec ns-1 arp -s 10.0.0.2 00:15:4d:00:00:02
sudo ip netns exec ns-1 arp -s 10.0.0.3 00:15:4d:00:00:03

sudo ip netns exec ns-2 arp -s 10.0.0.4 00:15:4d:00:00:00
sudo ip netns exec ns-2 arp -s 10.0.0.1 00:15:4d:00:00:01
sudo ip netns exec ns-2 arp -s 10.0.0.3 00:15:4d:00:00:03

sudo ip netns exec ns-3 arp -s 10.0.0.4 00:15:4d:00:00:00
sudo ip netns exec ns-3 arp -s 10.0.0.1 00:15:4d:00:00:01
sudo ip netns exec ns-3 arp -s 10.0.0.2 00:15:4d:00:00:02
