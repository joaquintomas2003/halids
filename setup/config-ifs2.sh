#!/bin/bash 

echo  "Namespaces para vf0 10.0.0.3 - vf1 10.0.0.4"
sudo ip netns delete ns-0 
sudo ip netns delete ns-1
sleep 1

sudo ip link set dev vf0_2 down
sudo ip link set dev vf0_3 down

echo "creando namespaces ns-0 y ns-1"
sudo ip netns add ns-0
sudo ip netns add ns-1

sudo ip link set vf0_0 netns ns-0
sudo ip link set vf0_1 netns ns-1

sudo ip -n ns-0 addr add 10.0.0.3/24 dev vf0_0
sudo ip -n ns-1 addr add 10.0.0.4/24 dev vf0_1
	
echo "levantando loopback e interfaces"

sudo ip -n ns-0 l set dev lo up
sudo ip -n ns-1 l set dev lo up
sudo ip -n ns-1 l set dev vf0_1 up
sudo ip -n ns-0 l set dev vf0_0 up 


 
