#!/bin/bash
set -x
 
host_ip="$1"
 
if ip netns list | grep -q "eztns"; then
    eth0_subnet="$(ip netns exec eztns ip -o -f inet addr show eth0 | grep -oP 'inet \K[\d./]+')"
    eth0_ip="${eth0_subnet%%/*}"
 
    eztif0_subnet="$(ip -o -f inet addr show eztif0 | grep -oP 'inet \K[\d./]+')"
    eztif0_ip="${eztif0_subnet%%/*}"

    table="123"

    ip netns exec eztns ip link set eth0 netns 1
    ip link set eth0 up

    ip netns exec eztns iptables -t nat -D PREROUTING -p tcp ! -i eztif1 -j DNAT --to-destination $eztif0_ip
    ip netns exec eztns iptables -t nat -D PREROUTING -p udp ! -i eztif1 ! --dport $wgport -j DNAT --to-destination $eztif0_ip
    ip netns exec eztns iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

    ip netns exec eztns ip link del wg0

    rm -rf wgconfig

    ip link delete eztif0
 
    ip netns delete eztns
 
    ip addr add $eth0_subnet dev eth0
    ip route add default via $host_ip dev eth0
 
    echo "Cleanup completed successfully."
else
    echo "Namespace 'eztns' does not exist. No cleanup necessary."
fi
