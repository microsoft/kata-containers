#!/bin/bash
set -x
eth0_subnet="$(ip -o -f inet addr show eth0 | grep -oP 'inet \K[\d./]+')"
eth0_ip="${eth0_subnet%%/*}"

eztif0_subnet="10.100.0.1/16"
eztif1_subnet="10.100.255.254/16"
host_ip="$1"

eztif0_ip="${eztif0_subnet%%/*}"
eztif1_ip="${eztif1_subnet%%/*}"
eztif_subnet="10.100.0.0/16"

#wgport="51820"
#wgsubnet="10.0.0.1/24"
#wgip="${wgsubnet%%/*}"
#wgdir="wgconfig"
#table="123"

ip netns add eztns
ip link set eth0 netns eztns
ip netns exec eztns ip addr add $eth0_subnet dev eth0
ip link add eztif0 type veth peer name eztif1 netns eztns
ip addr add $eztif0_subnet dev eztif0
ip netns exec eztns ip addr add $eztif1_subnet dev eztif1

ip link set lo up
ip link set eztif0 up
ip netns exec eztns ip link set lo up
ip netns exec eztns ip link set eth0 up
ip netns exec eztns ip link set eztif1 up

sysctl -w net.ipv4.ip_forward=1
ip netns exec eztns sysctl -w net.ipv4.ip_forward=1
ip netns exec eztns iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

ip netns exec eztns ip route add default via $host_ip dev eth0
ip route add default via $eztif1_ip dev eztif0
iptables -t nat -A OUTPUT -o eztif0 -d $eth0_ip -j DNAT --to-destination $eztif0_ip

all_ports="$(ss -tuln | grep 'LISTEN' | grep -o ':[0-9]*' | cut -d':' -f2 | sort -u)"
for port in $all_ports; do
        echo "Applying rules for port: $port"
        ip netns exec eztns iptables -t nat -A PREROUTING -p tcp --dport $port -i eth0 \
        -j DNAT --to-destination $eztif0_ip:$port
done
