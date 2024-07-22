#!/bin/bash
set -x
 
host_ip="$1"
 
if ip netns list | grep -q "eztns"; then
    eth0_subnet="$(ip netns exec eztns ip -o -f inet addr show eth0 | grep -oP 'inet \K[\d./]+')"
    eth0_ip="${eth0_subnet%%/*}"
 
    eztif0_subnet="$(ip -o -f inet addr show eztif0 | grep -oP 'inet \K[\d./]+')"
    eztif0_ip="${eztif0_subnet%%/*}"

    ip netns exec eztns ip link set eth0 netns 1
    ip link set eth0 up
 
    all_ports="$(ss -tuln | grep 'LISTEN' | grep -o ':[0-9]*' | cut -d':' -f2 | sort -u)"
    for port in $all_ports; do
        ip netns exec eztns iptables -t nat -D PREROUTING -p tcp --dport $port -i eth0 -j DNAT --to-destination $eztif0_ip:$port
    done

    iptables -t nat -D OUTPUT -o eztif0 --destination $eth0_ip -j DNAT --to-destination $eztif0_ip

    ip link delete eztif0
 
    ip netns delete eztns
 
    ip addr add $eth0_subnet dev eth0
    ip route add default via $host_ip dev eth0
 
    echo "Cleanup completed successfully."
else
    echo "Namespace 'eztns' does not exist. No cleanup necessary."
fi
