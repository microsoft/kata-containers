#!/bin/bash
set -e

default_gateway_ip="$(ip route show default | cut -d' ' -f 3)"
eth0_subnet="$(ip -o -f inet addr show eth0 | grep -oP 'inet \K[\d./]+')"
eth0_ip="${eth0_subnet%%/*}"

randomnum1=$(echo "$eth0_ip" | cut -d '.' -f 4)
randomnum2=$((256 - randomnum1))
eztif0_subnet="10.100.${randomnum1}.1/24"
eztif1_subnet="10.100.${randomnum1}.254/24"

eztif0_ip="${eztif0_subnet%%/*}"
eztif1_ip="${eztif1_subnet%%/*}"
eztif_subnet="10.100.${randomnum1}.0/24"

wgport="51820"
wgsubnet="10.0.0.${randomnum2}/32"
wgip="${wgsubnet%%/*}"
wgdir="wgconfig"
table="123"

multicast_udp_port="51850"

echo "eth0_ip $eth0_ip"
echo "eztif0_ip $eztif0_ip"
echo "eztif1_ip $eztif1_ip"
echo "wg_ip $wgip"
echo "wgport $wgport"

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

ip netns exec eztns ip route add default via $default_gateway_ip dev eth0
ip route add default via $eztif1_ip dev eztif0
iptables -t nat -A OUTPUT -o eztif0 -d $eth0_ip -j DNAT --to-destination $eztif0_ip

ip netns exec eztns ip link add wg0 type wireguard
ip netns exec eztns ip addr add $wgsubnet dev wg0

pushd /tmp
mkdir $wgdir
pushd $wgdir
wg genkey | tee privatekey | wg pubkey > publickey

PRIVATEKEY=$(cat privatekey)
PUBLICKEY=$(cat publickey)

echo "[Interface]
PrivateKey = $PRIVATEKEY
ListenPort = $wgport" >> wg-private.conf

echo "wgpublickey $PUBLICKEY"
ip netns exec eztns wg setconf wg0 wg-private.conf
echo "!!!NOTE!!!: Setup peer config after setting the correct ips and pubkeys"
ip netns exec eztns ip link set wg0 up
popd
popd

ip netns exec eztns ip rule add from $eztif0_ip table $table
ip netns exec eztns ip route add default via $wgip dev wg0 table $table
ip netns exec eztns ip route add $eztif_subnet dev eztif1 proto kernel scope link src $eztif1_ip table $table

echo "Applying port forwarding.."
ip netns exec eztns iptables -t nat -A PREROUTING -p tcp ! -i eztif1 -j DNAT --to-destination $eztif0_ip
ip netns exec eztns iptables -t nat -A PREROUTING -p udp ! -i eztif1 --match multiport ! --dport $wgport,$multicast_udp_port -j DNAT --to-destination $eztif0_ip
