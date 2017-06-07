#!/usr/bin/env bash

value=$(<ports.txt)
for i in $value; do
    sudo iptables -t nat -A PREROUTING -p tcp --dport $1 -j REDIRECT --to-port $2
    sudo iptables -t nat -A OUTPUT -p tcp --dport $1 -j REDIRECT --to-port $2
done
sudo iptables -t nat -S