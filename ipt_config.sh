#!/usr/bin/env bash

sudo iptables -t nat -F

value=$(<ports.txt)
for i in $value; do
    if [ $i -le 1024 ] && [ $i -ge 100 ]; then
    p=8$i;
    echo $p;
    elif [ $i -le 99 ]; then
        p=80$i;
        echo $p;
    else
        p=$i
    fi
    if [ $p -eq $i ]; then
        echo "[!] Non-privelaged port, no forwarding necessary " $p
    else
        sudo iptables -t nat -A PREROUTING -p tcp --dport $i -j REDIRECT --to-port $p
        sudo iptables -t nat -A OUTPUT -p tcp --dport $i -j REDIRECT --to-port $p
    fi
#    sudo iptables -t nat -A PREROUTING -p tcp --dport $i -j REDIRECT --to-port $p
#    sudo iptables -t nat -A OUTPUT -p tcp --dport $i -j REDIRECT --to-port $p
done
sudo iptables -t nat -S