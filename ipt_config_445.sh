#! /bin/bash
sudo iptables -t nat -F
sudo iptables -t nat -A PREROUTING -p tcp --dport 445 -j REDIRECT --to-port 8445
sudo iptables -t nat -A OUTPUT -p tcp --dport 445 -j REDIRECT --to-port 8445
sudo iptables -t nat -S
