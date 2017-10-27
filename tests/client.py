import socket
import sys
from itertools import product

# builds key list
characters_to_use = "0123456789"
keys_to_try = product(characters_to_use, repeat=2)

for key_pair in keys_to_try:
    key = key_pair[0] + key_pair[1]
    # print key

# define ip address and port to use
ip_addr = 'localhost'
tcp_port = 80

buffer_size = 1024
message_to_server = "bite my shiny metal @ss"

# opens socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except Exception as e:
    print e

# connects socket to ip address and port defined above
s.connect((ip_addr, tcp_port))

try:
    s.send(message_to_server)
    print "[*] sending: {0}".format(message_to_server)
except socket.error as e:
    print e

data = s.recv(buffer_size)
s.close()

print "[*] Response from server: {0}".format(data)
