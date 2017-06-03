import socket
import sys

ip_addr = 'localhost'
tcp_port = raw_input("[*] Connect to port: ")

buffer_size = 1024
message_to_server = "bite my shiny metal @ss"

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except Exception as e:
    print e

s.connect((ip_addr, int(tcp_port)))

try:
    s.send(message_to_server)
    print "[*] sending: {0}".format(message_to_server)
except socket.error as e:
    print e

data = s.recv(buffer_size)
s.close()

print "[*] Response from server: {0}".format(data)
