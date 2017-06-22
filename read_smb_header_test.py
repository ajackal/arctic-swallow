from scapy.all import *
from scapy.utils import PcapReader

# SMB HEADER
# Server Component: SMB
# SMB Command: Negotiate Protocol (0x72)
smb_header = "0xff0x530x4d0x420x72"
# SMB Response: Win10 Home
# File to read binary from:
smb_response_file = "pcaps\\smb_response_win10"
with open(smb_response_file, 'rb') as f:
    # Set variable with SMB response
    smb_response_win10_home = f.read()
# Get DATA from socket
with open("pcaps\\nmap_smb_scan.pcapng", 'rb') as p:
    raw = p.read()
    pcap_hex = ""
    for i in raw:
        read_pcap_hex = hex(ord(i))
        pcap_hex += read_pcap_hex
        # print read_pcap_hex
# Check DATA for SMB Header in Hex
if smb_header in pcap_hex:
    # Send reponse if Header is found.
    # self.request.sendall(smb_response_win10_home)
    print "SMB Header detected."
    print "Sending SMB response",
else:
    print "Nothing found!"
