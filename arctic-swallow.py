# this is the initial honey pot file
import SocketServer
import sys
from threading import Thread


BUFFER_SIZE = 1024
LHOST = '192.168.1.184'


class TCPEchoHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        self.DATA = self.request.recv(BUFFER_SIZE).strip()
        event = "[*] {0} wrote: {1}".format(self.client_address[0], self.DATA)
        write_event_log_event(event)
        print event
        self.request.sendall(self.DATA)


class SMBHandler(SocketServer.StreamRequestHandler):
    def handle(self):
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
        self.DATA = self.request.recv(BUFFER_SIZE).strip()
        # Convert DATA to hex
        pkt_hex = ""
        for i in self.DATA:
            # Converts each byte to hex
            pkt_hex_byte = hex(ord(i))
            # Constructs hex bytes together in one string
            pkt_hex += pkt_hex_byte
        # Check DATA for SMB Header in Hex
        if smb_header in pkt_hex:
            # Send reponse if Header is found.
            self.request.sendall(smb_response_win10_home)



class HoneyPotHandler(Thread):
    def __init__(self, port):
        Thread.__init__(self)
        self.port = port

    def run(self):
        if self.port is 8445:
            x = SMBHandler
        else:
            x = TCPEchoHandler
        try:
            server = SocketServer.TCPServer((LHOST, int(self.port)), x)
            print "[*] Echo handler started on {0}:{1}\n".format(LHOST, self.port)
            server.serve_forever()
        except Exception as log_error:
            print "[!] There was an error: {0} ".format(log_error)
            write_error_log_event(log_error)


def build_ports_list():
    ifile = str(sys.argv[1])

    with open(ifile, 'r') as i:
        global ports
        ports = i.readlines()
        ports = [x.strip('\n') for x in ports]
    print "[*] will start listening on: {0}".format(ports)
    return ports


def build_pot():
    thread_list = []
    for port in ports:
        print "[*] Starting handler on port {0}".format(port)
        t = HoneyPotHandler(port)
        thread_list.append(t)
    for thread in thread_list:
        thread.start()
    for thread in thread_list:
        thread.join()


def write_event_log_event(event):
    # add datetime to log name
    log_file = "event.log"
    with open(log_file, 'a') as l:
        l.write(event)


def write_error_log_event(error):
    # add datetime to log name
    log_file = "error.log"
    with open(log_file, 'a') as l:
        l.write(error)


def main():
    print "[*] Building ports list for handlers."
    build_ports_list()
    print "[*] Starting handlers."
    build_pot()

if __name__ == "__main__":
    main()
