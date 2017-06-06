
import SocketServer
import sys
from threading import Thread


BUFFER_SIZE = 1024
LHOST = 'localhost'


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
        smb_header_negotiate = "0xff0x530x4d0x420x72"
        # Session Setup: NT STATUS_SUCCESS
        smb_header_session_setup = "0xff0x530x4d0x420x730x000x000x000x00"
        # Session Setup: NT STATUS_ACCOUNT_DISABLED
        smb_header_account_disabled = "0xff0x530x4d0x420x730x720x000x000xc0"
        # Session close: NT STATUS_SUCCESS
        smb_session_close = "0xff0x530x4d0x420x740x000x000x000x00"
        # SMB Response: Win10 Home
        # File to read binary from:
        smb_negotiate_response = "pcaps/smb_response_win10"
        smb_session_startup_response = "pcaps/smb_session_response_win10"
        smb_account_disabled_response = "pcaps/smb_account_disabled_response_win10"
        smb_session_close_response = "pcaps/smb_session_close_response"
        # Get DATA from socket
        try:
            self.DATA = self.request.recv(BUFFER_SIZE).strip()
            # Convert DATA to hex
            pkt_hex = ""
            for i in self.DATA:
                # Converts each byte to hex
                pkt_hex_byte = hex(ord(i))
                # Constructs hex bytes together in one string
                pkt_hex += pkt_hex_byte
            # Check DATA for SMB Header in Hex
            if smb_header_negotiate in pkt_hex:
                # Send response if Header is found.
                event = "[*] SMB Header - Negotiate Session was detected from{0}".format(\
                    self.client_address[0])
                print event
                write_event_log_event(event)
                response_file = smb_negotiate_response
                self.send_response(response_file)
            if smb_header_session_setup in pkt_hex:
                # Send account disabled response to start up request.
                event = "[*] SMB Header - Session Setup detected from {0}".format(\
                    self.client_address[0]) 
                print event
                write_event_log_event(event)
                response_file = smb_session_startup_response
                self.send_response(response_file)
            if smb_header_account_disabled in pkt_hex:
                # Send LANMAN info to requester
                event = "[*] SMB Header - LANMAN information requested from {0}\
                ".format(self.client_address[0])
                print event
                write_event_log_event(event)
                response_file = smb_account_disabled_repsonse
                self.send_response(response_file)
            if smb_session_close in pkt_hex:
                # Send session close.
                event  = "[*] SMB Header - Session Close detected from {0}".format(\
                    self.client_address[0])
                print event
                write_event_log_event(event)
                response_file = smb_close_response
                self.send_response(response_file)
            else:
                self.request.sendall(self.DATA)
        except Exception as log_error:
            log_error = "[!] Error receiving data from socket with {0} because {1}".format(\
                self.client_address[0], error)
            print log_error
            write_error_log_event(str(log_error))


    def send_response(self, response_file):
        self.response_file = response_file
        with open(self.response_file, 'rb') as f:
            response = f.read()
        self.request.sendall(response)


class HoneyPotHandler(Thread):
    def __init__(self, port):
        Thread.__init__(self)
        self.port = port

    def run(self):
        if self.port == '8445':
            x = SMBHandler
        else:
            x = TCPEchoHandler
        try:
            server = SocketServer.TCPServer((LHOST, int(self.port)), x)
            event = "[*] {0} handler started on {1}:{2}".format(x, LHOST, self.port)
            print event
            write_event_log_event(event)
            server.serve_forever()
        except Exception as error:
            error = "[!] There was an error establishing a handler because {0}".format(\
                                                                                error)
            print error
            write_error_log_event(error)


def build_ports_list():
    ifile = str(sys.argv[1])

    with open(ifile, 'r') as i:
        global ports
        ports = i.readlines()
        ports = [x.strip('\n') for x in ports]
    event = "[*] will start listening on: {0}".format(ports)
    write_event_log_event(event)
    return ports


def build_pot():
    thread_list = []
    for port in ports:
        event = "[*] Starting handler on port {0}".format(port)
        print event
        write_event_log_event(event)
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
        l.write(event + "\n")


def write_error_log_event(error):
    # add datetime to log name
    log_file = "error.log"
    with open(log_file, 'a') as l:
        l.write(error + "\n")


def main():
    print "[*] Building ports list for handlers."
    build_ports_list()
    print "[*] Starting handlers."
    build_pot()

if __name__ == "__main__":
    main()
