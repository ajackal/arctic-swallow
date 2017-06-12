import SocketServer
import sys
from threading import Thread
import binascii

BUFFER_SIZE = 1024
LHOST = 'localhost'


class TCPEchoHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        try:
            self.DATA = self.request.recv(BUFFER_SIZE).strip()
            event = "[*] {0} wrote: {1}".format(self.client_address[0], self.DATA)
            write_event_log_event(event)
            print event
            self.request.sendall(self.DATA)
        except Exception as error:
            log_error = "[!] Error receiving data from socket with {0} : {1}".format(self.client_address[0], error)
            print log_error
            write_error_log_event(str(log_error))


class TelnetHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        telnet_xp_response_bin = "pcaps/telnet_xp_response"
        try:
            self.DATA = self.request.recv(BUFFER_SIZE).strip()
            event = "[*] {0} wrote over Port 23: {1}".format(self.client_address[0], self.DATA)
            write_event_log_event(event)
            response_file = telnet_xp_response_bin
            self.send_response(response_file)
            # self.request.sendall("login: ")
        except Exception as error:
            log_error = "[!] Error receiving data from socket with {0} : {1}".format(self.client_address[0], error)
            print log_error
            write_error_log_event(str(log_error))

    def send_response(self, response_file):
        with open(response_file, 'rb') as f:
            response = f.read()
        self.request.sendall(response)
        print "[*] Response packet sent."


class NetBiosHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        netbios_error_bin = "pcaps/netbios_error"
        try:
            self.DATA = self.request.recv(BUFFER_SIZE).strip()
            event = "[*] {0} wrote over Port 139: {1}".format(self.client_address[0], self.DATA)
            write_event_log_event(event)
            response_file = netbios_error_bin
            self.send_response(response_file)
        except Exception as error:
            log_error = "[!] Error receiving data from socket with {0} : {1}".format(self.client_address[0], error)
            print log_error
            write_error_log_event(str(log_error))

    def send_response(self, response_file):
        with open(response_file, 'rb') as f:
            response = f.read()
        self.request.sendall(response)
        print "[*] Response packet sent."


class MsrpcHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        msrpc_error_bin = "pcaps/msrpc_error"
        try:
            self.DATA = self.request.recv(BUFFER_SIZE).strip()
            event = "[*] {0} wrote over Port: {1}".format(self.client_address[0], self.DATA)
            write_event_log_event(event)
            response_file = msrpc_error_bin
            self.send_response(response_file)
        except Exception as error:
            log_error = "[!] Error receiving data from socket with {0} : {1}".format(self.client_address[0], error)
            print log_error
            write_error_log_event(str(log_error))

    def send_response(self, response_file):
        with open(response_file, 'rb') as f:
            response = f.read()
        self.request.sendall(response)
        print "[*] Response packet sent."


class SMBHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        # SMB HEADER
        # Server Component: SMB
        # SMB Command: Negotiate Protocol (0x72)
        smb_header_negotiate = "\xff\x53\x4d\x42\x72"
        # SMB Header NMAP request all Dialects:
        smb_nmap_all_dialects = "pcaps/smb_nmap_all_dialects"
        with open(smb_nmap_all_dialects, 'rb') as f:
            smb_nmap_all_dialects_bytes = f.read()
            pkt_hex_nmap_dialects = ""
            for i in smb_nmap_all_dialects_bytes:
                pkt_hex = binascii.hexlify(i)
                pkt_hex_nmap_dialects += "\\x" + pkt_hex
        # SMB Session Setup andX Request: \guest
        smb_nmap_setup_andx = "pcaps/smb_nmap_guest_connect"
        with open(smb_nmap_setup_andx, 'rb') as f:
            smb_nmap_guest_connect_bytes = f.read()
            pkt_hex_nmap_guest_connect = ""
            for i in smb_nmap_guest_connect_bytes:
                pkt_hex = binascii.hexlify(i)
                pkt_hex_nmap_guest_connect += "\\x" + pkt_hex
        # SMB Negotiate Request NTLM 0.12
        smb_negotiate_ntlm = "\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
        # Session Setup: NT STATUS_SUCCESS
        smb_header_session_setup = "\xff\x53\x4d\x42\x73\x00\x00\x00\x00"
        # Session Setup: NT STATUS_ACCOUNT_DISABLED
        smb_header_account_disabled = "\xff\x53\x4d\x42\x73\x72\x00\x00\xc0"
        # Session Setup: NTLMSSP
        smb_negotiate_ntlmssp = "\x4e\x54\x4c\x4d\x53\x53\x50\x00"
        # Session close: NT STATUS_SUCCESS
        smb_session_close = "\xff\x53\x4d\x42\x74\x00\x00\x00\x00"
        # SMB Response: Win10 Home
        # File to read binary from:
        #if win_ver == "10":
        smb_negotiate_response = "pcaps/smb_response_win10"
        # smb_negotiate_ntlm_response = "pcaps/smb_ntlm_response_win10"
        smb_negotiate_ntlm_response = "pcaps/smb_negotiate_ntlm_workgroup"
        smb_session_startup_response = "pcaps/smb_session_response_win10"
        smb_nmap_guest_connect_response = "pcaps/smb_nmap_guest_connect"
        smb_account_disabled_response = "pcaps/smb_account_disabled_response_win10"
        smb_negotiate_ntlmssp_response = "pcaps/smb_ntlmssp_response_win10"
        smb_session_close_response = "pcaps/smb_session_close_response"
        #if win_ver == "vista":

        # Get DATA from socket
        try:
            self.DATA = self.request.recv(BUFFER_SIZE).strip()
            # Convert DATA to hex
            pkt_hex = ""
            for i in self.DATA:
                # Converts each byte to hex
                pkt_hex_byte = binascii.hexlify(i)
                # Constructs hex bytes together in one string
                pkt_hex += "\\x" + pkt_hex_byte
            # Check DATA for SMB Header in Hex
            if pkt_hex.find(smb_header_negotiate):
                if pkt_hex.find(pkt_hex_nmap_dialects):
                    event = "[*] SMB Header - NMAP request for all dialects from {0}".format(self.client_address[0])
                    write_event_log_event(event)
                    response_file = smb_negotiate_response
                    self.send_response(response_file)
                if pkt_hex.find(smb_negotiate_ntlm):
                    event = "[*] SMB Header - Negotiate Session NTLM detected from {0}".format(self.client_address[0])
                    write_event_log_event(event)
                    response_file = smb_negotiate_ntlm_response
                    self.send_response(response_file)
                else:
                    # Send response if Header is found.
                    event = "[*] SMB Header - Negotiate Session was detected from {0}".format(self.client_address[0])
                    write_event_log_event(event)
                    response_file = smb_negotiate_response
                    self.send_response(response_file)
            if pkt_hex.find(smb_header_session_setup):
                if pkt_hex.find(pkt_hex_nmap_guest_connect):
                    event = "[*] SMB Header - Session Setup andX detected from {0}".format(self.client_address[0])
                    write_event_log_event(event)
                    response_file = smb_nmap_guest_connect_response
                    self.send_response(response_file)
                if pkt_hex.find(smb_negotiate_ntlmssp):
                    event = "[*] SMB Header - Session Startup NTLMSSP detected from {0}".format(self.client_address[0])
                    write_event_log_event(event)
                    response_file = smb_negotiate_ntlmssp_response
                    self.send_response(response_file)
                else:
                    # Send account disabled response to start up request.
                    event = "[*] SMB Header - Session Setup detected from {0}".format(self.client_address[0])
                    write_event_log_event(event)
                    response_file = smb_session_startup_response
                    self.send_response(response_file)
            if pkt_hex.find(smb_header_account_disabled):
                # Send LANMAN info to requester
                event = "[*] SMB Header - LANMAN information requested from {0}".format(self.client_address[0])
                print event
                write_event_log_event(event)
                response_file = smb_account_disabled_response
                self.send_response(response_file)
            if pkt_hex.find(smb_session_close):
                # Send session close.
                event = "[*] SMB Header - Session Close detected from {0}".format(self.client_address[0])
                print event
                write_event_log_event(event)
                response_file = smb_session_close_response
                self.send_response(response_file)
            else:
                self.request.sendall(self.DATA)
        except Exception as error:
            log_error = "[!] Error receiving data from socket with {0} : {1}".format(self.client_address[0], error)
            print log_error
            write_error_log_event(str(log_error))

    def send_response(self, response_file):
        # self.response_file = response_file
        with open(response_file, 'rb') as f:
            response = f.read()
        self.request.sendall(response)
        print "[*] Response packet sent."


class HoneyPotHandler(Thread):
    def __init__(self, port):
        Thread.__init__(self)
        self.port = port
        self.msrpc_ports = ['8135', '49152', '49153', '49154', '49155']
        # TODO: set if statement to bind ports > 1024 to ip.addr not localhost

    def run(self):
        if self.port == '8445':
            x = SMBHandler
        elif self.port == '8023':
            x = TelnetHandler
        elif self.port in self.msrpc_ports:
            x = MsrpcHandler
        elif self.port == '8139':
            x = NetBiosHandler
        else:
            x = TCPEchoHandler
        try:
            server = SocketServer.TCPServer((LHOST, int(self.port)), x)
            event = "[*] {0} handler started on {1}:{2}".format(str(x), LHOST, self.port)
            write_event_log_event(event)
            server.serve_forever()
        except Exception as error:
            error = "[!] There was an error establishing a handler because {0}".format(error)
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
        if int(port) < 1024:
            if int(port) < 100:
                port = "80" + port
            else:
                port = "8" + port
        event = "[*] Starting handler on port {0}".format(port)
        write_event_log_event(event)
        t = HoneyPotHandler(port)
        thread_list.append(t)
    for thread in thread_list:
        thread.start()
    for thread in thread_list:
        thread.join()


def write_event_log_event(event):
    # add datetime to log name
    print event
    log_file = "event.log"
    with open(log_file, 'a') as l:
        l.write(event + "\n")


def write_error_log_event(error):
    # add datetime to log name
    print error
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
