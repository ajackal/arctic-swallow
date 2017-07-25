import SocketServer
import sys
from threading import Thread
import binascii
from datetime import datetime
from termcolor import colored
import colorama

BUFFER_SIZE = 1024


class TCPEchoHandler(SocketServer.StreamRequestHandler):
    """ TCP Echo Handler listens on any port not previously listed.
    It simply echos any data that it receives back to the client.
    """
    def handle(self):
        try:
            self.DATA = self.request.recv(BUFFER_SIZE).strip()
            event = "[*] {0} wrote: {1}".format(self.client_address[0], self.DATA)
            write_event_log_event(event)
            print event
            self.request.sendall(self.DATA)
        except Exception as error:
            log_error = "[!] Error receiving data> {0} : {1}".format(self.client_address[0], error)
            print log_error
            write_error_log_event(str(log_error))


class TelnetHandler(SocketServer.StreamRequestHandler):
    """ Telnet Handler listens on port 8023 for telnet requests & mimics an XP telnet service. """
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
            log_error = "[!] Error receiving data> {0} : {1}".format(self.client_address[0], error)
            print log_error
            write_error_log_event(str(log_error))

    def send_response(self, response_file):
        """ Send Response
        1. opens the correct response_file
        2. reads binary to buffer
        3. sends the response to the client
        """
        with open(response_file, 'rb') as pkt_capture:
            response = pkt_capture.read()
        self.request.sendall(response)
        print "[*] Response packet sent."


class NetBiosHandler(SocketServer.StreamRequestHandler):
    """ NetBios Handler listens for and sends reponses for NetBios protocol. """
    def handle(self):
        netbios_error_bin = "pcaps/netbios_error"
        try:
            self.DATA = self.request.recv(BUFFER_SIZE).strip()
            event = "[*] {0} wrote over Port 139: {1}".format(self.client_address[0], self.DATA)
            write_event_log_event(event)
            response_file = netbios_error_bin
            self.send_response(response_file)
        except Exception as error:
            log_error = "[!] Error receiving data> {0} : {1}".format(self.client_address[0], error)
            print log_error
            write_error_log_event(str(log_error))

    def send_response(self, response_file):
        """ Send Response
        1. opens the correct response_file
        2. reads binary to buffer
        3. sends the response to the client
        """
        with open(response_file, 'rb') as pkt_capture:
            response = pkt_capture.read()
        self.request.sendall(response)
        print "[*] Response packet sent."


class MsrpcHandler(SocketServer.StreamRequestHandler):
    """ MSRPC Handler handles any port defined in the MSRPC port list """
    def handle(self):
        msrpc_error_bin = "pcaps/msrpc_error"
        try:
            self.DATA = self.request.recv(BUFFER_SIZE).strip()
            event = "[*] {0} wrote over Port: {1}".format(self.client_address[0], self.DATA)
            write_event_log_event(event)
            response_file = msrpc_error_bin
            self.send_response(response_file)
        except Exception as error:
            log_error = "[!] Error receiving data> {0} : {1}".format(self.client_address[0], error)
            print log_error
            write_error_log_event(str(log_error))

    def send_response(self, response_file):
        """ Send Response
        1. opens the correct response_file
        2. reads binary to buffer
        3. sends the response to the client
        """
        with open(response_file, 'rb') as pkt_capture:
            response = pkt_capture.read()
        self.request.sendall(response)
        print "[*] Response packet sent."


class SMBHandler(SocketServer.StreamRequestHandler):
    """ SMB Handler binds to port 8445 for to run unprivileged. """
    def check_smb_header(self, pkt_hex):
        """ SMB HEADER
        Server Component: SMB
        SMB Command: Negotiate Protocol (0x72)
        SMB Negotiate Request NTLM 0.12
        Session Setup: NT STATUS_SUCCESS
        Session Setup: NT STATUS_ACCOUNT_DISABLED
        Session Setup: NTLMSSP
        Session close: NT STATUS_SUCCESS
        """
        smb_header = {"header": "\xff\x53\x4d\x42\x72",
                      "negotiate_ntlm": "\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00",
                      "session_setup": "\xff\x53\x4d\x42\x73\x00\x00\x00\x00",
                      "account_disabled": "\xff\x53\x4d\x42\x73\x72\x00\x00\xc0",
                      "negotiate_ntlmssp": "\x4e\x54\x4c\x4d\x53\x53\x50\x00",
                      "session_close": "\xff\x53\x4d\x42\x74\x00\x00\x00\x00"
                     }
        # SMB Header NMAP request all Dialects:
        smb_nmap_all_dialects = "pcaps/smb_nmap_all_dialects"
        with open(smb_nmap_all_dialects, 'rb') as pkt_capture:
            smb_nmap_all_dialects_bytes = pkt_capture.read()
            pkt_hex_nmap_dialects = ""
            for i in smb_nmap_all_dialects_bytes:
                pkt_hex = binascii.hexlify(i)
                pkt_hex_nmap_dialects += "\\x" + pkt_hex
        # SMB Session Setup andX Request: \guest
        smb_nmap_setup_andx = "pcaps/smb_nmap_guest_connect"
        with open(smb_nmap_setup_andx, 'rb') as pkt_capture:
            smb_nmap_guest_connect_bytes = pkt_capture.read()
            pkt_hex_nmap_guest_connect = ""
            for i in smb_nmap_guest_connect_bytes:
                pkt_hex = binascii.hexlify(i)
                pkt_hex_nmap_guest_connect += "\\x" + pkt_hex
                # SMB Response: Win10 Home
        # File to read binary from:
        smb_response = {"negotiate_response": "pcaps/smb_response_win10",
                        "negotiate_ntlm": "pcaps/smb_negotiate_ntlm_workgroup",
                        "session_startup": "pcaps/smb_session_response_win10",
                        "guest_connect": "pcaps/smb_nmap_guest_connect",
                        "account_disabled": "pcaps/smb_account_disabled_response_win10",
                        "negotiate_ntlm_win10": "pcaps/smb_ntlmssp_response_win10",
                        "session_close": "pcaps/smb_session_close_response"
                       }
        # smb_negotiate_ntlm_response = "pcaps/smb_ntlm_response_win10"
        try:
            if pkt_hex.find(smb_header['header']):
                if pkt_hex.find(pkt_hex_nmap_dialects):
                    event = "[*] SMB Header - NMAP request for all \
                            dialects from {0}".format(self.client_address[0])
                    write_event_log_event(event)
                    self.send_response(smb_response['negotiate_response'])
                if pkt_hex.find(smb_header['negotiate_ntlm']):
                    event = "[*] SMB Header - Negotiate Session NTLM \
                            detected from {0}".format(self.client_address[0])
                    write_event_log_event(event)
                    self.send_response(smb_response['negotiate_ntlm'])
                else:
                    # Send response if Header is found.
                    event = "[*] SMB Header - Negotiate Session was \
                            detected from {0}".format(self.client_address[0])
                    write_event_log_event(event)
                    self.send_response(smb_response['negotiate_response'])
            if pkt_hex.find(smb_header['session_setup']):
                if pkt_hex.find(pkt_hex_nmap_guest_connect):
                    event = "[*] SMB Header - Session Setup and X \
                            detected from {0}".format(self.client_address[0])
                    write_event_log_event(event)
                    self.send_response(smb_response['guest_connect'])
                if pkt_hex.find(smb_header['negotiate_ntlmssp']):
                    event = "[*] SMB Header - Session Startup NTLMSSP \
                            detected from {0}".format(self.client_address[0])
                    write_event_log_event(event)
                    self.send_response(smb_response['negotiate_ntlmssp'])
                else:
                    # Send account disabled response to start up request.
                    event = "[*] SMB Header - Session Setup detected \
                            from {0}".format(self.client_address[0])
                    write_event_log_event(event)
                    self.send_response(smb_response['session_startup'])
            if pkt_hex.find(smb_header['account_disabled']):
                # Send LANMAN info to requester
                event = "[*] SMB Header - LANMAN information requested \
                        from {0}".format(self.client_address[0])
                print event
                write_event_log_event(event)
                self.send_response(smb_response['account_disabled'])
            if pkt_hex.find(smb_header['session_close']):
                # Send session close.
                event = "[*] SMB Header - Session Close detected \
                        from {0}".format(self.client_address[0])
                print event
                write_event_log_event(event)
                self.send_response(smb_response['session_close'])
            else:
                self.request.sendall(self.DATA)
        except Exception as error:
            log_error = "[!] Error receiving data from socket \
                    with {0} : {1}".format(self.client_address[0], error)
            write_error_log_event(str(log_error))

    def handle(self):
        """ Main methods in the SMB Handler
        1. reads the inbound request from the client
        2. determines the SMB request type by reading the SMB header
        3. defines the appropriate response and file
        4. calls the reponse method
        """
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
            self.check_smb_header(pkt_hex)
        except Exception as error:
            log_error = "[!] Error receiving data from socket \
                    with {0} : {1}".format(self.client_address[0], error)
            write_error_log_event(str(log_error))

    def send_response(self, response_file):
        """ Send Response
        1. opens the correct response_file
        2. reads binary to buffer
        3. sends the response to the client
        """
        with open(response_file, 'rb') as pkt_capture:
            response = pkt_capture.read()
        self.request.sendall(response)
        print "[*] Response packet sent."


class HoneyPotHandler(Thread):
    """HoneyPotHandler
    1. reads the port as an argument
    2. determines which handler to run based of the port
    3. determines what address to listen on
    4. starts the SocketServer with the appropriate handler.
    5. logs the events
    6. tells the server to live forever (run indefinitely)
    """
    def __init__(self, port):
        Thread.__init__(self)
        self.port = port
        self.msrpc_ports = ['8135', '49152', '49153', '49154', '49155']

    def run(self):
        if self.port == '8445':
            handler_type = SMBHandler
        elif self.port == '8023':
            handler_type = TelnetHandler
        elif self.port in self.msrpc_ports:
            handler_type = MsrpcHandler
        elif self.port == '8139':
            handler_type = NetBiosHandler
        else:
            handler_type = TCPEchoHandler
        try:
            if int(self.port) < 1024:
                listening_host = 'localhost'
            else:
                try:
                    listening_host = sys.argv[2]
                except IndexError:
                    listening_host = 'localhost'
            server = SocketServer.TCPServer((listening_host, int(self.port)), handler_type)
            event = "[*] {0} handler started on {1}:{2}".format(str(handler_type),\
                                                                listening_host, self.port)
            write_event_log_event(event)
            server.serve_forever()
        except Exception as error:
            error = "[!] There was an error establishing a handler because {0}".format(error)
            write_error_log_event(error)


def build_ports_list():
    """Build Ports List
    1. reads input file given
    2. writes the ports to a list
    3. logs the events
    """
    ifile = str(sys.argv[1])

    with open(ifile, 'r') as i:
        global ports
        ports = i.readlines()
        ports = [x.strip('\n') for x in ports]
    event = "[*] will start listening on: {0}".format(ports)
    write_event_log_event(event)
    return ports


def build_pot():
    """ Build Pot
    This function builds the threads that will make the pot.
    It will also adjust privileged ports to unprivileged ports.
    Starts and Joins threads.
    """
    thread_list = []
    for port in ports:
        if int(port) < 1024:
            if int(port) < 100:
                port = "80" + port
            else:
                port = "8" + port
        event = "[*] Starting handler on port {0}".format(port)
        write_event_log_event(event)
        new_thread = HoneyPotHandler(port)
        thread_list.append(new_thread)
    for thread in thread_list:
        thread.start()
    for thread in thread_list:
        thread.join()


def write_event_log_event(event):
    """ Writes all events to 'event.log' with date & time. """
    log_time = str(datetime.now())
    print event
    log_file = "event.log"
    with open(log_file, 'a') as event_log:
        event_log.write(log_time + event + "\n")


def write_error_log_event(error):
    """ Writes all errors to 'error.log' with date & time. """
    log_time = str(datetime.now())
    print error
    log_file = "error.log"
    with open(log_file, 'a') as error_log:
        error_log.write(log_time + error + "\n")


def print_usage():
    """ Prints the program useage when:
        1. No argument for the ports list is given.
        2. User inputs "?" option.
    """
    print "arctic-swallow.py {0} {1}".format(colored('<ports.txt>', 'red'),
                                            colored('<IP-address>', 'yellow'))
    print "\t{0} = text file with ports listed, one per line".format(colored('<ports.txt>', 'red'))
    print "\t[!] Don't forget to set up port forwarding with {0}".format(colored("'ipt_config.sh'",
                                                                                'green'))
    print "\t[!] Don't forget to set up {0} for full packet capture!".format(colored("TCPDUMP",
                                                                             'yellow'))
    # don't think we need this options.
    # iptables will forward from all IPs to localhost with one honeypot running
    # print "\t{0} = IP Address to listen on for \
    #        non-privileged ports.".format(colored('<IP-address>', 'yellow'))
    exit(0)


def main():
    """ Main Function
    1. initiates colorama for terminal colors on Windows.
    2. checks for proper inputs, displays help menu.
    3. runs function to build the ports list.
        a. modifies any privileged port to unprivileged port.
    4. builds and runs the honey pot.
    """
    colorama.init()
    try:
        sys.argv[1]
    except IndexError:
        print_usage()
    if sys.argv[1] == "?":
        print_usage()
    else:
        print "[*] Don't forget to:"
        print colored("[!]Setup port forwarding with 'ipt_setup.sh'!!", 'green')
        print colored("[!]Setup full packet capture with 'tcpdump'!!", 'yellow')
        print "[*] Building ports list for handlers."
        build_ports_list()
        print "[*] Starting handlers."
        build_pot()


if __name__ == "__main__":
    main()
