import SocketServer
import sys
from threading import Thread
import binascii
from termcolor import colored
import colorama
import random


LHOST = 'localhost'
BUFFER_SIZE = 1024


class TCPEchoHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        try:
            self.DATA = self.request.recv(BUFFER_SIZE).strip()
            event = "[*] {0} wrote: {1} {2}".format(self.client_address[0], self.request, self.DATA)
            write_event_log_event(event)
            self.request.sendall(self.DATA)
        except Exception as error:
            log_error = "[!] Error receiving data from socket with {0} : {1}".format(self.client_address[0], error)
            print log_error
            write_error_log_event(str(log_error))

    def check_hex(self):
        try:
            self.DATA = self.request.recv(BUFFER_SIZE).strip()
            # Convert DATA to hex
            pkt_hex = ""
            for i in self.DATA:
                # Converts each byte to hex
                pkt_hex_byte = binascii.hexlify(i)
                # Constructs hex bytes together in one string
                pkt_hex += "\\x" + pkt_hex_byte
        except Exception as e:
            print e


class InterceptorHandler(Thread):
    def __init__(self, port):
        Thread.__init__(self)
        self.port = port

    def run(self):
        # if self.port == '8445':
        #     x = SMBHandler
        # else:
        #     x = TCPEchoHandler
        x = TCPEchoHandler
        try:
            server = SocketServer.TCPServer((LHOST, int(self.port)), x)
            event = "[*] {0} handler started on {1}:{2}".format(str(x), LHOST, self.port)
            write_event_log_event(event)
            server.serve_forever()
        except Exception as error:
            error = "[!] There was an error establishing a handler because {0}".format(error)
            write_error_log_event(error)


def read_domain_list():
    ifile = str(sys.argv[1])

    with open(ifile, 'r') as i:
        global domains
        domains = i.readlines()
        domains = [x.strip('\n') for x in domains]
    event = "[*] targeting these domains: "
    write_event_log_event(event)
    for i in domains:
        event = str(i).strip('')
        write_event_log_event(event)
    return domains


def setup_interceptor():
    thread_list = []
    PORT = random.randint(8500, 8999)
    event = "[*] Starting interceptor on port {0}".format(PORT)
    write_event_log_event(event)
    t = InterceptorHandler(PORT)
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


def print_usage():
    print "arctic-swallow-interceptor.py {0} {1}".format(colored('<domains.txt>', 'red'))
    print "\t{0} = text file with domains to target, listed one per line".format(colored('<ports.txt>', 'red'))
    exit(0)


def main():
    colorama.init()
    try:
        sys.argv[1]
    except IndexError:
        print_usage()
    if sys.argv[1] == "?":
        print_usage()
    else:
        print "[*] Building target list for interceptor."
        read_domain_list()
        print "[*] Starting interceptor."
        setup_interceptor()


if __name__ == "__main__":
    main()
