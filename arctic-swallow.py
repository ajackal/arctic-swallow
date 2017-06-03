# this is the initial honey pot file
import SocketServer
import sys
from threading import Thread


BUFFER_SIZE = 1024
LHOST = 'localhost'


class TCPEchoHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        self.DATA = self.request.recv(BUFFER_SIZE).strip()
        print "[*] {0} wrote: {1}".format(self.client_address[0], self.DATA)
        self.request.sendall(self.DATA)


class HoneyPotHandler(Thread):
    def __init__(self, port):
        Thread.__init__(self)
        self.port = port

    def run(self):
        try:
            server = SocketServer.TCPServer((LHOST, int(self.port)), TCPEchoHandler)
            print "[*] Echo handler started on {0}:{1}\n".format(LHOST, self.port)
            server.serve_forever()
        except Exception as e:
            print "[!] There was an error: {0} ".format(e)


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


def main():
    print "[*] Building ports list for handlers."
    build_ports_list()
    print "[*] Starting handlers."
    build_pot()

if __name__ == "__main__":
    main()
