import sys
from threading import Thread
from termcolor import colored
import colorama
from handlers import *
import logging
from logger import Logger


class HoneyPotHandler(Thread):
    """ HoneyPotHandler
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
        # Enabling TCPEchoHandler only for right now
        # if self.port == '8445':
        #     handler_type = SMBHandler
        # elif self.port == '8023':
        #     handler_type = TelnetHandler
        # elif self.port in self.msrpc_ports:
        #     handler_type = MsrpcHandler
        # elif self.port == '8139':
        #     handler_type = NetBiosHandler
        # else:
        #     handler_type = TCPEchoHandler
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
            event = "{0} started on {1}:{2}".format(str(handler_type), listening_host, self.port)
            logging.info(event)
            print('[*] {0}\n'.format(event))
            server.serve_forever()
        except Exception as error:
            error = "There was an error establishing a handler because {0}".format(error)
            logging.error(error)
            print('[!] {0}\n'.format(error))


# TODO: fix broken logging method dependency.
class HoneyPot:
    def __init__(self):
        self.logger = Logger()
        self.ports = []

    def build_ports_list(self):
        """Build Ports List
        1. reads input file given
        2. writes the ports to a list
        3. logs the events
        """
        ports_list_file = str(sys.argv[1])

        with open(ports_list_file, 'r') as i:
            self.ports = i.readlines()
            self.ports = [x.strip('\n') for x in self.ports]
        event = "Will start listening on: {0}".format(self.ports)
        logging.info(event)
        print('[*] {0}\n'.format(event))
        return self.ports

    def build_pot(self):
        """ Build Pot
        This function builds the threads that will make the pot.
        It will also adjust privileged ports to unprivileged ports.
        Starts and Joins threads.
        """
        thread_list = []
        for port in self.ports:
            if int(port) < 1024:
                if int(port) < 100:
                    port = "80" + port
                else:
                    port = "8" + port
            event = "Starting handler on port {0}".format(port)
            logging.info(event)
            print('[*] {0}\n'.format(event))
            new_thread = HoneyPotHandler(port)
            thread_list.append(new_thread)
        for thread in thread_list:
            thread.start()
        for thread in thread_list:
            thread.join()

    def print_usage(self):
        """ Prints the program usage when:
            1. No argument for the ports list is given.
            2. User inputs "?" option.
        """
        print("arctic-swallow.py {0} {1}".format(colored('<ports.txt>', 'red'), colored('<IP-address>', 'yellow')))
        print("\t{0} = text file with ports listed, one per line".format(colored('<ports.txt>', 'red')))
        print("\t[!] Don't forget to set up port forwarding with {0}".format(colored("'ipt_config.sh'", 'green')))
        print("\t[!] Don't forget to set up {0} for full packet capture!".format(colored("TCPDUMP", 'yellow')))
        # don't think we need this options.
        # iptables will forward from all IPs to localhost with one honeypot running
        # print("\t{0} = IP Address to listen on for \
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
    Logger()
    colorama.init()
    hp = HoneyPot()
    try:
        sys.argv[1]
    except IndexError:
        hp.print_usage()
    if sys.argv[1] == "?":
        hp.print_usage()
    else:
        print("[*] Don't forget to:")
        print(colored("[!]Setup port forwarding with 'ipt_setup.sh'!!", 'green'))
        print(colored("[!]Setup full packet capture with 'tcpdump'!!", 'yellow'))
        print("[*] Building ports list for handlers.")
        hp.build_ports_list()
        print("[*] Starting handlers.")
        hp.build_pot()


if __name__ == "__main__":
    main()
