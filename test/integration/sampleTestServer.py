#!/usr/bin/python3

import socket
import ssl
import os
import signal
import sys
import atexit
import time

SSL_SERVER_PORT = 54321
KMYTH_ROOT = os.getcwd()
SERVER_KEY_PATH = KMYTH_ROOT + '/test/integration/key/server.key'
SERVER_CERT_PATH = KMYTH_ROOT + '/test/integration/cert/server.pem'
CA_CERT_PATH = KMYTH_ROOT + '/test/integration/cert/server.pem'
DUMMY_BYTES_VALUE = 'd53e3f024ae6a8d7bb6dff10e6eb89437c408de378918d2832361d4c6541a13a'
PIDFILE = '/tmp/sampleTestServer.pid'


# daemonize - supports starting/stopping as a daemon
def daemonize(pidfile):

    print('KMYTH_ROOT = ', KMYTH_ROOT)

    # check to see if already running
    if os.path.exists(pidfile):
        raise RuntimeError('sampleTestServer.py: already running ...')

    # write the PID file
    with open(pidfile, 'w') as f:
        print(os.getpid(), file=f)

    # setup PID file removal on exit/signal
    atexit.register(lambda: os.remove(pidfile))

    # signal handler for termination
    def signal_handler(signal, frame):
        try:
            print('sampleTestServer.py: exiting ...')
            ssl_conn.close()
            server_socket.close()
        except:
            pass
        raise SystemExit(1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


# main - sampleTestServer functionality
def main():

    print('KMYTH_ROOT = ', KMYTH_ROOT)

    print('sampleTestServer.py: starting ...')

    # serve until stopped
    while True:

        # initialize socket and bind to SSL_SERVER_PORT
        print('sampleTestServer.py: initializing and binding socket ...')
        server_socket = socket.socket()
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', SSL_SERVER_PORT))

        # wait for client connection (listen) on SSL_SERVER_PORT
        server_socket.listen(5)
        print('sampleTestServer.py: waiting for ssl client on port ', end='')
        print('{}'.format(SSL_SERVER_PORT))

        # write DUMMY_BYTES_VALUE to socket on client connection
        newsocket, fromaddr = server_socket.accept()
        ssl_conn = ssl.wrap_socket(newsocket,
                                   server_side=True,
                                   certfile=SERVER_CERT_PATH,
                                   keyfile=SERVER_KEY_PATH,
                                   ssl_version=ssl.PROTOCOL_TLSv1_2,
                                   cert_reqs=ssl.CERT_REQUIRED,
                                   ca_certs=CA_CERT_PATH)
        cert = ssl_conn.getpeercert()
        ssl_conn.write(bytes.fromhex(DUMMY_BYTES_VALUE))
        print('sampleTestServer.py: served SSL client ...')
        print('sampleTestServer.py: closing SSL connection ...')
        ssl_conn.close()
        server_socket.close()


if __name__ == '__main__':

    # check for attempt to start daemon with invalid number of arguments
    if len(sys.argv) != 2:
        print('Usage: {} [start|stop]'.format(sys.argv[0]))
        raise SystemExit(1)

    # start daemon
    if sys.argv[1] == 'start':
        try:
            daemonize(PIDFILE);

        except RuntimeError as e:
            print(e)
            raise SystemExit(1)
        main()

    # stop daemon
    elif sys.argv[1] == 'stop':
        if os.path.exists(PIDFILE):
            with open(PIDFILE) as f:
                os.kill(int(f.read()), signal.SIGTERM)
        else:
            print('sampleTestServer.py: daemon not running ...')
            raise SystemExit(1)

    # invalid daemon command (not 'start' or 'stop')
    else:
        print('sampleTestServer.py: unknown command: {}'.format(sys.argv[1]))
        raise SystemExit(1)

