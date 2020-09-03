#!/usr/bin/python3

import pathlib
import argparse
import signal
import sys
import glob
import subprocess
import atexit
import time
import re

#-----------------------------------------------------------------------------
# Test Key / Certificate Creation
#-----------------------------------------------------------------------------
def test_key_and_cert_creation(verbose_flag):
    if verbose_flag:
        print('Kmyth Integration Tests: test key / certificate creation')

    # Generate Test Key / Certificate for the Kmyth Client
    # openssl req -nodes -newkey rsa:2048 -keyout client.key -out client.pem -x509 -subj "/C=US/ST=State/L=City/O=Kmyth Test Entity/CN=Kmyth Test Client" -days 365

    # Generate Test Key / Certificate for the Key Server
    # openssl req -nodes -newkey rsa:2048 -keyout server.key -out server.pem -x509 -subj "/C=US/ST=State/L=City/O=Kmyth Test Entity/CN=Sample Key Server" -days 365

