#!/usr/bin/env python3

import sys
from websocket import create_connection


ws = create_connection("ws://localhost:8081")

while True :
    ret = ws.recv()
    print(ret)

ws.close()
