#!/usr/bin/env python3

import sys
import time
import json
import dpkt
import pcapy
import socket
import argparse


from threading import Thread
from threading import Lock

import numpy as np
from keras.models import load_model
from keras.optimizers import RMSprop

from websocket_server import WebsocketServer

model = None # trained model h5 file
wssrv = None # WebSocketServer instance
interval = None # interval of export to websocket (for test)

predict_lock = Lock()


class SynPacket() :

    def __init__(self, ip_pkt) :
        tcp = ip_pkt.data

        self.src = socket.inet_ntoa(ip_pkt.src)
        self.timestamp = int(time.time() * 1000) # msec
        self.src_port = tcp.sport
        self.dst_port = tcp.dport
        self.win = tcp.win
        self.seq = tcp.seq


class SynPicture() :

    def __init__(self, addr) :
        self.addr = addr
        self.syn_packets = []

    def __str__(self) :
        return(str(self.syn_packets))

    def add_packet(self, ip_pkt) :
        
        self.syn_packets.append(SynPacket(ip_pkt))
        while len(self.syn_packets) > 100 :
            self.syn_packets.pop(0)

        return

    def parge(self) :
        self.syn_packets.clear()

    def ready(self) :
        if len(self.syn_packets) == 100 :
            return True
        return False

    def dump(self) :

        d = { "addr" : self.addr }

        pic = []

        for syn_pkt in self.syn_packets :
            pic.append([
                syn_pkt.timestamp, syn_pkt.src_port, syn_pkt.dst_port,
                syn_pkt.seq, syn_pkt.win
            ])
    
        # normalize between 0 ~ 1
        for x in range(len(pic[0])) :

            minimum = None
            maximum = None

            for y in range(len(pic)) :
                if not minimum or minimum > pic[y][x] :
                    minimum = pic[y][x]
                if not maximum or maximum < pic[y][x] :
                    maximum = pic[y][x]

            maximum = float(maximum)
            minimum = float(minimum)

            for y in range(len(pic)) :
                if maximum == minimum :
                    pic[y][x] = 0
                else :
                    pic[y][x] = (pic[y][x] - minimum) / (maximum - minimum)

                if pic[y][x] < 0 :
                    pic[y][x] = 0

        d["picture"] = pic

        return d
    


class Capture_wo_Thread:

    def __init__(self, dev):
        self.dev = dev
        self.hosts = {} # key addr, value SynPicture

    def start(self) :
        print("Start Capture without Threading")
        p = pcapy.open_live(self.dev, 128, True, 1)
        p.setfilter("tcp[13] & 255 == 2") # SYN only
        p.loop(-1, self.handle_packet)

    def handle_packet(self, header, data) :
        store(self.hosts, data)



class Capture(Thread) :

    def __init__(self, pcap) :
        self.pcap = pcap
        self.hosts = {} # key addr, value SynPicture
        Thread.__init__(self)

    def run(self) :
        while True:
            try :
                self.pcap.loop(0, self.handler)
            except Exception as e:
                print("pcap loop exception: %s" % e)
                

    def handler(self, header, data) :
        store(self.hosts, data)


class WebSocketServer(Thread) :

    def __init__(self, host = "172.16.18.220", port = 8081) :
        self.host = host
        self.port = port
        self.server = WebsocketServer(self.port, host = self.host)
        Thread.__init__(self)

    def run(self) :
        self.server.run_forever()

    def send_all(self, msg) :
        try :
            self.server.send_message_to_all(msg)
        except Exception as e:
            print(e)

        


def capture(dev) :

    p = pcapy.open_live(dev, 128, True, 1)
    p.setfilter("tcp[13] & 255 == 2") # SYN only
    Capture(p).start()


def readfile(filename, repeat = False) :

    hosts = {}
    p = dpkt.pcap.Reader(open(filename, "rb"))
    for header, data in p :
        store(hosts, data)
    
    if repeat :
        while True :
            p = dpkt.pcap.Reader(open(filename, "rb"))
            for header, data in p :
                store(hosts, data)

    
def store(hosts, pkt) :

    try :
        eth = dpkt.ethernet.Ethernet(pkt)
    except :
        return
        
    if type(eth.data) == dpkt.ip.IP :
        ip = eth.data
    else :
        return

    if type(ip.data) == dpkt.tcp.TCP :
        tcp = ip.data
    else :
        return

    ipsrc = socket.inet_ntoa(ip.src)
    if not ipsrc in hosts :
        hosts[ipsrc] = SynPicture(ipsrc)

    hosts[ipsrc].add_packet(ip)

    if hosts[ipsrc].ready() :
        probability = predict(hosts[ipsrc])
        if not probability :
            return
        d = hosts[ipsrc].dump()
        d["probability"] = probability
        wssrv.send_all(json.dumps(d))
        hosts[ipsrc].parge()
        if interval:
            time.sleep(interval)


def predict(synpic) :

    ret = predict_lock.acquire(False)
    if not ret :
        return False

    d = synpic.dump()
    x_orig = np.asarray([d["picture"][:100]])
    print(x_orig)
    x = x_orig.astype("float32")
    x = x[:, np.newaxis]
    predicted = model.predict(x)
    
    print("%s: Negative %.2f, Positive %.2f" %
          (synpic.addr, predicted[0][0] * 100, predicted[0][1] * 100))

    predict_lock.release()

    return predicted[0][1] * 100


if __name__ == "__main__" :
    parser = argparse.ArgumentParser(
        prog = "synpic-server",
        usage = "synpic-server -m MODEL [-i|-f]",
        add_help = True,
    )

    parser.add_argument("-i", "--interface", help = "capture interface")
    parser.add_argument("-f", "--filename", help = "pcap file")
    parser.add_argument("-m", "--model", help = "keras trained model",
                        required = True)
    parser.add_argument("-r", "--repeat", help = "repeat read pcap file",
                        action = "store_true", default = False)
    parser.add_argument("-t", "--interval", help = "interval between export",
                        type = float, default = None)




    args = parser.parse_args()

    model = load_model(args.model)

    #model = load_model(args.model, compile = False)
    #model.compile(optimizer=RMSprop(),
    #metrics=['accuracy'],
    #loss='categorical_crossentropy')
    
    

    wssrv = WebSocketServer()
    interval = args.interval
    wssrv.start()

    if args.interface :
        #capture(args.interface)
        c = Capture_wo_Thread(args.interface)
        c.start()

    elif args.filename :
        readfile(args.filename, repeat = args.repeat)


