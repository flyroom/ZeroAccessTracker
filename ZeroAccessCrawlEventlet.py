#!/usr/bin/python
# -*- coding:utf8 -*-
#'''
#Created on 2013-3-13
#
#@author: p2psec
#'''
import dpkt
import socket,thread
import pygeoip
import struct
import zlib
import ctypes
import numpy as np
import os,sys
import traceback
import time

from twisted.internet import protocol, reactor
from twisted.internet.protocol import DatagramProtocol

from multiprocessing import Process, Queue
import multiprocessing as mul

import eventlet
from eventlet.green import socket

from ZeroAccessUtil import ZeroAccessUtil

def query(p2p_node,message):
    print 'query'
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)

    ip = socket.inet_ntoa(struct.pack('I',p2p_node.get_ip()))
    host = ip
    udp_port = p2p_node.get_udpport()
    #print ip + ' --> ' + str(udp_port)
    datagram = message
    #self.transport.connect(ip,udp_port)
    #print 'message to send ' + datagram.encode('hex')
    s.sendto(datagram,(ip,udp_port))
    result=''
    try:
        result = s.recvfrom(1024)
    except:
        print 'timeout'
    return result 


def main():
    query_message = ZeroAccessUtil.buildMessage()

    SEPARATOR = '/'
    if sys.platform == 'win32':
        SEPARATOR = "\\"

    message = ZeroAccessUtil.buildMessage()
    print message.encode("hex")

    nonQueryedNodes = mul.Queue(5000)

    zeroaccess_bootstrap_seeds_path = "Data"+SEPARATOR+"zeroaccess_node.dat"
    zeroaccess_nodes = ZeroAccessUtil.read_zeroaccess_data_from_file(zeroaccess_bootstrap_seeds_path)

    pile = eventlet.GreenPile()
    for x in zeroaccess_nodes[:10]:
        pile.spawn(query, x,message)

    # note that the pile acts as a collection of return values from the functions
    # if any exceptions are raised by the function they'll get raised here
    key = [ord('2'),ord('p'),ord('t'),ord('f')]
    for node, result in zip(zeroaccess_nodes[:10], pile):
        if(result == ''):
            print 'no response from '+ socket.inet_ntoa(struct.pack('I',node.get_ip()))
            continue
        print 'received'
        original_message = ZeroAccessUtil.xorMessage(result[0],key)
        crc32,retL_command,b_flag,ip_count = struct.unpack('IIII',original_message[:16])
        print socket.inet_ntoa(struct.pack('I',node.get_ip()))+' --> ip count:  '+str(ip_count)
        #print '%s: %s' % (url, repr(result)[:50])
    
    
if __name__ == '__main__':
    main()
