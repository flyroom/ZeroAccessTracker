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
from multiprocessing import Process, Queue
from threading import Semaphore

import multiprocessing as mul

from twisted.internet.protocol import DatagramProtocol

updateNodelistLock = Semaphore(value=1) 

def Send(shared_node_list):
    thread_label = u'启动发送线程'
    if sys.platform == 'win32':
            print (thread_label).encode('gbk')
    else:
            print (thread_label).encode('utf8')
     
    message = buildMessage()
    MAX_RECEIVED = 65535
    host = ''

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #s.bind(('127.0.0.1',8964))

    while True:
        try:
            p2p_node = shared_node_list.get()
            #ip = socket.inet_ntoa(struct.pack('I',socket.htonl(p2p_node.get_ip())))
            ip = socket.inet_ntoa(struct.pack('I',p2p_node.get_ip()))
            host = ip
            udp_port = p2p_node.get_udpport()
            #print ip + ' --> ' + str(udp_port)
            datagram = message
            #self.transport.connect(ip,udp_port)
            #print 'message to send ' + datagram.encode('hex')
            s.sendto(datagram,(ip,udp_port))
            #print 'datagram sent to node '+ip
        except Exception , e:
            #print 'error in sending query to node '+host
            #print str(e)
            #traceback.print_exc()
            continue
def Receive(shared_node_list):
    thread_label = u'启动监听线程'
    print (thread_label).encode('gbk')
    
    MAX_RECEIVED = 65535
    datagram=''
    host = ''

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1',8964))
    
    while True:
        try:
            datagram,host = s.recvfrom(MAX_RECEIVED)
            print 'Datagram received: ', repr(datagram)
            original_message = xorMessage(datagram,key)
            crc32,retL_command,b_flag,ip_count = struct.unpack('IIII',datagram[:16])
            print 'this node ' + host + ' has ' + ip_count + ' descendant ip'  
        except Exception , e:
            print 'error in parsing query from node '+host
            print str(e)
            traceback.print_exc()

class SendThread(Process):
    message=''
    key = [ord('2'),ord('p'),ord('t'),ord('f')]
    
    def __init__(self,shared_nodes_list):
        Process.__init__(self)
        message = buildMessage()
        nonQueryedNodes = shared_nodes_list
    def return_name(self):
        return "Process returned %s" % self.name
    def run(self):
        self.sendDatagram()
    def sendDatagram(self):
        thread_label = u'启动发送线程'
        if sys.platform == 'win32':
                print (thread_label).encode('gbk')
        else:
                print (thread_label).encode('utf8')
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
        MAX_RECEIVED = 65535
        host = ''
        while True:
            try:
                updateNodelistLock.acquire()
                if self.nonQueryedNodes.empty():
                    print 'Empty nonQueryedNodes'
                    return
                else:
                    print 'Not Empty nonQueryedNodes'
                while(not self.nonQueryedNodes.empty()):
                    p2p_node = self.nonQueryedNodes.get()
                    print 'ip : ' + str(p2p_node.get_ip())
                    ip = socket.inet_ntoa(struct.pack('I',socket.htonl(p2p_node.get_ip())))
                    host = ip
                    udp_port = p2p_node.get_udpport()
                    print ip + ' --> ' + str(udp_port)
                    datagram = self.message
                    #self.transport.connect(ip,udp_port)
                    print 'message to send ' + datagram.encode('hex')
                    s.sendto(datagram,(ip,udp_port))
                    print 'datagram sent to node '+ip
            except Exception , e:
                print 'error in sending query to node '+host
                print str(e)
                traceback.print_exc()
            finally:
                updateNodelistLock.release()
class ReceiveThread(Process):
    def __init__(self,udp_port):
        Process.__init__(self)
        self.udp_port = udp_port
    def return_name(self):
        return "Process returned %s" % self.name
    def run(self):
        self.Receive(self.udp_port)
    def Receive(self,udp_port):
        thread_label = u'启动监听线程'
        print (thread_label).encode('gbk')
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
        s.bind(('127.0.0.1',self.udp_port))
        MAX_RECEIVED = 65535
        datagram=''
        host = ''
        while True:
            try:
                datagram,host = s.recvfrom(MAX_RECEIVED)
                print 'Datagram received: ', repr(datagram)
                original_message = xorMessage(datagram,key)
                updateNodelistLock.acquire()
                crc32,retL_command,b_flag,ip_count = struct.unpack('IIII',datagram[:16])
                print 'this node ' + host + ' has ' + ip_count + ' descendant ip'  
            except Exception , e:
                print 'error in parsing query from node '+host
                print str(e)
                traceback.print_exc()
            finally:
                updateNodelistLock.release()

class ZeroAccessNode:
        def __init__(self):
            ip = 0
            udp_port = 0
        def set_ip(self,ip): 
            self.ip = ip 
        def set_udpport(self,udp_port): 
            self.udp_port = udp_port
        def get_ip(self):
            return self.ip;
        def get_udpport(self):
            return self.udp_port
def buildMessage():
    message = struct.pack('I4cIL',
            0,
            'L','t','e','g',
            0,
            0x85E246A8
            )
    crc_sum = zlib.crc32(message) & 0xffffffffL
    message = struct.pack('I4cIL',
            crc_sum,
            'L','t','e','g',
            0,
            0x85E246A8
            )

    key = [ord('2'),ord('p'),ord('t'),ord('f')]
    key_index=0
    print message.encode('hex')
    final_message = xorMessage(message,key)
    return final_message 

def main():

    SEPARATOR = '/'
    if sys.platform == 'win32':
        SEPARATOR = "\\"

    message = buildMessage()
    print message.encode("hex")

    nonQueryedNodes = mul.Queue(5000)

    zeroaccess_bootstrap_seeds_path = "Data"+SEPARATOR+"zeroaccess_node.dat"
    zeroaccess_nodes = read_zeroaccess_data_from_file(zeroaccess_bootstrap_seeds_path)

    queryResultNodeList = zeroaccess_nodes
    for node in zeroaccess_nodes[:5]:
        nonQueryedNodes.put(node)
        print node.get_ip()

    if nonQueryedNodes.empty():
        print 'insert into nonQueryedNodes failed'

    result = []

    sender = Process(target=Send, args=[nonQueryedNodes])
    receiver = Process(target=Receive, args=[nonQueryedNodes])

    receiver.start()
    time.sleep(5)    
    sender.start()
    
    receiver.join()
    sender.join()
    
if __name__ == '__main__':
    main()
