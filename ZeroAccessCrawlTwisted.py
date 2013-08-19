#!/usr/bin/python
# -*- coding:utf8 -*-
'''
Created on 2013-3-13

@author: p2psec
'''
import dpkt
import socket,thread
import pygeoip
import struct
import zlib
import ctypes
import numpy as np
import os,sys
import traceback
import hashlib
import time
import random
import getopt
import signal
import urllib2

import logging
import logging.config

logging.config.fileConfig("logger.properties")
logger = logging.getLogger("root")
if(logger is None):
    print 'logger init failed'

from twisted.internet import protocol, reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import task

from multiprocessing import Process, Queue
from threading import Semaphore

import multiprocessing as mul

from IPy import IP

from ZeroAccessUtil import ZeroAccessUtil
from ZeroAccessUtil import ZeroAccessNode
from ZeroAccessUtil import ZeroAccessFileInfo 

class ZeroAccessProtocol(DatagramProtocol):
    #消息内容
    getL_message=''
    newL_message=''
    retL_message=''

    # 消息解密密钥
    key = [ord('2'),ord('p'),ord('t'),ord('f')]
    key_int = struct.unpack('I',struct.pack('4B',key[0],key[1],key[2],key[3]))[0]

    # 消息类型标识符
    getL_command = [ord('L'),ord('t'),ord('e'),ord('g')]
    retL_command = [ord('L'),ord('t'),ord('e'),ord('r')]
    newL_command = [ord('L'),ord('w'),ord('e'),ord('n')]

    # 消息类型标识符 (整型)
    getL_command_int = struct.unpack('I',struct.pack('4B',getL_command[0],getL_command[1],getL_command[2],getL_command[3]))[0]
    retL_command_int = struct.unpack('I',struct.pack('4B',retL_command[0],retL_command[1],retL_command[2],retL_command[3]))[0]
    newL_command_int = struct.unpack('I',struct.pack('4B',newL_command[0],newL_command[1],newL_command[2],newL_command[3]))[0]

    node_size_count=0

    nonQueryedNodes = mul.Queue(5000000)
    allZeroAccessNodesMap = {}
    allZeroAccessFilesMap = {}

    udp_port = 16471
    ZEROACCESS_FILE_HEADER_LENGTH = 128

    local_ip=''

    interactive = False

    def __init__(self):
        self.silent = False

    def set_udp_port(self,udp_port_param):
        self.udp_port = udp_port_param

    def set_silent_state(self,silent_param):
        self.silent = silent_param

    def set_bootstrap_node_list(self,zeroaccess_nodes):
        for node in zeroaccess_nodes:
            self.insertGlobalMap(node)
    def generate_message(self,zeroaccess_nodes,zeroaccess_file_list):
        ret = urllib2.urlopen('https://enabledns.com/ip')
        self.local_ip = ret.read()
        get_local_ip_info = 'Retrieve local ip : '+self.local_ip
        logger.info(get_local_ip_info)

        #faked_ip = self.local_ip
        faked_ip = '96.8.117.251'

        self.getL_message = ZeroAccessUtil.buildZeroAccessGetLMessage()
        self.newL_message = ZeroAccessUtil.buildZeroAccessNewLMessage(faked_ip)

        faked_node_info = ZeroAccessNode()
        faked_node_info.set_ip(struct.unpack("I",socket.inet_aton(faked_ip))[0])
        faked_node_info.set_time(time.time())

        seed_node_size = 15
        seed_node_list = random.sample(zeroaccess_nodes,seed_node_size)
        seed_node_list.append(faked_node_info)

        print 'bootstrap nodes len : ' + str(len(zeroaccess_nodes))
        print 'bootstrap file len : ' + str(len(zeroaccess_file_list))
        file_list = random.sample(zeroaccess_file_list,5)
        self.retL_message = ZeroAccessUtil.buildZeroAccessretLMessage(seed_node_list,file_list)
        print 'retL message length  ' + str(len(self.retL_message))
        print 'retL message :\n' 
        #print ''.join( [ "%02X" % x for x in self.retL_message]).strip()
        print self.retL_message.encode('hex')

    def startProtocol(self):
        logger.info('Crawling kick off in seconds with udp_port '+str(self.udp_port)+' and '+str(self.nonQueryedNodes.qsize())+' bootstrap nodes')
    def sendDatagram(self):
        if(self.silent):
                return
        ip = ''
        try:
            if self.nonQueryedNodes.empty():
                logger.debug('No bootstrap nodes to send query')
                return
            logger.debug('Unrequested ZeroAccess Nodes Size Now  :'+str(self.nonQueryedNodes.qsize()))
            while(not self.nonQueryedNodes.empty()):
                p2p_node = self.nonQueryedNodes.get()
                ip = socket.inet_ntoa(struct.pack('I',p2p_node.get_ip()))
                self.transport.write(self.getL_message,(ip,self.udp_port))
        except Exception , e:
            logger.debug('error in sending query to node '+ip)
            logger.debug(str(e))
            #traceback.print_exc()
            return
    def set_interactive(self,interactive_param):
        self.interactive = interactive_param
    def get_nodes_map(self):
        return self.allZeroAccessNodesMap
    def get_files_map(self):
        return self.allZeroAccessFilesMap

    def getL_process(self,original_message,host):
        crc32,command,b_flag,ip_count = struct.unpack('IIII',original_message[:16])
        query_log_info = 'getL query from ' + host[0]
        logger.info(query_log_info)
        if(self.interactive):
                self.transport.write(self.retL_message,host)
                self.transport.write(self.newL_message,host)

    def newL_process(self,original_message,host):
        crc32,command,b_flag,ip = struct.unpack('IIII',original_message[:16])
        query_log_info = 'newL query ' + socket.inet_ntoa(struct.pack('I',ip)) + ' <--> from host ' + host[0]
        logger.info(query_log_info)

    def retL_process(self,original_message,host):
        crc32,command,b_flag,ip_count = struct.unpack('IIII',original_message[:16])

        node_in_info = 'this node ' + str(host) + ' has ' + str(ip_count) + ' descendant ip'  
        logger.debug(node_in_info)
        base_pointer = 16
        if(ip_count > 20):
            return
            #raise Exception(str(host)+ ' IP Count return from P2P Node Two Large : '+str(ip_count),'memory error')
        
        private_ip_count = 0.0
        for i in xrange(ip_count):
            ip =  struct.unpack('I',original_message[base_pointer:(base_pointer+4)])[0]
            times_tamp =  struct.unpack('I',original_message[base_pointer+4:base_pointer+8])[0]
            node = ZeroAccessNode()
            node.set_ip(ip)
            node.set_udpport(self.udp_port)
            node.set_time(times_tamp)
            base_pointer = base_pointer + 8

            z_ip = IP(socket.ntohl(ip))            
            if(z_ip.iptype() == 'PRIVATE'):
                logger.debug('Private IP '+  socket.inet_ntoa(struct.pack('I',ip))+' from '+host[0])
                private_ip_count+=1                
                continue

            if not self.AlreadyQueryed(node):
                self.insertGlobalMap(node)
                self.nonQueryedNodes.put(node)
                self.node_size_count+=1
                if(self.node_size_count % 1000 == 0):
                    info = 'ZeroAccess Nodes Size Mounts to :'+str(self.node_size_count)
                    logger.info(info)
                    print info

        if(private_ip_count > 0):
                self.UpdateFakedRatioInfoOfNode(host[0],(private_ip_count/ip_count))
        

        file_count = struct.unpack('I',original_message[base_pointer:base_pointer+4])[0]
        base_pointer += 4
        for i in range(file_count):
            file_name =  struct.unpack('I',original_message[base_pointer:base_pointer+4])[0]
            file_timestamp =  struct.unpack('I',original_message[base_pointer+4:base_pointer+8])[0]
            file_size =  struct.unpack('I',original_message[base_pointer+8:base_pointer+12])[0]
            file_signature = struct.unpack(str(self.ZEROACCESS_FILE_HEADER_LENGTH)+'B',
                    original_message[base_pointer+12:base_pointer+12+self.ZEROACCESS_FILE_HEADER_LENGTH])

            file_info = ZeroAccessFileInfo()
            #file_info.set_filename(str(hex(file_name)))
            file_info.set_filename(file_name)
            file_info.set_timestamp(file_timestamp)
            file_info.set_filesize(file_size)
            file_info.set_sig(file_signature)

            self.insertFileInfo(file_info,host)

            base_pointer+=12+self.ZEROACCESS_FILE_HEADER_LENGTH
        logger.debug('received file count : '+str(file_count))
        self.sendDatagram()
    def datagramReceived(self, datagram, host):
        try:
            #print 'host in --> '+str(host[0])
            #original_message = ZeroAccessUtil.xorMessage(datagram,self.key)
            original_message = ZeroAccessUtil.xorMessageFast(datagram,self.key_int)
            crc32,command,b_flag,ip_count = struct.unpack('IIII',original_message[:16])
            if(command == self.getL_command_int):
                self.getL_process(original_message,host)
            elif command == self.retL_command_int:
                self.retL_process(original_message,host)
            elif command == self.newL_command_int:
                self.newL_process(original_message,host)
            else:
                print 'Unknown command : '+str(hex(command))
        except Exception , e:
            logger.debug('error in parsing query from node '+str(host))
            logger.debug(str(e))
            traceback.print_exc()
            return

    def insertFileInfo(self,file_info,node_info):
        file_info_found = self.allZeroAccessFilesMap.get(file_info.signature)
        if(file_info_found is None):
            #print ''.join( [ "%02X" % x for x in file_info.signature ]).strip()
            #print 'signature length:  '+str(len(file_info.signature))
            new_file_sig_info = 'Incoming File With Unique Signature:  ' + str(hex(file_info.get_filename()))
            logger.info(new_file_sig_info)
            file_info.node_list.append(file_info)
            self.allZeroAccessFilesMap[file_info.signature]=file_info
        else:
            file_info_found.node_list.append(node_info)
        return True

    def insertGlobalMap(self,node):
           self.allZeroAccessNodesMap[node.get_ip()]=node
           #logger.debug('IP '+ socket.inet_ntoa(struct.pack('I',node.get_ip())) +' inserted')
    def AlreadyQueryed(self,node):
           node_found = self.allZeroAccessNodesMap.get(node.get_ip(),None)
           if(not node_found is None):
                    node_found.increase_rssi_count() 
                    return True
           else:
                    logger.debug('IP '+ socket.inet_ntoa(struct.pack('I',node.get_ip())) +'  not exist')
                    return False
    def UpdateFakedRatioInfoOfNode(self,ip,faked_ip_ratio):
        ip_int = struct.unpack("I",socket.inet_aton(ip))[0]
        node_found = self.allZeroAccessNodesMap.get(ip_int,None)
        faked_ratio = faked_ip_ratio
        if(not node_found is None):
            node_found.update_faked_ratio(faked_ip_ratio)
            faked_ratio = node_found.get_faked_ratio()
        else:
            logger.debug('IP '+ ip +'  send unsolicited response')
        logger.debug('IP '+ ip +'  current faked ip ratio --> '+str(faked_ratio))
    
    def RestartCrawl(self):
        for k,v in self.allZeroAccessNodesMap.items():
            self.nonQueryedNodes.put(v)
        logger.info('Crawl Restarted : current node count ' + str(len(self.allZeroAccessNodesMap)))
        if(self.allZeroAccessNodesMap.has_key(self.local_ip)):
                local_node_info = self.allZeroAccessNodesMap[self.local_ip]
                logger.info('Local Node Info RSSI : ' + socket.inet_ntoa(struct.pack('I',local_node_info.get_ip())) + ' --> '+str(local_node_info.get_rssi_count()))
        self.sendDatagram()
        print 'RestartCrawl'
       
def ShutdownGracefully(udp_port,nodes_map,files_map):
    reactor.stop()
    info = 'Crawling Eventloop Stopped with node count : ' + str(len(nodes_map))
    print info
    logger.info(info)

    nodes_file_path_prefix = 'log/zeroaccess_nodes_'
    files_file_path_prefix = 'log/zeroaccess_nodes_file_'
    files_bin_path_prefix = 'log/zeroaccess_nodes_bin_'
    ZeroAccessUtil.save_zeroaccess_data_to_csv(nodes_map,nodes_file_path_prefix,udp_port)
    ZeroAccessUtil.save_zeroaccess_file_data_to_csv(files_map,files_file_path_prefix,udp_port)
    ZeroAccessUtil.save_zeroaccess_file_data_to_bin(files_map,files_bin_path_prefix,udp_port)

def shutdown():
    reactor.stop()

def SIGINT_exit(num, frame):
    print 'ctrl+c pressed,exiting.....'
    #if(num == 2):
    #    reactor.callFromThread(reactor.stop)
        #reactor.stop()
    reactor.callLater(1,shutdown)

def main():
    #logging.Formatter.converter = time.gmtime
    #FORMAT = '%(levelname)s %(asctime)-15s %(message)s'
    #logging.basicConfig(filename = os.path.join(os.getcwd(),'crawl.log'), level = logger.INFO,format = FORMAT)  

    SEPARATOR = '/'
    if sys.platform == 'win32':
        SEPARATOR = "\\"

    ZEROACCESS_UDP_PORT = 16471
    silent = False

    zeroaccess_nodes = []

    zeroaccess_file_info_path = "Data"+SEPARATOR+"zeroaccess_file.bin"
    zeroaccess_file_list = ZeroAccessUtil.read_zeroaccess_file_data_from_bin(zeroaccess_file_info_path)

    zeroaccess_protocol = ZeroAccessProtocol()

    interactive = False
    crawl_only = False

    # 静默状态，监听
    # -l

    # 使用 getL 查询爬取全网
    # -s

    # 周期性大量发送 getL 查询，同时积极回应，使用newL推送 ip
    # -i

    # 做为客户端，发送查询
    # -c

    try:
        opts,args = getopt.getopt(sys.argv[1:],"hp:lis")
    except getopt.GetoptError as err:
        print str(err)
        sys.exit(2)
    for o,a in opts:
        if o=='-h':
            print 'help'
            sys.exit()
        if o=='-i':
            interactive = True
            zeroaccess_protocol.set_interactive(interactive)
        if o=='-s':
            crawl_only = True
        if o=='-c':
            zeroaccess_nodes = []
            ip_path = "Data"+SEPARATOR+"ip_list.txt"
            ip_file = open(ip_path)
            for ip_line in ip_file:
                print ip_line
                node = ZeroAccessNode()
                ip_int = struct.unpack("I",socket.inet_aton(ip_line))[0]
                node.set_ip(ip_int)
                zeroaccess_nodes.append(node)
        if o=='-l':
            silent = True
            zeroaccess_protocol.set_silent_state(True)
        if o=='-p':
            try:
                ZEROACCESS_UDP_PORT = int(a)
            except ValueError:
                print 'Invalid Value'
            if ZEROACCESS_UDP_PORT not in [16471,16470,16464,16465]:
                port_error_info = 'Crawling Port Not Valid : ' + str(ZEROACCESS_UDP_PORT)
                logger.info(port_error_info)
                sys.exit()
            port_info = 'Crawling Port : ' + str(ZEROACCESS_UDP_PORT)
            logger.info(port_info)
            print port_info

    # get a sample list of zeroaccess nodes map
    #ip_list = random.sample(zeroaccess_nodes,16)
    #print ip_list

    zeroaccess_bootstrap_seeds_path = "Data"+SEPARATOR+"zeroaccess_node_"+str(ZEROACCESS_UDP_PORT)+".dat"

    bootstrap_nodes = ZeroAccessUtil.read_zeroaccess_data_from_file(zeroaccess_bootstrap_seeds_path)
    zeroaccess_nodes = zeroaccess_nodes + bootstrap_nodes

    zeroaccess_protocol.set_udp_port(ZEROACCESS_UDP_PORT)
    zeroaccess_protocol.set_bootstrap_node_list(zeroaccess_nodes)
    zeroaccess_protocol.generate_message(zeroaccess_nodes,zeroaccess_file_list)

    t = reactor.listenUDP(ZEROACCESS_UDP_PORT , zeroaccess_protocol)

    signal.signal(signal.SIGINT, SIGINT_exit)

    if(crawl_only):
        reactor.callLater(40,zeroaccess_protocol.RestartCrawl)
        reactor.callLater(60,ShutdownGracefully,ZEROACCESS_UDP_PORT,zeroaccess_protocol.get_nodes_map(),zeroaccess_protocol.get_files_map())
    if(interactive):
        newL_query_update_loop = task.LoopingCall(zeroaccess_protocol.RestartCrawl)
        newL_query_update_loop.start(120) # call every second

    try:
        reactor.run()
    #except KeyboardInterrupt:
    #    print "Interrupted by keyboard. Exiting."
    #    reactor.stop()
    except:
        print 'Exception caught while interuptting reactor'
        pass
if __name__ == '__main__':
    main()
