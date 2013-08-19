#!/usr/bin/python
# -*- coding:utf8 -*-
#'''
#Created on 2013-3-13
#
#@author: chengran
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
import logging
import random
import urllib2
from ctypes import *

from ftplib import FTP
from StringIO import StringIO

from urlparse import urlparse

logger = logging.getLogger("root")

libP2PCrawlUtil = 0
if sys.platform == 'win32':
        dll_path = os.getcwd() + '\C_Extension\P2PCrawlUtil.dll'
        libP2PCrawlUtil = cdll.LoadLibrary(dll_path)
else:
        lib_path = os.getcwd() + '/C_Extension/bin/libP2PCrawlUtil.so'
        libP2PCrawlUtil = cdll.LoadLibrary(lib_path)

xorMessageCFuncType = ctypes.PYFUNCTYPE(
    ctypes.py_object,     # return val: a python object
    ctypes.py_object      # argument 1: a tuple
)
xorMessageCFunc = xorMessageCFuncType(('XorEncryptZeroAccess', libP2PCrawlUtil))

class ZeroAccessGetLMessageBuilder:
    def __init__(self):
        self.message = ZeroAccessUtil.buildZeroAccessGetLMessage()
    def buildMessage():
        return self.message

class ZeroAccessNewLMessageBuilder:
    def __init__(self):
        self.message = ZeroAccessUtil.buildZeroAccessNewLMessage()
    def buildMessage():
        return self.message

class ZeroAccessretLMessageBuilder:
    def __init__(self):
        self.retL_message = ZeroAccessUtil.buildZeroAccessretLMessage(zeroaccess_nodes,file_list)
        self.message = ZeroAccessUtil.buildZeroAccessNewLMessage()
    def buildMessage():
        return self.message

class ZeroAccessFileInfo:
    def __init__(self):
        self.file_name=0
        self.timestamp=0
        self.file_size=0
        self.signature=[]
        self.node_list=[]
    def get_filename(self):
        return self.file_name
    def set_filename(self,filename):
        self.file_name = filename
    def get_timestamp(self):
        return self.timestamp
    def set_timestamp(self,timestamp):
        self.timestamp = timestamp
    def get_filesize(self):
        return self.file_size
    def set_filesize(self,file_size):
        self.file_size = file_size
    def get_sig(self):
        return self.signature
    def set_sig(self,sig):
        self.signature = sig
    def __hash__(self):
        return hash((self.file_name,self.timestamp,self.file_size,self.signature))
    def __eq__(self,other):
        return (self.file_name,self.timestamp,self.file_size,self.signature) == (other.file_name,other.timestamp,other.file_size,other.signature)

class ZeroAccessNode:
        def __init__(self):
            self.ip = 0
            self.udp_port = 0
            self.live_time = 0
            self.rssi_count = 1
            self.faked_ratio = 0.0
        def set_ip(self,ip): 
            self.ip = ip 
        def set_udpport(self,udp_port): 
            self.udp_port = udp_port
        def get_ip(self):
            return self.ip;
        def get_udpport(self):
            return self.udp_port
        def get_time(self):
            return self.live_time
        def set_time(self,l_time):
            self.live_time = l_time
        def get_rssi_count(self):
            return self.rssi_count
        def set_rssi_count(self,rssi_count_param):
            self.rssi_count = rssi_count_param
        def increase_rssi_count(self):
            self.rssi_count += 1
        def update_faked_ratio(self,faked_ratio_param):
            self.faked_ratio = (self.faked_ratio + faked_ratio_param)/2
        def get_faked_ratio(self):
            return self.faked_ratio

class ZeroAccessUtil:
        @staticmethod
        def read_zeroaccess_file_data_from_bin(file_path):
            file = open(file_path,'rb')

            version = struct.unpack("I",file.read(4))[0]
            file_creation_time = struct.unpack("I",file.read(4))[0]
            udp_port = struct.unpack("I",file.read(4))[0]
            file_list_len = struct.unpack("I",file.read(4))[0]

            file_list = []

            for i in xrange(file_list_len):
                   file_info = ZeroAccessFileInfo()
                   signature = struct.unpack("128B",file.read(128))
                   file_name = struct.unpack("I",file.read(4))[0]
                   node_list_size = struct.unpack("I",file.read(4))[0]
                   file_size = struct.unpack("I",file.read(4))[0]

                   file_info.set_sig(signature)
                   file_info.set_filename(file_name)
                   file_info.set_filesize(file_size)
                   file_list.append(file_info)
            file.close()
            return file_list
        @staticmethod
        def save_zeroaccess_file_data_to_bin(file_map,file_path_prefix,udp_port):
            time_int = time.time()
            file_path = file_path_prefix + str(time_int) + '.bin'
            file = open(file_path,'wb')
            file_header = struct.pack('IIII',
                    0, #version
                    time_int,     #time
                    udp_port,        #udp_port
                    len(file_map), #length
                    )
            file.write(file_header)
            
            error_count=0
            for file_k,file_v in file_map.iteritems():
                try:
                    file.write(struct.pack('%sf' % len(file_k),*file_k))
                    file.write(struct.pack('I',file_v.get_filename()))
                    file.write(struct.pack('I',len(file_v.node_list)))
                    file.write(struct.pack('I',file_v.get_filesize()))
                except Exception , e:
                    traceback.print_exc()
                    error_count+=1
                    continue
            logger.info('Error Count in saving file nodes bin data '+str(error_count))
            file.close()
        @staticmethod
        def save_zeroaccess_file_data_to_csv(file_map,file_path_prefix,udp_port):
            time_int = time.time()
            time_string = time.asctime(time.gmtime(time_int))

            file_path = file_path_prefix + time_string + '.csv'
            file = open(file_path,'w')
            file_header = struct.pack('IIII',
                    0, #version
                    time_int,     #time
                    udp_port,        #udp_port
                    len(file_map), #length
                    )
            file_header_string = '0,'+ time_string +','+str(udp_port)+','+str(len(file_map))+'\n'
            file.write(file_header_string)
            
            error_count=0
            print 'file_map size : '+str(len(file_map))
            for file_k,file_v in file_map.iteritems():
                try:
                    file_sig = ''.join( [ "%02X" % x for x in file_k]).strip()
                    record = file_sig + ','+ str(hex(file_v.get_filename())) + ',' + str(len(file_v.node_list)) + ','+str(file_v.get_filesize())
                    record += '\n'
                    file.write(record)
                except Exception , e:
                    traceback.print_exc()
                    error_count+=1
                    continue
            logger.info('Error Count in saving file nodes data '+str(error_count))
            file.close()
        @staticmethod
        def save_zeroaccess_data_to_csv(node_map,file_path_prefix,udp_port):
            time_int = time.time()
            time_string = time.asctime(time.gmtime(time_int))

            file_path = file_path_prefix + time_string + '.dat'
            file = open(file_path,'w')
            file_header = struct.pack('IIII',
                    0, #version
                    time_int,     #time
                    udp_port,        #udp_port
                    len(node_map), #length
                    )
            file_header_string = '0,'+ time_string +','+str(udp_port)+','+str(len(node_map))
            file.write(file_header_string)
            
            error_count=0
            for node_k,node in node_map.iteritems():
                try:
                    ip = socket.inet_ntoa(struct.pack('I',node.get_ip()))
                    node_live_time = node.get_time()
                    time_string = 'Time Unknown'
                    if(not node_live_time is None):
                            time_string = time.asctime(time.gmtime(node_live_time))
                    rssi_string = str(node.get_rssi_count())
                    record = ip + ',' + time_string + ',' + rssi_string +'\n'
                    file.write(record)
                except Exception , e:
                    #traceback.print_exc()
                    error_count+=1
                    continue
            logger.info('Error Count in saving nodes data '+str(error_count))
            file.close()
        @staticmethod
        def read_zeroaccess_data_from_bin(file_path):
            file = open(file_path,'rb')

            version = struct.unpack("I",file.read(4))[0]
            file_creation_time = struct.unpack("I",file.read(4))[0]
            udp_port = struct.unpack("I",file.read(4))[0]
            node_list_size = struct.unpack("I",file.read(4))[0]

            node_list = []

            for i in xrange(node_list_size):
                   node = ZeroAccessNode()
                   ip = struct.unpack("I",file.read(4))[0]
                   time = struct.unpack("I",file.read(4))[0]
                   rssi = struct.unpack("I",file.read(4))[0]
                   node.set_ip(ip)
                   node.set_time(time)
                   node.set_udpport(udp_port)
                   node.set_rssi_count(rssi_count)
                   node_list.append(node)
            file.close()
            return node_list
        @staticmethod
        def save_zeroaccess_data_to_bin(node_map,file_path_prefix,udp_port):
            time_int = time.time()
            time_string = time.asctime(time.gmtime(time_int))
            file_path = file_path_prefix + time_string + '.dat'
            
            file = open(file_path,'wb')

            file_header = struct.pack('IIII',
                    0, #version
                    time.time(),     #time
                    udp_port,        #udp_port
                    len(node_map), #length
                    )

            file.write(file_header)
            
            for node_k,node in node_map.iteritems(): 
                 ip = struct.pack("L",node.get_ip())
                 alive_time = struct.unpack("L",node.get_time())
                 file.write(ip)
                 file.write(alive_time)
            file.close()
        @staticmethod
        def buildZeroAccessretLMessage(seed_node_list,file_list):

            header_message = struct.pack('I4cI',
                    0,
                    'L','t','e','r',
                    0,
                    )

            ip_message = struct.pack('I',len(seed_node_list))
            current_time_int = time.time()
            for seed_node in seed_node_list:
                ip_message += struct.pack('II',seed_node.get_ip(),current_time_int)

            file_message = struct.pack('I',len(file_list))
            for file in file_list:
                file_message +=  struct.pack('III',file.get_filename(),file.get_timestamp(),file.get_filesize())
                file_sig = file.get_sig()
                for i in range(len(file_sig)):
                    file_content = struct.pack('B',file_sig[i])
                    file_message += file_content
                print 'file message size: ' + str(len(file_message))

            message = header_message+ip_message+file_message
            crc_sum = zlib.crc32(message) & 0xffffffffL

            modified_header_message = struct.pack('I4cI',
                    crc_sum,
                    'L','t','e','r',
                    0,
                    )

            message = modified_header_message+ip_message+file_message

            key = [ord('2'),ord('p'),ord('t'),ord('f')]
            final_message = ZeroAccessUtil.xorMessage(message,key)
            return final_message
        @staticmethod
        def buildZeroAccessNewLMessage(new_ip):
            message = struct.pack('I4cIL',
                    0,
                    'L','w','e','n',
                    8,
                    struct.unpack("I",socket.inet_aton('209.140.20.40'))[0]
                    )
            crc_sum = zlib.crc32(message) & 0xffffffffL

            message = struct.pack('I4cIL',
                    crc_sum,
                    'L','w','e','n',
                    0,
                    struct.unpack("I",socket.inet_aton(new_ip))[0]
                    )
            key = [ord('2'),ord('p'),ord('t'),ord('f')]
            key_index=0
            final_message = ZeroAccessUtil.xorMessage(message,key)

            return final_message
        @staticmethod
        def buildZeroAccessGetLMessage():
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
            final_message = ZeroAccessUtil.xorMessage(message,key)
            return final_message 
        @staticmethod
        def xorMessageFast(message,key):
            args = (message,key)
            return xorMessageCFunc(args)
        @staticmethod
        def xorMessage(message,key):
            final_message=''
            key_index = 0
            for byte_msg in message:
                byte_msg_int = ord(byte_msg)
                byte_msg_int ^= key[key_index]
                final_message += chr(byte_msg_int)
                #print str(key_index) + ' ' + hex(ord(byte_msg)) + ' xor ' + hex(key[key_index]) + ' = ' + hex(byte_msg_int)
                key_index = (key_index+1)%4
                if key_index == 0:
                    key_long = struct.unpack('I',struct.pack('4B',key[0],key[1],key[2],key[3]))[0]
                    key_long = np.uint32(key_long)
                    key_long = np.left_shift(key_long,1) | np.right_shift(key_long,31)
                    key_int = int(key_long) &  0xffffffffL
                    key = struct.unpack('4B',struct.pack('I',key_int))
            return final_message
        @staticmethod
        def read_zeroaccess_data_from_file(zeroaccess_filepath):
            zeroaccess_file = open(zeroaccess_filepath,'rb')
            zeroaccess_file_size = os.path.getsize(zeroaccess_filepath)
            logger.debug('zeroaccess file size '+str(zeroaccess_file_size))
            zeroaccess_node_list = []

            for i in range(zeroaccess_file_size/8): 
               node = ZeroAccessNode()
               ip=0
               time=0
               try:
                 ip = struct.unpack("L",zeroaccess_file.read(4))[0]
                 time = struct.unpack("L",zeroaccess_file.read(4))[0]
               except:
                 print 'error in '+str(i)+' th node'
                 traceback.print_exc()
                 return zeroaccess_node_list
               node.set_ip(ip)
               #print socket.inet_ntoa(struct.pack('I',ip))
               zeroaccess_node_list.append(node)
            return zeroaccess_node_list
        @staticmethod
        def get_file_content_from_ftp(ftp_file_url):
            url_obj = urlparse(ftp_file_url)
            print url_obj
            print url_obj.hostname
            print url_obj.path

            ftp = FTP(url_obj.hostname) 
            ftp.login()
            r = StringIO()
            #ftp.retrbinary('RETR /pub/README_ABOUT_BZ2_FILES', r.write)
            ftp.retrbinary('RETR '+url_obj.path, r.write)
            ftp.quit()
            print r.getvalue()
        @staticmethod
        def get_ip_list_from_file_with_country_code(ip_file_path,country_code):
            ip_file = open(ip_file_path,'rb')
            ip_count = 0
            for ip_record in ip_file:
                if(ip_record.find('CA') != -1):
                    ip_start = int(ip_record.split(' ')[0])
                    ip_end = int(ip_record.split(' ')[1])
                    ip_start_str = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_start)))
                    ip_end_str = socket.inet_ntoa(struct.pack('I',socket.htonl(ip_end)))
                    #print ip_start_str + ' --> ' + ip_end_str
                    ip_count += (ip_end - ip_start)
            print ip_count
            ip_file.close()
        
def test_ftp():
    ftp_url = 'ftp://ftp.apnic.net/pub/apnic/stats/apnic/README.TXT'
    ftp_content = ZeroAccessUtil.get_file_content_from_ftp(ftp_url)
    print ftp_content
def test_http():
    http_url = 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
    print urllib2.urlopen(http_url).read()
def test_read_ip_geo_file():
    ip_file_path = 'Data\\ip2country.db'
    ZeroAccessUtil.get_ip_list_from_file_with_country_code(ip_file_path,'HK')
def test_read_zeroaccess_bootstrap_file():
    ZEROACCESS_UDP_PORT = 16464
    SEPARATOR = '\\'
    file_path = "Data"+SEPARATOR+"zeroaccess_node_"+str(ZEROACCESS_UDP_PORT)+".dat"
    ZeroAccessUtil.read_zeroaccess_data_from_file(file_path)
def main():
    test_read_zeroaccess_bootstrap_file()
if __name__ == '__main__':
    main()
