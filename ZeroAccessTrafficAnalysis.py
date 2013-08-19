# -*- coding:utf8 -*-
'''
Created on 2013-3-13

@author: p2psec
'''
import dpkt
import socket
import pygeoip
import os

from dpkt.ip import IP, IP_PROTO_UDP
from dpkt.udp import UDP

geo_locator = pygeoip.GeoIP(os.getcwd() + "\\data\GeoLiteCity.dat")

def getGeoInfo(ip):
    try:
        country = geo_locator.country_name_by_addr(ip)
        return country
    except:
        return "unregistered"
def findCommon(pcap):
    remote_ip_list=[]
    remote_size_list=[]
    for (ts,buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            if (type(ip.data) != UDP):
                continue
            if src != '192.168.100.110':
                continue
            if dst == '255.255.255.255':
                continue
            if dst in remote_ip_list:
                continue
            remote_ip_list.append(dst)
            content_bytes = ip.data.data
            print type(content_bytes)
            udpResultData = ZeroDecrypt(content_bytes[0:44])
            print udpResultData.encode('hex')[0:87]
            #print udpResultData
            #print content_bytes.encode('hex')[0:21]
            #print 'Src ' + src + ' --> Dst '+dst
            #print len(content_bytes)
            remote_size_list.append(len(content_bytes))
        except:
            raise
    #print 'average: '+str(sum(remote_size_list)/len(remote_size_list)-44)
def ZeroDecrypt(udpData):
    length = len(udpData)
    print length
    udpResultData=[]
    udpResultData.append(ord(udpData[0]))
    for i in range(length-1):
        re = ord(udpData[i])^ord(udpData[i-1])
        udpResultData.append(re)
    return "".join(map(chr, udpResultData))
def printPcap(pcap):
    for (ts,buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            if (type(ip.data) != UDP):
                print 'not udp'
                continue
            print 'Src ' + src + ' --> Dst '+dst
            print 'Src ' + getGeoInfo(src) + ' --> Dst ' + getGeoInfo(dst)
        except:
            pass
def main():
    pcap_path = 'C:\\AliveZeusP2P.pcap'
    f = open(pcap_path,'rb')
    pcap = dpkt.pcap.Reader(f)
    #printPcap(pcap)
    findCommon(pcap)
if __name__ == '__main__':
    main()
