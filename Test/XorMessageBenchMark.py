#!/usr/bin/python
# -*- coding:utf8 -*-
from ctypes import *
import ctypes
import os,sys
import struct
import numpy as np

def loopC(public_key):
    args = (bytes_array,public_key)
    for x in range(loop_count):
        xorMessageCFunc(args)

def loopPython(public_key):
    key = struct.unpack('4B',struct.pack('I',public_key))
    for x in range(loop_count):
        xorMessage(bytes_array,key)
def compareCAndPython(public_key):
    test_bytes_array = [128,32,56,88,91,23,54,23,12,12,67,29,9,187,98,95,28,64,44]
    test_bytes_array = ''.join(chr(x) for x in test_bytes_array)
    print 'Original Message: ' + test_bytes_array.encode('hex')

    args = (test_bytes_array,public_key)
    key = struct.unpack('4B',struct.pack('I',public_key))

    print 'c message :\n ' + xorMessageCFunc(args).encode('hex')
    print 'python message :\n' + xorMessage(test_bytes_array,key).encode('hex')
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

libP2PCrawlUtil=0
if sys.platform == 'win32':
        dll_path = os.getcwd() + '\Test\P2PCrawlUtil.dll'
        libP2PCrawlUtil = cdll.LoadLibrary(dll_path)
else:
        lib_path = os.getcwd() + '/../C_Extension/bin/libP2PCrawlUtil.so'
        libP2PCrawlUtil = cdll.LoadLibrary(lib_path)

xorMessageCFuncType = ctypes.PYFUNCTYPE(
    ctypes.py_object,     # return val: a python object
    ctypes.py_object      # argument 1: a tuple
)
xorMessageCFunc = xorMessageCFuncType(('XorEncryptZeroAccess', libP2PCrawlUtil))
bytes_array = np.random.bytes(1000)
loop_count=10000

def main():

    key_array = [ord('2'),ord('p'),ord('t'),ord('f')]
    key = struct.unpack('I',struct.pack('4B',key_array[0],key_array[1],key_array[2],key_array[3]))[0]
    print key

    #loopC(key)
    #loopPython(key)
    #compareCAndPython(key)
if __name__ == '__main__':
    main()
