#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pwn attack frame
# directly modify "pwn info" and "exp" parts
from zio import *

# pwn info #
local = './pepper'
local = ('10.211.55.56', 1111)  # no support socat
remote = '10.211.55.56'
port = 1111
cmd = 'cat /home/flag/pepper'

def start(io, debug=0):
    # exp #
    if debug:
        io.gdb_hint()

def attack(host='127.0.0.1', port=1234, shell=False):
    if host == local:
        debug = 1
        io = zio(local, print_read=COLORED(REPR,'yellow'),\
                print_write=COLORED(REPR,'blue'))
    else:
        debug = 0
        io = zio((host, port), print_read=False, print_write=False)

    start(io, debug)

    if shell:
        return io
    else:
        flag = ''
        io.write(cmd+'\n')
        flag = io.readline().strip()
        io.close()
        return flag


if __name__ == '__main__':
    host = local
    flag = attack(host, port)
    log('flag: %s' % flag, 'red')
    io = attack(host, port, shell=True)
    log('get shell...', 'red')
    io.interact()
