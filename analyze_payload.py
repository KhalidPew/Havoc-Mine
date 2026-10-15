import struct, sys

d = open(r'C:\Users\dELL\Desktop\allbutterfact.x64\allbutterfact.x64.bin', 'rb').read()
print('total size', len(d))
print('first 32 bytes:', d[:32].hex())

# find all MZ occurrences and check for a following PE
for i in range(len(d) - 1):
    if d[i] == 0x4D and d[i+1] == 0x5A:
        pe = struct.unpack_from('<i', d, i + 0x3C)[0]
        if 0 < pe < len(d) - i - 4 and d[i+pe] == 0x50 and d[i+pe+1] == 0x45:
            print('REAL MZ+PE at offset', i)

# scan for a DOS stub / PE header pattern in the tail region
# a real PE has 'This program cannot be run in DOS mode' or PE\0\0 somewhere
for sig in [b'PE\x00\x00', b'This program', b'Rich']:
    off = d.find(sig)
    print(sig, 'found at offset', off)
