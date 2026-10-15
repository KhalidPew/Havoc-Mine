import struct, math

path = r'C:\Users\dELL\Documents\butterfact.x64noencode\butterfact.x64noencode.bin'
d = open(path, 'rb').read()
print('===', path)
print('size', len(d))
print('first 16:', d[:16].hex())

# real MZ+PE scan
real = []
for i in range(len(d)-1):
    if d[i] == 0x4D and d[i+1] == 0x5A:
        pe = struct.unpack_from('<i', d, i + 0x3C)[0]
        if 0 < pe < len(d) - i - 4 and d[i+pe] == 0x50 and d[i+pe+1] == 0x45:
            real.append(i)
print('real MZ+PE offsets:', real)

for sig in [b'PE\x00\x00', b'This program', b'Rich', b'.text', b'.rdata', b'Demon', b'HAVOC_CRYPT_KEY_MARKER', b'HAVOC_STOMP_TARGET', b'xmllite']:
    off = d.find(sig)
    print('  %s -> %s' % (sig, off))

# if MZ found, dump PE header details
for off in real:
    pe = struct.unpack_from('<i', d, off + 0x3C)[0]
    nth = off + pe
    machine = struct.unpack_from('<H', d, nth + 4)[0]
    numsec = struct.unpack_from('<H', d, nth + 6)[0]
    sizeofimg = struct.unpack_from('<I', d, nth + 0x50)[0]
    entry = struct.unpack_from('<I', d, nth + 0x28)[0]
    print('MZ@0x%X: machine=0x%X numsec=%d SizeOfImage=0x%X EntryPoint=0x%X' % (off, machine, numsec, sizeofimg, entry))

    # entropy of region after MZ
    tail = d[off:]
    freq = {}
    for byte in tail: freq[byte] = freq.get(byte, 0) + 1
    ent = -sum((c/len(tail)) * math.log2(c/len(tail)) for c in freq.values())
    print('  tail entropy from MZ: %.4f bits/byte (8.0=encrypted/random, ~6-7=normal PE)' % ent)

    # is the tail a valid PE size?
    print('  bytes from MZ to EOF: %d (SizeOfImage=%d)' % (len(tail), sizeofimg))
