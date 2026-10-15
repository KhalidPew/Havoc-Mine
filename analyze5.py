import struct

d = open(r'C:\Users\dELL\Documents\butterfact.x64noencode\butterfact.x64noencode.bin', 'rb').read()
MZ = 1888

# The KaynCaller walk from Start (offset 0):
#   caller pops rcx = return addr; the 'call caller' is at file offset 12 (0xC),
#   so rcx = 0xC + 5 = 0x11. It then does 'inc rcx' FIRST then compares.
#   So the first byte checked is 0x11 (17). Let's simulate.
print('Simulating KaynCaller forward walk from rcx=0x11:')
rcx = 0x11
found = None
for step in range(200000):
    rcx += 1
    if rcx + 1 >= len(d):
        print('  walked off end of buffer at rcx=0x%X, NO MZ found' % rcx)
        break
    if d[rcx] == 0x4D and d[rcx+1] == 0x5A:  # 'MZ'
        pe = struct.unpack_from('<i', d, rcx + 0x3C)[0]
        if 0 < pe < len(d) - rcx - 4 and d[rcx+pe] == 0x50 and d[rcx+pe+1] == 0x45:
            found = rcx
            print('  MZ+PE found at rcx=0x%X after %d increments' % (rcx, step))
            break
if found is None:
    print('  => KaynCaller FAILS to find the Demon MZ')

# Where does the walk actually find the *first* 0x5A4D?
print()
print('First occurrence of 0x5A4D (MZ) from offset 0x11:')
for i in range(0x11, min(len(d)-1, 0x800)):
    if d[i] == 0x4D and d[i+1] == 0x5A:
        print('  MZ bytes at 0x%X: %s' % (i, d[i:i+16].hex()))
        break

# Check the exact bytes at the MZ=1888 the analyzer found via full scan
print()
print('bytes at 1888 (the real Demon MZ):', d[1888:1904].hex())
print('bytes at 1888 as ascii:', d[1888:1904])
