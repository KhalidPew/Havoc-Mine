import struct

d = open(r'C:\Users\dELL\Documents\butterfact.x64noencode\butterfact.x64noencode.bin', 'rb').read()
MZ = 1888
pe = struct.unpack_from('<i', d, MZ + 0x3C)[0]
nth = MZ + pe

sizeof_img  = struct.unpack_from('<I', d, nth + 0x50)[0]
sizeof_hdrs = struct.unpack_from('<I', d, nth + 0x54)[0]
imgbase     = struct.unpack_from('<Q', d, nth + 0x30)[0]
entry       = struct.unpack_from('<I', d, nth + 0x28)[0]
numsec      = struct.unpack_from('<H', d, nth + 6)[0]
print('Demon PE @0x%X' % MZ)
print('  ImageBase      = 0x%X' % imgbase)
print('  SizeOfImage    = 0x%X (%d)' % (sizeof_img, sizeof_img))
print('  SizeOfHeaders  = 0x%X' % sizeof_hdrs)
print('  AddressOfEntry = 0x%X' % entry)
print('  NumSections    = %d' % numsec)

# section table
sec_off = nth + 0x18 + struct.unpack_from('<H', d, nth + 0x14)[0]
print('  Sections:')
for i in range(numsec):
    s = sec_off + i*40
    name = d[s:s+8].rstrip(b'\x00').decode('ascii','replace')
    vsize  = struct.unpack_from('<I', d, s+8)[0]
    va     = struct.unpack_from('<I', d, s+12)[0]
    rawsz  = struct.unpack_from('<I', d, s+16)[0]
    rawptr = struct.unpack_from('<I', d, s+20)[0]
    chars  = struct.unpack_from('<I', d, s+36)[0]
    print('    %-8s VA=0x%06X VSize=0x%06X RawPtr=0x%06X RawSize=0x%06X Chars=0x%08X' % (name, va, vsize, rawptr, rawsz, chars))

# The appended DLL is truncated (raw sections only). Check the LAST section's raw end.
last_raw_end = 0
for i in range(numsec):
    s = sec_off + i*40
    rawsz  = struct.unpack_from('<I', d, s+16)[0]
    rawptr = struct.unpack_from('<I', d, s+20)[0]
    end = rawptr + rawsz
    if end > last_raw_end: last_raw_end = end
print('  last raw end (file offset in DLL) = 0x%X' % last_raw_end)
print('  total bytes available from MZ     = 0x%X' % (len(d) - MZ))
print('  => DLL truncated? last_raw_end > available:', last_raw_end > (len(d) - MZ))

# The stub's KHdrSize = section[0].VirtualAddress.
# The stub copies section[0].PointerToRawData .. from KaynLibraryLdr (MZ).
# So the FIRST section's PointerToRawData must be 0 for the copy to align to MZ.
s0 = sec_off
print('  section[0] PointerToRawData = 0x%X (stub expects 0 = headers live at MZ)' % struct.unpack_from('<I', d, s0+20)[0])
print('  section[0] VirtualAddress   = 0x%X (this becomes KHdrSize)' % struct.unpack_from('<I', d, s0+12)[0])
