import struct

for path in [
    r'C:\Users\dELL\Desktop\testbutterfact.x64\testbutterfact.x64.bin',
    r'C:\Users\dELL\Desktop\allbutterfact.x64\allbutterfact.x64.bin',
]:
    try:
        d = open(path, 'rb').read()
    except Exception as e:
        print(path, 'ERR', e); continue
    print('===', path)
    print('  size', len(d))
    print('  first 16:', d[:16].hex())
    # count real MZ+PE
    real = 0
    for i in range(len(d)-1):
        if d[i]==0x4D and d[i+1]==0x5A:
            pe = struct.unpack_from('<i', d, i+0x3C)[0]
            if 0 < pe < len(d)-i-4 and d[i+pe]==0x50 and d[i+pe+1]==0x45:
                real += 1
                print('  MZ+PE at offset', i)
    print('  real MZ+PE count:', real)
    for sig in [b'PE\x00\x00', b'This program', b'Rich', b'.text', b'.rdata', b'Demon']:
        print('   ', sig, '-> offset', d.find(sig))
