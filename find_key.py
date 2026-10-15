d = open(r'C:\Users\dELL\Desktop\testbutterfact.x64\testbutterfact.x64.bin','rb').read()

# The template is 1888 bytes. gCryptKey[32] sits inside it (in the merged data section).
# The stub is ~1888 bytes. Search the first 1888 bytes for a 32-byte printable-ASCII slot
# that is NOT the marker (i.e. has been patched with the real key).
print('scanning first 1888 bytes for 31-char printable runs (candidate patched key)...')
for i in range(0, 1888 - 31):
    run = d[i:i+31]
    if all(32 <= c < 127 for c in run):
        # exclude the marker itself
        if b'HAVOC_CRYPT_KEY_MARKER' not in run:
            print('  candidate key at offset', i, ':', run.decode('ascii', 'replace'))
            break

# Also scan for the stomp target wide string
import re
for m in re.finditer(rb'(?:[ -~]\x00){4,20}', d[:1888]):
    s = m.group().decode('utf-16le', 'replace')
    if 'dll' in s.lower() or '.dll' in s.lower():
        print('  stomp target at', m.start(), ':', s)
