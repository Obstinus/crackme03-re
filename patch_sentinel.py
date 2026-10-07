"""Patch sentinel_scan (0x140001490) to 'xor eax,eax; ret' -> always 'clean'."""
import pefile, shutil, sys
SRC = '/home/sapoimundo/Downloads/Crackmes/6abd98190885f990699dc084/crackme03.exe'
DST = sys.argv[1] if len(sys.argv) > 1 else 'crackme03_nosentinel.exe'
pe = pefile.PE(SRC, fast_load=True)
off = pe.get_offset_from_rva(0x140001490 - pe.OPTIONAL_HEADER.ImageBase)
data = bytearray(open(SRC, 'rb').read())
print('file offset', hex(off), 'old bytes', data[off:off+3].hex())
data[off:off+3] = b'\x31\xc0\xc3'   # xor eax,eax ; ret
open(DST, 'wb').write(data)
print('wrote', DST)
