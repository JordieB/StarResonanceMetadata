# script to extract IL2CPP global-metadata.dat from a memory dump file

# THIS FILE WAS CREATED BY @rushkii (on GitHub), USING INFORMATION PROVIDED FOR ANALYSIS BY @dmlgzs (on GitHub)
# PLEASE DO NOT REMOVE THIS WATERMARK.




import sys
import struct

if len(sys.argv) < 3:
    print("Usage: python global-metadata-dumper.py <dumpfile> <out>")
    print("Example: python global-metadata-dumper.py BPSR.DMP global-metadata.dat")
    sys.exit(1)

# memory .DMP file
# can be obtained via Task Manager -> Select BPSR.exe -> Right Click -> Create dump file
# recommended: create dump file when the game is logged-in.
dumpfile = sys.argv[1]
outfile  = sys.argv[2] # output metadata file

IL2CPP_MAGIC = b"\xAF\x1B\xB1\xFA"

print("[*] Loading dump file...")

with open(dumpfile, "rb") as f:
    data = f.read()

# find metadata magic
idx = data.find(IL2CPP_MAGIC)
if idx == -1:
    print("[-] ERROR: Metadata magic not found in dump!")
    sys.exit(1)

print(f"[+] Found metadata magic at offset 0x{idx:X}")

# -------------------------------------------------------------------
# Read metadata header
# -------------------------------------------------------------------
# Metadata Header Layout:
#   uint32 sanity;
#   uint32 version;
#   uint32 stringLiteralOffset;
#   uint32 stringLiteralCount;
#   uint32 stringLiteralDataOffset;
#   uint32 stringLiteralDataCount;
#   ...
#   (More tables follow — increasing offsets)
#
# to determine actual metadata file size, use all table offsets.
# -------------------------------------------------------------------

def read_u32(off):
    return struct.unpack_from("<I", data, off)[0]

header_off = idx

sanity   = read_u32(header_off)
version  = read_u32(header_off + 4)

print(f"[+] Metadata version : {version}")

# save table offsets (first 64 bytes)
offsets = []
for i in range(0, 0x100, 4):
    val = read_u32(header_off + i)
    if 0 < val < 0xFFFFFFF:  # ignore zero or invalid offsets
        offsets.append(val)

# metadata size: max_offset + some padding
metadata_size = max(offsets) + 0x1000  # extra safety padding

print(f"[+] Estimated metadata size : {metadata_size} bytes (≈ {metadata_size/1024:.1f} KB)")

end = idx + metadata_size
chunk = data[idx:end]

with open(outfile, "wb") as f:
    f.write(chunk)

print(f"[+] Extracted metadata saved to : {outfile}")
print("[!] Try running this file inside Il2CppDumper now.")
print('\033[1;37mTHIS FILE WAS CREATED BY \033[4;32m\033[40m\033[1;92m@rushkii (on GitHub)\033[0m\033[1;37m, USING INFORMATION PROVIDED FOR ANALYSIS BY \033[4;32m\033[40m\033[1;92m@dmlgzs (on GitHub)\033[0m')
