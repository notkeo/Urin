import struct
import binascii
from os import listdir
from os.path import isfile, join
from hashlib import md5
# name of sample file in current directory
sample_name = "TFTP.exe"
s_sig = 0
s_hash = 0


def hashcalc(path):
    try:
        with open(path, 'rb') as f:
            if 'MZ' == f.read(2):
                m = md5()
                f.seek(0)
                m.update(f.read())
                return m.digest()
    except IOError:
        print "access denied: %s", path


def extract_cs(path):
    try:
        with open(path, "rb") as f:
            if 'MZ' == f.read(2):
                f.seek(0x3c)
                e_lfanew = struct.unpack("<i", f.read(4))[0]  # offset to PE
                f.seek(e_lfanew + 6)
                try:
                    for i in range(struct.unpack('H', f.read(2))[0]):  # loop sections
                        f.seek(e_lfanew + 248 + 40 * i)
                        section_name = f.read(8)
                        if '.text' in section_name and 'bss' not in section_name:
                            f.seek(e_lfanew + 248 + 40 * i + 16)
                            cs_prop = [struct.unpack('<i', f.read(4))[0], struct.unpack('<i', f.read(4))[0]]
                            f.seek(cs_prop[1])
                            return f.read(cs_prop[0])
                except struct.error:
                    print "file was packed: ", path
    except IOError:
        print "access denied: ", path


props = eval(open("props.txt", 'r').readline())

if props['type'] == 'sig':
    sample_cs = extract_cs(sample_name)
    s_sig = sample_cs[len(sample_cs) / 2:len(sample_cs) / 2 + 32]
    print "sample sig: ", binascii.hexlify(s_sig)
else:
    s_hash = hashcalc(sample_name)
    print 'sample md5: ', binascii.hexlify(s_hash)

dirs_queue = [props['path']]
while len(dirs_queue) != 0:
    current_dir = dirs_queue.pop()
    entries = listdir(current_dir)
    for e in entries:
        path = join(current_dir, e)
        if isfile(path):
            if props['type'] == 'sig':
                cs = extract_cs(path)
                if cs is not None and s_sig in cs:
                    print "[***OK***] catched by sig: ", path.encode("utf-8")
            else:
                if s_hash == hashcalc(path):
                    print "[***OK***] catched by hash: ", path.encode("utf-8")
        else:
            dirs_queue.append(path)