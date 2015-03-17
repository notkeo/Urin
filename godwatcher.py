import struct
import binascii
import logging
from logging import debug, error
from os import listdir
from os.path import isfile, join
from hashlib import md5

logging.setLoggerClass(logging.DEBUG | logging.ERROR)
# name of sample file in current directory
sample_name = "TFTP.exe"
# samples signature and hash values
s_sig = 0
s_hash = 0


def hashcalc(file_path):
    try:
        with open(file_path, 'rb') as f:
            if 'MZ' == f.read(2):
                m = md5()
                f.seek(0)
                m.update(f.read())
                return m.digest()
    except IOError:
        error("access denied: %s" % file_path)


def extract_cs(file_path):
    try:
        with open(file_path, "rb") as f:
            if 'MZ' == f.read(2):
                f.seek(0x3c)
                e_lfanew = struct.unpack("<i", f.read(4))[0]  # offset to PE
                f.seek(e_lfanew + 6)
                sections_count = struct.unpack('H', f.read(2))[0]
                debug("file: %s" % file_path)
                debug("offset to PE section table %s" % binascii.hexlify(e_lfanew))
                debug("sections count %d" % sections_count)
                try:
                    for i in range(sections_count):  # loop sections
                        f.seek(e_lfanew + 248 + 40 * i)
                        section_name = f.read(8)
                        if '.text' in section_name and 'bss' not in section_name:
                            f.seek(e_lfanew + 248 + 40 * i + 16)
                            cs_prop = [struct.unpack('<i', f.read(4))[0], struct.unpack('<i', f.read(4))[0]]
                            f.seek(cs_prop[1])
                            debug(".text size: %s , offset: %s" % (cs_prop[0], cs_prop[1]))
                            return f.read(cs_prop[0])
                except struct.error:
                    error("MZ file was packed: %s , e_lfanew: " % (file_path, binascii.hexlify(e_lfanew)))
    except IOError:
        error("access denied: %s" % file_path)


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