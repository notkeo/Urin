import struct
import binascii
import logging
from os import listdir
from os.path import isfile, join
from hashlib import md5


# log settings
log = logging.getLogger("godwatcher-debug")
log.addHandler(logging.FileHandler("./log/log.txt"))
log.setLevel(logging.DEBUG)

# params of current sample
SAMPLE_FILE_NAME = "TFTP.exe"
SAMPLE_SIG = 0
SAMPLE_HASH = 0


def hashcalc(file_path):
    try:
        with open(file_path, 'rb') as f:
            if 'MZ' == f.read(2):
                m = md5()
                f.seek(0)
                m.update(f.read())
                return m.digest()
    except IOError:
        log.error("access denied: %s" % file_path)


def extract_cs(file_path):
    try:
        with open(file_path, "rb") as f:
            if 'MZ' == f.read(2):
                f.seek(0x3c)
                try:
                    e_lfanew = struct.unpack("<i", f.read(4))[0]  # offset to PE
                    f.seek(e_lfanew + 6)
                    sections_count = struct.unpack('H', f.read(2))[0]
                    log.debug("file: %s" % file_path)
                    log.debug("offset to PE section table %s" % binascii.hexlify(str(e_lfanew)))
                    log.debug("sections count %d" % sections_count)
                    for i in range(sections_count):  # loop sections
                        f.seek(e_lfanew + 248 + 40 * i)
                        section_name = f.read(8)
                        if '.text' in section_name and 'bss' not in section_name:
                            f.seek(e_lfanew + 248 + 40 * i + 16)
                            cs_prop = [struct.unpack('<i', f.read(4))[0], struct.unpack('<i', f.read(4))[0]]
                            f.seek(cs_prop[1])
                            log.debug(".text size: %s , offset: %s" % (cs_prop[0], cs_prop[1]))
                            return f.read(cs_prop[0])
                except struct.error:
                    log.error(
                        "MZ file was packed: %s , e_lfanew: %s" % (file_path, binascii.hexlify(str(e_lfanew))))

    except IOError:
        log.error("access denied: %s" % file_path)


props = eval(open("props.txt", 'r').readline())
if props['type'] == 'sig':
    sample_cs = extract_cs(SAMPLE_FILE_NAME)
    SAMPLE_SIG = sample_cs[len(sample_cs) / 2:len(sample_cs) / 2 + 32]
    print "sample sig: ", binascii.hexlify(SAMPLE_SIG)
else:
    SAMPLE_HASH = hashcalc(SAMPLE_FILE_NAME)
    print 'sample md5: ', binascii.hexlify(SAMPLE_HASH)

dirs_queue = [props['path']]
while len(dirs_queue) != 0:
    current_dir = dirs_queue.pop()
    try:
        entries = listdir(current_dir)
        for e in entries:
            path = join(current_dir, e)
            if isfile(path):
                if path.lower().endswith('.exe'):
                    if props['type'] == 'sig':
                        cs = extract_cs(path)
                        if cs is not None and SAMPLE_SIG in cs:
                            print "[***OK***] catched by sig: ", path.encode("utf-8")
                    else:
                        if SAMPLE_HASH == hashcalc(path):
                            print "[***OK***] catched by hash: ", path.encode("utf-8")
            else:
                dirs_queue.append(path)
    except WindowsError:
        log.error("access denied %s", current_dir)





