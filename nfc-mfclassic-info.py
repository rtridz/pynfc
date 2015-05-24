#!/usr/bin/env python
"""
nfc-mfclassic-info.py - show info from mfclassic-info
ex:
nfc-mfclassic r a dump.mfd keys.mfd
nfc-mfclassic-info.py dump.mfd
"""
import sys
from struct import unpack 
from datetime import datetime
 
def get_crc(block):
    """XOR all bytes in block"""
    return reduce(lambda x, y: x ^ ord(y), block, 0)
 
def get_bits(i, s, l):
    """ Get l bits starting at s"""
    mask = (1 << (l)) - 1 
    return int((i >> s) & mask)
 
def print_info(data):
    # card number
    number = unpack('<4H', data[0x46:0x4E])
    print "Card #:tt{3:04X} {2:04X} {1:04X} {0:04X}".format(*number)
 
    # card header blocks
    header_block = data[0x2D0:0x2E0]
    crc_2d = get_crc(header_block)
    crc_2e = get_crc(data[0x2E0:0x2F0])
    print "nHeader: t" + ("ok" if crc_2d == crc_2e else "err")
    print "Block 0x2D CRC:t{:#x}".format(crc_2d)
    print "Block 0x2E CRC:t{:#x}".format(crc_2e)
 
    # last activity
    activity_number, activity2, activity1 = unpack('>HLH', data[0x2E2:0x2EA])
    activity = activity1 + (activity2 << 16)
    activity_count = get_bits(activity, 38, 10)
    y = get_bits(activity, 6, 5) + 2000
    M = get_bits(activity, 11, 4)
    d = get_bits(activity, 15, 5)
    h = get_bits(activity, 20, 5)
    m = get_bits(activity, 25, 6)
    s = get_bits(activity, 31, 5) * 2
    activity_date = datetime(y, M, d, h, m, s)
    activity_position, = unpack('>H', data[0x147:0x149])
    activity_index = (activity_position / 0x40) - 32
    print  "nLast activity #t{}".format(activity_number)
    print  "Positiont{:#x} ({})".format(activity_position, activity_index)
    print  "Date:tt" + activity_date.isoformat()
    print  "Counter:t{}".format(activity_count)
 
    # last activities positions
    positions = [0xC0, 0xD0, 0xE0, 0x100, 0x110, 0x120]
    print "n{:^20}{:^5}{:^20}{:^12}".format("Date", "unk", "Terminal", "Operation")
    print "{:>31}{:>5}{:>4}{:>10}{:>7}".format("ID", "Type", "Cnt", "Type", "Cnt")
 
    # get correct order
    i = 5 if activity_index > 5 else activity_index
    positions_ordered = positions[(i+1):] + positions[:(i+1)]
    for pos in positions_ordered:
        block = data[pos:pos+0x10]
        # if undefined or empty block
        if (get_crc(block) <> 0) or (ord(block[0]) == 0):
            continue
        date_i, unk = unpack('>LH', block[1:7])
        term_id, term_type, term_cnt = unpack('>BBH', block[7:11])
        op_type, op_cnt_i  = unpack('>HH', block[11:15])
        op_cnt = op_cnt_i / 0x40
        h = get_bits(date_i, 2, 5)
        m = get_bits(date_i, 7, 6)
        s = get_bits(date_i, 13, 5) * 2
        y = 2000 + get_bits(date_i, 18, 5)
        M = get_bits(date_i, 23, 4)
        d = get_bits(date_i, 27, 5)
        date = datetime(y, M, d, h, m, s)
        print "{}{:>#5x}{:>#7x}{:>#5x}{:>#7x}{:>#9x}{:>4}
        ".format(date.isoformat(), unk, term_id, term_type, term_cnt, op_type, op_cnt)
 
def main(filename):
    with open(filename, "rb") as f:
        data = f.read(1024)
        print_info(data)
 
if __name__ == "__main__":
    main(sys.argv[1])
