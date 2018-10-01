#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
Silicon Labs AN945 EFM8 USB bootloader client

https://www.silabs.com/documents/public/application-notes/an945-efm8-factory-bootloader-user-guide.pdf

Copyright: Max <ulidtko@gmail.com> 2018
License: MIT
"""
from __future__ import print_function

import sys
import argparse
import warnings
from itertools import chain

try:
    import usb.core
    from intelhex import IntelHex
except ImportError:
    print("Could not import dependencies, try: pip install -r requirements.txt")
    sys.exit(1)

# pylint: disable=invalid-name

#-----------------------------------------------------------------------------#

VID_SILABS = 0x10C4
PID_EFM8UB1 = 0xEAC9
PID_EFM8UB2 = 0xEACA
PID_EFM8UB3 = 0xEACB

def product_filter(dev):
    """ PID filter """
    return dev.idProduct in (PID_EFM8UB1, PID_EFM8UB2, PID_EFM8UB3)


def hid_set_report(dev, report):
    """ Implements HID SetReport via USB control transfer """
    trace('out', report)
    dev.ctrl_transfer(
        0x21, # REQUEST_TYPE_CLASS | RECIPIENT_INTERFACE | ENDPOINT_OUT
        9, # SET_REPORT
        0x200, 0x00,
        report)

def hid_get_report(dev):
    """ Implements HID GetReport via USB control transfer """
    r = dev.ctrl_transfer(
        0xA1, # REQUEST_TYPE_CLASS | RECIPIENT_INTERFACE | ENDPOINT_IN
        1, # GET_REPORT
        0x200, 0x00,
        1)
    trace('in', r)
    return r

def locate_device(argp, _):
    """ Find and init our USB device """
    matches = usb.core.find(find_all=True, idVendor=VID_SILABS,
                            custom_match=product_filter)
    matches = list(matches) #-- force the lazy generator
    if not matches:
        argp.error("Did not find any Silabs EFM8 USB bootloaders connected")
    if len(matches) > 1:
        argp.error("Found {:d} devices. This is not supported. Disconnect some:\n{:s}"
                   .format(len(matches), str.join("\n", [repr(d) for d in matches])))
    #-- whew, is error handling hard.
    device = matches[0]

    #-- tell the kernel to stay back
    for intf in device.get_active_configuration():
        if device.is_kernel_driver_active(intf.bInterfaceNumber):
            device.detach_kernel_driver(intf.bInterfaceNumber)
    device.set_configuration()
    return device

#-----------------------------------------------------------------------------#

def cmd_identify(dev, opts):
    """ The identify commandline handler. Will try the user-passed ID, or
    all 65536 possible IDs """
    if opts.id is None:
        for a in range(256):
            for b in range(256):
                if do_identify(dev, a, b):
                    print("The device identifies as " + identify_interpret(a,b))
                    return 0
        print("Identification failed!")
        return 12

    a, b = [int(s, base=16) for s in opts.id.split(':')]
    if do_identify(dev, a, b):
        print("Identified as " + identify_interpret(a, b))
    else:
        print("Identify as {:2X}:{:2X} was NACK".format(a, b))
        return 13
    return 0

def identify_interpret(a, b):
    datasheet_hits = {
        (0x32, 0x41): "EFM8UB10F16G_QFN28",
        (0x32, 0x43): "EFM8UB10F16G_QFN20",
        (0x32, 0x45): "EFM8UB11F16G_QSOP24",
        (0x32, 0x49): "EFM8UB10F8G_QFN20",
        (0x32, 0x4A): "EFM8UB11F16G_QFN24",
    }
    if (a,b) in datasheet_hits.keys():
        return "{} [{:2X}:{:2X}].".format(datasheet_hits[a,b], a, b)
    else:
        return "{:2X}:{2X} ?.. which is unknown DEVICEID:DERIVID, proceed with care"

def do_identify(dev, a, b):
    """
    > Identify 0x30 — [id:2]
    > This optional command is normally the first command sent. It is used to
    confirm that the boot image is compatible with the target. The id is the
    device and derivative ID's concatenated together [device_id:derivative_id],
    and these ID's can be found in the device Reference Manual. A BADID error
    (0x42) is returned if the id field does not match the target id. If a boot
    image is compatible with multiple targets, this command can be resent with
    different id's until an ACK (0x40) is received.
    """
    hid_set_report(dev, [36, 3, 0x30, a, b])
    r = hid_get_report(dev)
    return r[0] == 0x40

def cmd_flash(dev, opts):
    """ flash cmdline handler """
    ihex = IntelHex(source=opts.img)
    do_setup(dev)
    for a, b in ihex.segments():
        segment = ihex.tobinstr(start=a, end=b-1)
        write_chunked(dev, segment, a, chunksize=128)
        crc_check(dev, segment, a)

def write_chunked(dev, datum, addr, chunksize):
    PAGE = 512
    if addr % PAGE != 0:
        pagestart = addr // PAGE * PAGE
        warnings.warn(
            "Unaligned segment start @ {:04X}; flash page [{:04X}-{:04X}) erase skipped!"
            .format(addr, pagestart, pagestart + PAGE)
        )
        #do_erase(dev, pagestart)
    while len(datum) > 0:
        size = min(chunksize, len(datum))
        chunk, datum = datum[:size], datum[size:]

        if addr % PAGE == 0:
            do_erase(dev, addr)
        do_write(dev, addr, chunk)
        #crc_check(dev, chunk, addr)

        addr += size

def do_setup(dev):
    """
    > Setup 0x31 — [keys:2, bank:1]
    > This command must be sent once before any command that modifies or
    verifies flash. It passes the flash keys to the bootloader and selects the
    active flash bank. The keys parameter for all devices is 0xA5F1. The bank
    parameter should be set to 0x00 for all parts except EFM8SB2, where it can
    be used to select scratchpad flash. For the SB2 devices, a bank value of
    0x00 selects user flash, and 0x01 selects scratchpad flash. This command
    always returns ACK (0x40).
    """
    hid_set_report(dev, [36, 4, 0x31, 0xA5, 0xF1, 0x00])
    assert hid_get_report(dev) [0] == 0x40 #pylint: disable=bad-whitespace

def do_erase(dev, addr):
    """
    > Erase 0x32 — [addr:2, data:0-128]
    > The erase command behaves the same as the write command except that it
    erases the flash page at the desired address before writing any data. To
    perform a page erase without writing data, simply do not include data with
    the command. The data range of an erase command must not cross a flash page
    boundary, as the bootloader is not aware of page boundaries and only erases
    the flash page of the starting address of the command. A RANGE error (0x41)
    is returned if the targeted address range cannot be written by the
    bootloader.
    """
    addrH, addrL = addr // 256, addr % 256
    hid_set_report(dev, [36, 3, 0x32, addrH, addrL])
    assert hid_get_report(dev) [0] == 0x40 #pylint: disable=bad-whitespace

def do_write(dev, addr, data):
    """
    > Write 0x33 — [addr:2, data:1-128]
    > Writes the payload data to flash starting at the indicated address. Does
    not erase the flash before writing. A RANGE error (0x41) is returned if the
    targeted address range cannot be written by the bootloader.
    """
    addrH, addrL = addr // 256, addr % 256
    dlen, data = len(data), list(data)
    hid_set_report(dev, [36, dlen + 3, 0x33, addrH, addrL] + data)
    assert hid_get_report(dev) [0] == 0x40 #pylint: disable=bad-whitespace

def crc_check(dev, data, addr):
    expected = crc16_ccitt(0, data)
    r = do_verify(dev, addr, addr + len(data) - 1, expected)
    if r == 0x43:
        raise RuntimeError(
            "CRC mismatch @ {:04X}, expected {:04X}, actual <unknown>".format(addr, expected)
        )

def crc16_ccitt(crc, data):
    """ "XMODEM", poly=0x1021, init=0x0000 """
    msb = crc >> 8
    lsb = crc & 255
    for c in data:
        x = c ^ msb
        x ^= (x >> 4)
        msb = (lsb ^ (x >> 3) ^ (x << 4)) & 255
        lsb = (x ^ (x << 5)) & 255
    return (msb << 8) + lsb

def do_verify(dev, addr1, addr2, crc16):
    """
    > Verify 0x34 — [addr1:2, addr2:2, CRC16:2]
    > This command computes a CRC16 (CCITT-16, XModem) over the flash contents
    starting at addr1 up to and including addr2 and compares the result to
    CRC16. Returns a CRC error (0x43) if the CRC's do not match.
    """
    addr1H, addr1L = addr1 // 256, addr1 % 256
    addr2H, addr2L = addr2 // 256, addr2 % 256
    crcH, crcL = crc16 // 256, crc16 % 256
    hid_set_report(dev, [36, 7, 0x34, addr1H, addr1L, addr2H, addr2L, crcH, crcL])
    r = hid_get_report(dev)
    return r[0]

def do_lock(dev, sig=0xFF, lock=0xFF):
    """
    > Lock 0x35 — [sig:1, lock:1]
    > This command overwrites the bootloader signature and flash lock bytes
    with the payload values. Setting the signature to 0xA5 will enable the
    bootloader, and setting it to 0x00 will permanently disable the bootloader.
    The signature or lock values are not changed if their corresponding
    parameter is set to 0xFF, which enables writing the lock byte without
    changing the signature and vice versa. This command always returns ACK.
    """
    hid_set_report(dev, [36, 3, 0x35, sig, lock])
    hid_get_report(dev)

def cmd_runapp(dev, _):
    """ runapp cmdline handler """
    do_runapp(dev)

def do_runapp(dev):
    """
    > RunApp 0x36 — [option:2]
    > Resets the device in order to start the application. Currently the option
    field is unused. The command always returns ACK (0x40) and the USB
    bootloader will delay 100 ms before resetting to give the host time to
    close the connection.
    """
    hid_set_report(dev, [36, 3, 0x36, 0x00, 0x00])
    hid_get_report(dev)

def cmd_dump(dev, opts):
    """ Dumps the firmware. Slowly. Essentially bruteforcing the CRC16 feature. """
    #-- this is a permutation of range(256) sorted by occurence frequency to optimize search
    freq_order = (
        0x0, 0x12, 0x90, 0x1, 0xe0, 0x2, 0xf0, 0x22, 0xa3, 0x80, 0xff, 0x3, 0x20,
        0xe5, 0xe4, 0x75, 0xae, 0xfb, 0x7f, 0xaf, 0x82, 0xef, 0x83, 0x60, 0x5, 0xf5,
        0x70, 0x4, 0xfe, 0xe7, 0x74, 0x7, 0xb1, 0xc, 0x24, 0x7a, 0x6, 0xd0, 0x40,
        0x8, 0xc0, 0xfd, 0xfa, 0x79, 0x21, 0xb, 0x9, 0x7b, 0x54, 0x30, 0x94, 0xc3,
        0xfc, 0xee, 0xd1, 0x7d, 0x28, 0x13, 0xa, 0x10, 0xc8, 0x50, 0xed, 0xd, 0xe9,
        0xb4, 0x7e, 0x14, 0x25, 0xdf, 0xb0, 0x64, 0xf9, 0xf, 0x2c, 0x29, 0x2b, 0xc5,
        0xec, 0x11, 0x44, 0xe, 0xeb, 0x15, 0x16, 0xf8, 0xcc, 0xd3, 0x8f, 0xaa, 0x27,
        0x93, 0xa7, 0x43, 0xbb, 0x92, 0xa5, 0xc2, 0xab, 0xea, 0x4e, 0x9e, 0x53,
        0xf6, 0xf2, 0x7c, 0xad, 0x17, 0xc4, 0x89, 0x33, 0x71, 0x1d, 0xa2, 0x46,
        0x8a, 0x9a, 0x23, 0xa9, 0x8d, 0x1b, 0x1f, 0x1c, 0x8e, 0xce, 0x78, 0x3a,
        0x2a, 0xd2, 0xa8, 0x9c, 0x26, 0x1e, 0x1a, 0xa4, 0x88, 0x65, 0xcd, 0x95,
        0x3c, 0xb8, 0x42, 0xe3, 0x9d, 0x2f, 0x6d, 0xe1, 0x4c, 0xe2, 0x38, 0xb6,
        0xa0, 0x91, 0xe8, 0x9f, 0xd8, 0x18, 0x4f, 0xb2, 0xac, 0xb3, 0xcf, 0x8c,
        0xca, 0xde, 0x32, 0xc6, 0xe6, 0x85, 0xc9, 0x99, 0x4b, 0x96, 0xa1, 0x3e,
        0x73, 0xf7, 0xf3, 0x98, 0xd5, 0x81, 0x97, 0xc1, 0x35, 0xb5, 0x31, 0xd4,
        0xa6, 0x19, 0xf4, 0x69, 0xb9, 0xbc, 0x76, 0x55, 0x41, 0x48, 0x2d, 0xda,
        0x45, 0x86, 0x52, 0x4a, 0x6c, 0xba, 0x6e, 0x9b, 0x37, 0xdc, 0x3b, 0x49,
        0x61, 0xcb, 0x5e, 0x6f, 0x6b, 0x58, 0xdb, 0xf1, 0x68, 0x87, 0x2e, 0xbd,
        0xdd, 0x47, 0x39, 0x5a, 0x56, 0xbf, 0xb7, 0x36, 0x66, 0x77, 0x5d, 0x3d,
        0xbe, 0x34, 0x63, 0x4d, 0xd9, 0xd7, 0x5b, 0x84, 0x5f, 0x57, 0x59, 0x5c,
        0x3f, 0x8b, 0x62, 0x72, 0x67, 0x51, 0x6a, 0xc7, 0xd6
    )
    empties = {size: crc16_ccitt(0, [0xff] * size) for size in (512,256,128,64,32,16,8,4,2,1)}
    freq_crc = [(byte, crc16_ccitt(0, [byte])) for byte in freq_order]

    #-- first, try to quickly localize non-empty areas
    #-- FIXME detect 8kiB devices and adjust 0x4000 -> 0x2000
    pending_blocks = [(a, a + 512) for a in range(0, 0x4000, 512)]
    known_bytes = {i: None for i in chain(range(0, 0x4000), range(0xfbc0, 0xfc00))}
    while pending_blocks:
        blockA, blockB = pending_blocks.pop()
        blocksize = blockB - blockA
        emptyCRC = empties[blocksize]
        checkRet = do_verify(dev, blockA, blockB-1, emptyCRC)
        if 0x40 == checkRet:
            #-- gotcha, the whole block is filled with ones
            for i in range(blockA, blockB):
                known_bytes[i] = 0xff
            continue
        if 0x43 == checkRet:
            #-- hmm, got some bytes!
            split = (blockA + blockB) // 2
            if blocksize > 1:
                pending_blocks.append( (blockA, split) )
                pending_blocks.append( (split, blockB) )
            continue
        warnings.warn(
            "Unexpected ret 0x{:02X} from verify({:04X}, {:04X}, {:04X})"
            .format(checkRet, blockA, blockB-1, emptyCRC)
        )

    #-- second, find missing byte values
    total = sum(1 for v in known_bytes.values() if v is None)
    print("== {} bytes to guess ==".format(total))
    sofar = 0
    for cursor in known_bytes.keys():
        if known_bytes[cursor] is not None:
            continue
        for found, candidate in freq_crc:
            checkRet = do_verify(dev, cursor, cursor, candidate)
            if 0x43 == checkRet:
                continue
            if 0x40 == checkRet:
                known_bytes[cursor] = found
                break
            warnings.warn(
                "Unexpected ret 0x{:02X} from verify({:04X}, {:04X}, {:04X})"
                .format(checkRet, cursor, cursor, candidate)
            )
        else:
            warnings.warn("Couldn't find a byte value??") #-- shouldn't fire

        sofar += 1
        percent = sofar / total
        progress = "#" * int(24 * percent) + "-" * int(24 * (1 - percent))
        eraseline = "\x1B[2K\x1B[G"
        print("{}[{}] {:2.1f}% done ({} of {})"
              .format(eraseline, progress, percent * 100, sofar, total),
              end='')
    print('')

    #-- finally, save the image
    img = IntelHex(known_bytes)
    img.tofile(opts.img, format='hex') # can do format='bin'

def trace(direction, content):
    """ Trace device-host communications """
    if opts.trace:
        if direction == 'in':
            print([chr(c) if chr(c).isprintable() else "%02X" % c for c in content])
        if direction == 'out':
            hex = str.join(' ', ["%02X" % c for c in content])
            hex = hex.replace('24', '$', 1)
            print(hex + " -> ", end='')
    else:
        #if direction == 'in':
        #    print(chr(content[0]), end='')
        pass

def main(): #pylint: disable=missing-docstring
    argP = argparse.ArgumentParser(
        description="EFM8 factory bootloader client",
        epilog="Remember to put the device in bootloader mode! (C2D to GND and power-on)"
    )
    argP.add_argument('--trace', action='store_true', help="Dump all communication bytes")
    actP = argP.add_subparsers(title="actions")

    cmdID = actP.add_parser('identify', help="Identify (0x30) command")
    cmdID.set_defaults(cmd=cmd_identify)
    cmdID.add_argument('id', nargs='?', default=None,
                       help="DEVICEID:DERIVID, two bytes in format AA:BB")

    cmdApp = actP.add_parser('runapp', help="Reboot into main user firmware")
    cmdApp.set_defaults(cmd=cmd_runapp)

    cmdFlash = actP.add_parser('upload', help="Flash given ihex image")
    cmdFlash.set_defaults(cmd=cmd_flash)
    cmdFlash.add_argument('img', metavar="IHEX",
                          type=argparse.FileType('r'), default=sys.stdin,
                          help="an Intel HEX firmware file [STDIN]")

    cmdDump = actP.add_parser('dump', help="Dump the firmware (SLOW) via CRC16")
    cmdDump.set_defaults(cmd=cmd_dump)
    cmdDump.add_argument('img', metavar="IHEX",
                         type=argparse.FileType('w'),
                         help="filename to save the ihex dump")

    global opts
    opts = argP.parse_args()
    device = locate_device(argP, opts)
    return opts.cmd(device, opts)

if __name__ == "__main__":
    sys.exit(main())
