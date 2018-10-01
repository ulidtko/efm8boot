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
        if direction == 'in':
            print(chr(content[0]), end='')

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
    global opts
    opts = argP.parse_args()
    device = locate_device(argP, opts)
    return opts.cmd(device, opts)

if __name__ == "__main__":
    sys.exit(main())
