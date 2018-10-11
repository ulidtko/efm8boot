# Silicon Labs EFM8 Factory Bootloader client

This program talks with the factory pre-programmed AN945 USB bootloader on EFM8 devices.

## Features ##

- [x] `.ihex` firmware upload to EFM8UB1, EFM8UB2, EFM8UB3 chips
- [x] device identification
- [x] firmware dump!

Eventhough the AN945 protocol "doesn't allow" direct flash reading, it still allows checksumming via CRC16. That's enough to restore the complete flash image, albeit through a large-ish number of 07 Verify requests `8-)`

## Dependencies ##
 - [pyusb](https://github.com/pyusb/pyusb)
 - [intelhex](https://github.com/bialix/intelhex)

That's it. Yes, we work over USB HID without any HID libraries. Cause they're all shit. See code.

# Udev rules and permissions #
Drop the included `70-efm8-bootloader.rules` under `/etc/udev/rules.d/`, and `sudo udevadm trigger`.

Then the script can work without root. Depending on your distro, either udev's `uaccess` feature will grant that (not sure I understand how it works), or the classic `plugdev` group membership.

# References
Application Note AN945: https://www.silabs.com/documents/public/application-notes/an945-efm8-factory-bootloader-user-guide.pdf
