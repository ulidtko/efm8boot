# Silicon Labs EFM8 Factory Bootloader client

This program talks with the factory pre-programmed AN945 USB bootloader on EFM8 devices.

## Features ##

- [x] `.ihex` firmware upload to EFM8UB1, EFM8UB2, EFM8UB3 chips
- [x] device identification
- [x] firmware dump!

Eventhough the AN945 protocol "doesn't allow" direct flash reading, it still allows checksumming via CRC16. That's enough to restore the complete flash image, albeit through a large number of 07 Verify requests `8-)`

# References
Application Note AN945: https://www.silabs.com/documents/public/application-notes/an945-efm8-factory-bootloader-user-guide.pdf
