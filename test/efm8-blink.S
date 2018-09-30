.area _CODE

init:
    ; disable watchdog
    ;mov 0x97, #0xDE
    ;mov 0x97, #0xAD
    ; mov 0x97, #0xA5 ; ping WDTCN
    ; configure out pin
    ;mov 0xF2, #3    ; P1MDIN, digital P1.0 & P1.1
    ;mov 0xA4, #0    ; P1MDOUT, open-drain all
    ; XBARE <- 1
    mov 0xE3, #0x40 ; XBR2
    mov P1, #0xFE
    ; init delay counters
    mov 11, #0
    mov 12, #0
main:
delay:
    nop
    nop
    nop
    nop
    inc 11
    mov A, 11
    jnz delay
    inc 12
    mov A, 12
    jnz delay

toggle:
    xrl P1, #0x03
    ;xrl P0, #0x80
    sjmp main


; sdas8051 -o efm8-blink.S && sdld -i efm8-blink.rel && r2 -a 8051 ihex://efm8-blink.ihx

; vim: filetype=asm68k
