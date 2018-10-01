.radix X
.area MAIN (abs)
    sjmp init

    .byte 90, 90

init:
    ; 1 -> XBARE
    mov 0xE3, #0x40
    mov P1, #0xFE

init_timers:
    mov 0xA7, #0x10 ; select SFR page 0x10

    ; configure timer T4
    mov 0xA2, #0xd8   ; TMR4RLL
    mov 0xA3, #0xf0   ; TMR4RLH
    mov 0xA4, #0xd8   ; TMR4L
    mov 0xA5, #0xf0   ; TMR4H
    mov 0x98, #4 + #3 ; TR4 + T4XCLK

    ; enable interrupts for T4
    mov 0xCE, 0x10 ; +EIE2_ET4
    ; global interrupt enable
    setb EA ; 0xA8.0

sleep:
    orl 0x87, #1 ; +PCON0.IDLE
    sjmp sleep

.org 0x9B
T4ISR:
    xrl P1, #1

    mov 0xA7, #0x10 ; select SFR page 0x10
    anl 0x98, #0x7f ; clear TMR4CN0_TF4H
    ;mov 0xA7, #0    ; select SFR page 0

    setb EA
    reti

; sdas8051 -o efm8-rgblink.S && sdld -i efm8-rgblink.rel && r2 -a 8051 ihex://efm8-rgblink.ihx

; vim: filetype=asm68k
