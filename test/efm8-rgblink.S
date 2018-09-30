.area MAIN (abs)
    jmp init

    .byte 0x90, 0x90

init:
    ; 1 -> XBARE
    mov 0xE3, #0x40
    mov P1, #0xFE

init_timers:
    mov 0xA7, #0x10 ; select SFR page 0x10

    ; configure timer T4
    mov 0xA2, #d8   ; TMR4RLL
    mov 0xA3, #f0   ; TMR4RLH
    mov 0xA4, #d8   ; TMR4L
    mov 0xA5, #f0   ; TMR4H
    mov 0x98, #4+#3 ; TR4 + T4XCLK

    ;mov 0xA7, #0 ; select SFR page 0

    ; enable interrupts for T4
    mov 0xCE, 0x10 ; +EIE2_ET4
    ; global interrupt enable
    setb EA ; 0xA8.0

sleep:
    setb 0x87.0 ; PCON0.IDLE
    jmp sleep

.org 0x9B
T4ISR:
    xrl P1, #1

    mov 0xA7, #0x10 ; select SFR page 0x10
    clrb 0x98.7     ; clear TMR4CN0_TF4H
    ;mov 0xA7, #0    ; select SFR page 0

    reti

; vim: filetype=asm68k
