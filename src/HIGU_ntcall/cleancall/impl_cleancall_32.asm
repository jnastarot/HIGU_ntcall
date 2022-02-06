.686 
.XMM 
.MODEL flat, c 
ASSUME fs:_DATA 
.CODE

EXTERN internal_cleancall_wow64_gate: PROC

internal_cleancall_native_int2e PROC

mov eax, [esp + 4]   ; syscall idx from param  
lea edx, [esp + 0Ch] ; arguments table
int 02Eh
ret

internal_cleancall_native_int2e ENDP


internal_cleancall_native_sysenter PROC

push ebp
mov ebp, esp

mov ecx, [ebp + 0Ch]  ; arguments count
mov edx, [ebp + 010h] ; arguments table

test ecx, ecx
jz make_call

push_argument:
 dec ecx
 push [edx + ecx * 4]
 jnz push_argument

make_call:
mov eax, [ebp + 8] ; syscall idx from param

push ret_address_epilog

call do_sysenter_interupt
lea esp, [esp+4]

ret_address_epilog:
mov esp, ebp
pop ebp

ret

do_sysenter_interupt:

mov edx, esp

sysenter

ret

internal_cleancall_native_sysenter ENDP


internal_cleancall_WOW64 PROC

push ebp
mov ebp, esp

mov ecx, [ebp + 0Ch]  ; arguments count
mov edx, [ebp + 010h] ; arguments table

test ecx, ecx
jz make_call

push_argument:
 dec ecx
 push [edx + ecx * 4]
 jnz push_argument

make_call:
mov eax, [ebp + 8] ; syscall idx from param

push ret_address_epilog

call dword ptr internal_cleancall_wow64_gate ; call KiFastSystemCall
lea esp, [esp+4]

ret_address_epilog:

mov esp, ebp
pop ebp

ret

internal_cleancall_WOW64 ENDP


internal_cleancall_WOW64_syscall PROC

push ebp
mov ebp, esp

and esp, 0FFFFFFF8h

mov edx, [ebp + 4*2]  ; pointer to x64 callback
mov ecx, [ebp + 4*4]  ; arguments table
    
push 033h ; 033 - x64 cs seg
push start_context_in_64mode
retf
start_context_in_64mode:

; x64 execution
;;;;;;;;;;;;;;;;;;;;

db 41h ; push r15
db 57h 
db 41h ; push r14
db 56h
db 41h ; push r13
db 55h 
db 41h ; push r12
db 54h
db 41h ; push r11
db 53h 
db 41h ; push r10
db 52h
db 41h ; push r9
db 51h
db 41h ; push r8
db 50h  

sub esp, 28h

call edx

add esp, 28h

db 41h ; pop r8
db 58h
db 41h ; pop r9
db 59h
db 41h ; pop r10
db 5Ah
db 41h ; pop r11
db 5Bh
db 41h ; pop r12
db 5Ch
db 41h ; pop r13
db 5Dh
db 41h ; pop r14
db 5Eh
db 41h ; pop r15
db 5Fh

;;;;;;;;;;;;;;;;;;;;

push eax
db 0C7h ; mov dword [esp + 4], 0x23
db 044h
db 024h
db 004h
db 023h
db 000h
db 000h
db 000h
    
mov [esp], end_context_in_64mode
retf

end_context_in_64mode:
    
mov esp, ebp
pop ebp

ret

internal_cleancall_WOW64_syscall ENDP


END