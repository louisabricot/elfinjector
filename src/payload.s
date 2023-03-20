SECTION .text
	global _payload
	global _payloadend
	global _stub
	global _decrypt

_payload:

pagestart dq 0xffffffffffffffff
end dq 0xffffffffffffffff
textstart dq  0xffffffffffffffff
textlen dq	0xffffffffffffffff
address dq	0x0000000000000000

msg db `.....WOODY.....\n`, 0x0

_stub:
	push rdx
	mov rdi, 1			
	mov rdx, 16			 		 
	lea rsi, [rel msg]			 
	mov rax, 1					 
	syscall
_writeable:
	mov rdi, [rel pagestart]
	mov rsi, [rel end]
	sub rsi, [rel pagestart]
	mov rdx, 0x7
	mov rax, 10
	syscall

_decrypt:
	mov rdi, [rel textstart]
	mov rdx, [rel textlen]
.decrypt_loop:
	mov al, [rdi]
	dec al
	
	cmp rdx, 0
	je _mprotect
	
	mov [rdi], al
	
	inc rdi
	dec rdx
	jmp .decrypt_loop

_mprotect:
	mov rdi, [rel pagestart] 
	mov rsi, [rel end]
	sub rsi, [rel pagestart]
	mov rdx, 0x5
	mov rax, 10
	syscall
	pop rdx
_jmp_to_old_entrypoint:
	mov rax, [rel address]
	jmp rax
_payloadend:
