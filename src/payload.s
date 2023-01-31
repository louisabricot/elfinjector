SECTION .text
	global _payload
	global _payloadend
	global _stub

_payload:

msg db `.....WOODY.....\n`, 0x0

_stub:
	push rdx
	mov rdi, 1
	mov rdx, 16
	lea rsi, [rel msg]
	mov rax, 1
	syscall
	pop rdx

_payloadend:
