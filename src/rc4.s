
swap:
	push   rbp
	mov    rbp,rsp
	mov    QWORD PTR [rbp - 0x8],rdi
	mov    QWORD PTR [rbp - 0x10],rsi
	mov    rax, QWORD PTR [rbp - 0x8]
	mov    al, BYTE PTR [rax]
	mov    BYTE PTR [rbp-0x11],al
	mov    rax, QWORD PTR [rbp-0x10]
	mov    cl, BYTE PTR [rax]
	mov    rax, QWORD PTR [rbp-0x8]
	mov    BYTE PTR [rax],cl
	mov    cl, BYTE PTR [rbp-0x11]
	mov    rax, QWORD PTR [rbp-0x10]
	mov    BYTE PTR [rax],cl
	pop    rbp
	ret 

ksa:
	push rbp
	mov rbp, rsp
	sub rsp, 0x30
	mov QWORD PTR [rbp - 0x8], rdi	; byte S[256]
	mov QWORD PTR [rbp - 0x10], rsi	; byte* key 
	mov QWORD PTR [rbp - 0x18], rdx	; size_t key_length
	mov BYTE PTR [rbp - 0x19], 0x0	; j = 0 (at rbp-0x19)
	mov DWORD PTR [rbp - 0x20], 0x0	; i = 0 (at rbp-0x20)

	start_loop_identity_permutation:
		cmp DWORD PTR [rbp - 0x20], 0x100
		jge end_loop_identity_permutation
		mov eax, DWORD PTR [rbp - 0x20]
		mov dl, al
		mov rax, QWORD PTR [rbp - 0x8]
		movsxd rcx, DWORD PTR [rbp - 0x20]
		mov BYTE PTR [rax + rcx * 1], dl
		mov eax, DWORD PTR [rbp - 0x20]
		add eax, 0x1
		mov DWORD PTR [rbp - 0x20], eax
		jmp start_loop_identity_permutation

	end_loop_identity_permutation:
		mov DWORD PTR [rbp - 0x24], 0x0

	start_key_mixing_loop:
		cmp DWORD PTR [rbp - 0x24], 0x100
		jge end_key_mixing_loop
		movzx eax, BYTE PTR [rbp - 0x19]
		mov rcx, QWORD PTR [rbp - 0x8]
		movsxd rdx,DWORD PTR [rbp-0x24]
		movzx  ecx,BYTE PTR [rcx+rdx*1]
		add    eax,ecx
		mov    DWORD PTR [rbp-0x28],eax
		mov    rcx,QWORD PTR [rbp-0x10]
		movsxd rax,DWORD PTR [rbp-0x24]
		xor    edx,edx
		div    QWORD PTR [rbp-0x18]
		mov    eax,DWORD PTR [rbp-0x28]
		movzx  ecx,BYTE PTR [rcx+rdx*1]
		add    eax,ecx
		and    eax,0xff
		mov    BYTE PTR [rbp-0x19],al
		mov    rdi,QWORD PTR [rbp-0x8]
		movsxd rax,DWORD PTR [rbp-0x24]
		add    rdi,rax
		mov    rsi,QWORD PTR [rbp-0x8]
		movzx  eax,BYTE PTR [rbp-0x19]
		add    rsi,rax
		call swap
		mov    eax,DWORD PTR [rbp-0x24]
		add    eax,0x1
		mov    DWORD PTR [rbp-0x24],eax
		jmp start_key_mixing_loop
	end_key_mixing_loop
		add    rsp,0x30
		pop    rbp
		ret
prga:
	push   rbp
	mov    rbp, rsp
	sub    rsp, 0x40
	mov    QWORD PTR [rbp-0x8], rdi		; byte S[256]
	mov    QWORD PTR [rbp-0x10], rsi	; byte* plaintext
	mov    QWORD PTR [rbp-0x18], rdx	; size_t length (of plaintext)
	mov    QWORD PTR [rbp-0x20], 0x0	; i = 0
	mov    QWORD PTR [rbp-0x28], 0x0	; j = 0
	mov    QWORD PTR [rbp-0x30], 0x0	; n = 0
start_prga_loop:
	mov    rax, QWORD PTR [rbp-0x30]
	cmp    rax, QWORD PTR [rbp-0x18]
	jae    end_prga_loop				; break if n >= length
	mov    rax, QWORD PTR [rbp-0x20]	; move i into rax
	add    rax, 0x1						; i++
	and    rax, 0xFF					; i = i & 0xFF
	mov    QWORD PTR [rbp-0x20], rax	; move i back into rbp-0x20
	mov    rax, QWORD PTR [rbp-0x28]	; move j into rax
	mov    rcx, QWORD PTR [rbp-0x8]		; move S into rcx
	mov    rdx, QWORD PTR [rbp-0x20]	; move i into rdx
	movzx  ecx, BYTE PTR [rcx+rdx*1]	; move S[i] into ecx
	add    rax, rcx						; j = j + S[i]
	and    rax, 0xFF					; j = j & 0xFF
	mov    QWORD PTR [rbp-0x28], rax	; move j back into rbp-0x28 from rax
	mov    rdi, QWORD PTR [rbp-0x8]		; rdi = S
	add    rdi, QWORD PTR [rbp-0x20]	; rdi += i
	mov    rsi, QWORD PTR [rbp-0x8]		; rsi = S
	add    rsi, QWORD PTR [rbp-0x28]	; rsi += j
	call   swap
	mov    rax, QWORD PTR [rbp-0x8]		; rax = S
	mov    rcx, QWORD PTR [rbp-0x8]		; rcx = S
	mov    rdx, QWORD PTR [rbp-0x20]	; rdx = i
	movzx  ecx, BYTE PTR [rcx+rdx*1]	; ecx = S[i]
	mov    rdx, QWORD PTR [rbp-0x8]		; rdx = S
	mov    rsi, QWORD PTR [rbp-0x28]	; rsi = j
	movzx  edx, BYTE PTR [rdx+rsi*1]	; edx = S[j]
	add    ecx, edx						; ecx = S[i] + S[j]
	and    ecx, 0xff					; ecx = ecx & 0xFF
	movsxd rcx, ecx						; 
	movzx  eax, BYTE PTR [rax+rcx*1]
	mov    DWORD PTR [rbp-0x34], eax
	mov    esi, DWORD PTR [rbp-0x34]
	mov    rax, QWORD PTR [rbp-0x10]
	mov    rcx, QWORD PTR [rbp-0x30]
	movzx  edx, BYTE PTR [rax+rcx*1]
	xor    edx, esi
	mov    BYTE PTR [rax+rcx*1],dl
	mov    rax, QWORD PTR [rbp-0x30]
	add    rax, 0x1
	mov    QWORD PTR [rbp-0x30],rax
	jmp    start_prga_loop
end_prga_loop:
	add    rsp,0x40
	pop    rbp
	ret

rc4:
	push rbp
	mov rbp, rsp
	sub rsp, 0x120
	mov QWORD PTR [rbp - 0x8], rdi
	mov QWORD PTR [rbp - 0x10], rsi
	mov QWORD PTR [rbp - 0x18], rdx
	mov QWORD PTR [rbp - 0x20], rcx
	lea rdi, [rbp - 0x120]
	mov rsi, QWORD PTR [rbp - 0x8]
	mov rdx, QWORD PTR [rbp - 0x10]
	call ksa
	lea rdi, [rbp - 0x120]
	mov rsi, QWORD PTR [rbp - 0x18]
	mov rdx, QWORD PTR [rbp - 0x20]
	call prga
	mov rax, QWORD PTR [rbp - 0x18]
	add rsp, 0x120
	pop rbp
	ret
