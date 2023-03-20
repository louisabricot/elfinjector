#ifndef WOODY_H
# define WOODY_H
# include <stdio.h>
# include <fcntl.h>
# include <sys/mman.h>
# include <unistd.h>
# include <elf.h>
# include <string.h>
# include <stdlib.h>
# include <errno.h>
# include <string.h>

# define MOV_RDI_OPCODE 0xbf
# define MOV_RDX_OPCODE 0xba
# define MAGIC_NUMBER 0xCAFEBABE
# define JMP_OPCODE 0xe9
# define WOODY "woody"
# define SUCCESS 0
# define ERROR -1
# define ELFMAGSIZE 4
# define ELFMAG "\177ELF"
# define EM_X86_64	62 /* AMD x86-64 architecture */
# define ELFCLASS32	1 /* 32-bit objects */
# define ELFCLASS64	2 /* 64-bit objects */
# define PAYLOAD_SIZE (_payloadend - _payload)
# define STUB_SIZE (_payloadend - _stub)
# define TOTAL_PAYLOAD_SIZE (PAYLOAD_SIZE + 5) //size of payload + size of jmp instruction
# define MSG_SIZE (_stub - _payload)
# define FREE_SPACE(next_segment_addr, segment_end_addr) (next_segment_addr - segment_end_addr)
extern void _payload(void);
extern void _stub(void);
extern void _payloadend(void);
extern void _decrypt(void);
int			payload_injection(void *fmap);
void	encrypt(void *fmap, Elf64_Xword old_memsz);
#endif
