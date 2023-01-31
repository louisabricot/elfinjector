#ifndef WOODY_H
# define WOODY_H
# include <stdio.h>
# include <fcntl.h>
# include <sys/mman.h>
# include <unistd.h>
# include <elf.h>
# include <string.h>
# include <stdlib.h>

# define SELFMAG 4
# define ELFMAG "\177ELF"
# define EM_X86_64	62 /* AMD x86-64 architecture */
# define ELFCLASS32	1 /* 32-bit objects */
# define ELFCLASS64	2 /* 64-bit objects */

//struct Elf64_Ehdr;
//typedef struct elf64_hdr {
//    unsigned char    e_ident[EI_NIDENT];
//    Elf64_Half e_type;
//    Elf64_Half e_machine;
//    Elf64_Word e_version;
//    Elf64_Addr e_entry;
//    Elf64_Off e_phoff;
//    Elf64_Off e_shoff;
//    Elf64_Word e_flags;
//    Elf64_Half e_ehsize;
//    Elf64_Half e_phentsize;
//    Elf64_Half e_phnum;
//    Elf64_Half e_shentsize;
//    Elf64_Half e_shnum;
//    Elf64_Half e_shstrndx;
//} Elf64_Ehdr;

//typedef struct
//{
//  Elf64_Word p_type;   /* Segment type */
//  Elf64_Word p_flags;  /* Segment flags */
//  Elf64_Off  p_offset; /* Segment file offset */
//  Elf64_Addr p_vaddr;  /* Segment virtual address */
//  Elf64_Addr p_paddr;  /* Segment physical address */
//  Elf64_Xword p_filesz;/* Segment size in file */
//  Elf64_Xword p_memsz; /* Segment size in memory */
//  Elf64_Xword p_align; /* Segment alignment */
//} Elf64_Phdr;

extern void _payload(void);
extern void _stub(void);
extern void _payloadend(void);
#endif
