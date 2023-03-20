#include "../inc/woody.h"
# define BASE_ADDRESS ((unsigned char *)0x400000)

uint64_t	g_stub_entrypoint;

void	pt_load_injection(void *fmap, uint64_t old_entry, Elf64_Ehdr *eheader, Elf64_Phdr *pheader, Elf64_Shdr *s)
{
	void	*loader;
	int		jmp_addr;
	char	jmp = JMP_OPCODE;
	
	// Find page size for this system
	size_t pagesize = sysconf(_SC_PAGESIZE);
	
	// Calculate start and end addresses of .text section
	uintptr_t start = (uintptr_t)(BASE_ADDRESS + s->sh_offset);
	uintptr_t end = start + s->sh_size;

	// Calculate start of page for mprotect
	uintptr_t pagestart = start & -pagesize;

	//Calculate the offset to our payload
	g_stub_entrypoint = pheader->p_offset + pheader->p_memsz;

	//Rewrite the entrypoint to jump to the start of our stub
	eheader->e_entry = pheader->p_vaddr + pheader->p_memsz + MSG_SIZE;

	//Point to the start of our payload in memory
	loader = fmap + g_stub_entrypoint;

	//Copy our payload in the padding
	memcpy(loader, _payload, PAYLOAD_SIZE);

	//Rewrite our payload to use correct addresses
	memcpy(loader, &pagestart, sizeof(uintptr_t));
	memcpy(loader + sizeof(uintptr_t), &end, sizeof(uintptr_t));
	memcpy(loader + sizeof(uintptr_t) + sizeof(uintptr_t), &start, sizeof(uintptr_t));;
	memcpy(loader + sizeof(uintptr_t) + sizeof(uintptr_t) + sizeof(uintptr_t), &s->sh_size, sizeof(s->sh_size));;

	//Jumping to the end of our payload
	loader += PAYLOAD_SIZE;

	//Add at the end of the payload a jump instruction to the original entrypoint
	memcpy(loader, &jmp, sizeof(jmp));
	loader += sizeof(jmp);
	jmp_addr = old_entry - (pheader->p_vaddr + pheader->p_memsz + TOTAL_PAYLOAD_SIZE);
	memcpy(loader, &jmp_addr, sizeof(uint64_t));

	//Update segment size variables with TOTAL_PAYLOAD_SIZE
	pheader->p_filesz += TOTAL_PAYLOAD_SIZE;
	pheader->p_memsz += TOTAL_PAYLOAD_SIZE;
}

static char		*get_name(void *fmap, uint64_t sh_name)
{
	Elf64_Ehdr	*eheader;
	Elf64_Shdr	*sheader;
	Elf64_Shdr	*snheader;
	char		*snames;

	eheader = (Elf64_Ehdr *)fmap;
	sheader = (Elf64_Shdr *)(fmap + eheader->e_shoff);
	snheader = &(sheader[eheader->e_shstrndx]);
	snames = (char *)(fmap + snheader->sh_offset);
	return snames + sh_name;
}

static Elf64_Shdr	*find_section(void *fmap, char *name)
{
	Elf64_Ehdr	*eheader;
	Elf64_Shdr	*sheader;
	char		*sh_name;

	eheader = (Elf64_Ehdr *)fmap;
	sheader = (Elf64_Shdr *)(fmap + eheader->e_shoff);
	for (Elf64_Half i = 0; i < eheader->e_shnum; i++)
	{
		sh_name = get_name(fmap, sheader[i].sh_name);
		if (strcmp(name, sh_name) == 0)
		{
			return &(sheader[i]);
		}

	}
	return NULL;
}

int	attempt_injection(void *fmap, Elf64_Ehdr *eheader, Elf64_Phdr *pheader)
{
	Elf64_Phdr	*next;
	Elf64_Off	padding_size;
	Elf64_Xword	old_memsz;
	Elf64_Shdr	*s;
	next = pheader + 1;
	s = find_section(fmap, ".text");
	if ((pheader->p_flags & PF_X) && (pheader->p_flags & PF_R))
	{
		padding_size = pheader->p_offset + pheader->p_filesz - next->p_offset;
		if (next->p_type == PT_LOAD && padding_size > (Elf64_Off)TOTAL_PAYLOAD_SIZE)
		{
			old_memsz = pheader->p_memsz;	
			pt_load_injection(fmap, eheader->e_entry, eheader, pheader, s);
			encrypt(fmap + s->sh_offset, s->sh_size);
			return (1);
		}
	}
	return (0);       
}

void	check_magic_number(Elf64_Ehdr *eheader)
{
	int magic = 0xCAFEBABE;
	if (memcmp(&(eheader->e_ident[EI_PAD]), &magic, sizeof(int)) == 0) {
		dprintf(STDOUT_FILENO, "Already injected\n");
		//TODO: does not inject again
	} else {
		dprintf(STDOUT_FILENO, "Not injected yet\n");
	}
}

int	payload_injection(void *fmap)
{
	Elf64_Ehdr	*eheader;
	Elf64_Phdr 	*pheader;

	eheader = fmap;
	pheader = fmap + eheader->e_phoff;
	check_magic_number(eheader);
	for (int i = 0; i < eheader->e_phnum; i++ )
	{
		if (pheader->p_type == PT_LOAD)
		{
			if (attempt_injection(fmap, eheader, pheader)) {
				//TODO: print OXCAFEBABE in padding
				dprintf(STDOUT_FILENO, "Injected\n");	
				return (SUCCESS);
			}
		}
		pheader++;
	}
	return ERROR;
}
