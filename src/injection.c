#include "../inc/woody.h"

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
			return &(sheader[i]);
	}
	return NULL;
}

static int			pt_load_injection(void *fmap, Elf64_Phdr *pheader, Elf64_Shdr *text)
{
	Elf64_Ehdr		*eheader;
	void			*loader;
	uint64_t		jmp_addr;
	size_t			page_size;
	uintptr_t		start;
	uintptr_t		end;
	uintptr_t		page_start;

	eheader = (Elf64_Ehdr *)fmap;

	jmp_addr = eheader->e_entry - (pheader->p_vaddr + pheader->p_memsz + PAYLOAD_SIZE);
	eheader->e_entry = pheader->p_vaddr + pheader->p_memsz + DATA_SIZE;

	// Find page size for this system
	page_size = sysconf(_SC_PAGESIZE);

	// Calculate start and end of the .text section
	start = (uintptr_t)(BASE_ADDRESS + text->sh_offset);
	end = start + text->sh_offset;

	// Calculate start of page for mprotect
	page_start = start & -page_size;

	//Copy payload into padding
	loader = fmap + pheader->p_offset + pheader->p_memsz;
	memcpy(loader, _payload, PAYLOAD_SIZE);

	//Rewrite our payload with correct addresses
	memcpy(loader, &page_start, sizeof(uintptr_t));
	memcpy(loader + sizeof(uintptr_t), &end, sizeof(uintptr_t));
	memcpy(loader + 2 * sizeof(uintptr_t), &start, sizeof(uintptr_t));
	memcpy(loader + 3 * sizeof(uintptr_t), &text->sh_size, sizeof(uintptr_t));
	memcpy(loader + 4 * sizeof(uintptr_t), &jmp_addr, sizeof(uint64_t));

	//Update segment size variable with our payload size
	pheader->p_filesz += PAYLOAD_SIZE;
	pheader->p_memsz += PAYLOAD_SIZE;

	return (SUCCESS);
}

static int			enough_space(Elf64_Phdr *pheader, Elf64_Phdr *next)
{
	uint64_t padding_size;

	//TODO: why is padding size computed this way?
	padding_size = pheader->p_offset + pheader->p_filesz - next->p_offset;
	if (padding_size > (uint64_t)PAYLOAD_SIZE)
		return (1);
	return (0);
}

static int			is_injectable(Elf64_Phdr *pheader)
{
	Elf64_Phdr *next;

	next = pheader;
	next++;
	if (pheader->p_type == PT_LOAD && \
		(pheader->p_flags & PF_X) && \
		(pheader->p_flags & PF_R) && \
		next->p_type == PT_LOAD && \
		enough_space(pheader, next))
		return (1);
	return (0);
}

int					inject(void *fmap)
{
	Elf64_Ehdr		*eheader;
	Elf64_Phdr		*pcurr;
	Elf64_Shdr		*text;

	eheader = (Elf64_Ehdr *)fmap;
	pcurr = (Elf64_Phdr *)(fmap + eheader->e_phoff);
	for (int i = 1; i < eheader->e_phnum; i++ )
	{
		if (is_injectable(pcurr))
		{
			printf("Is injectable\n");
			text = find_section(fmap, ".text");
			if (pt_load_injection(fmap, pcurr, text) == SUCCESS)
			{
				encrypt(fmap + text->sh_offset, text->sh_size);
				return (SUCCESS);
			}
			//TODO: print OXCAFEBABE in padding
		}
		pcurr++;
	}
	printf("Could not inject!");
	return (ERROR);
}
