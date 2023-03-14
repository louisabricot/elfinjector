#include "woody.h"
#define PAYLOAD_SIZE (_payloadend - _payload)
#define STUB_SIZE (_payloadend - _stub)
#define TOTAL_PAYLOAD_SIZE (PAYLOAD_SIZE + 5)
#define MSG_SIZE 17
#define FREE_SPACE(next_segment_addr, segment_end_addr) (next_segment_addr - segment_end_addr)
#define THERE_IS_ENOUGH_FREE_SPACE(free_space) (free_space - STUB_SIZE)

uint64_t	g_stub_entrypoint;
int			g_filesize;

void exit_error(char *message)
{
	dprintf(STDERR_FILENO, "%s\n", message);
	exit(-1);
}

void	create_woody(void *fmmap)
{
	//create woody file
	int fd = open("woody", O_TRUNC | O_CREAT | O_WRONLY, 0777);
	if (!fd)
	{
		exit_error("Could not create woody file");
	}

	//copy fmmap to woody file
	write(fd, fmmap, g_filesize);

	close(fd);
}

void *copybin(char *binary)
{
	void	*copy;
	int		fd;

	//open the binary
	fd = open(binary, O_RDONLY);
	if (!fd)
	{
		exit_error("Error opening binary");
	}

	//calculate sizeof binary
	g_filesize = lseek(fd, 0, SEEK_END);
	if (!g_filesize)
	{
		close(fd);
		exit_error("Error lseeking the binary");
	}

	//mmap the binary into copy
	copy = mmap(NULL, g_filesize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (!copy)
	{
		close(fd);
		exit_error("Error mmap the binary\n");
	}

	close(fd);
	return copy;
}

int		is_ELF64(void *fmmap)
{
	Elf64_Ehdr	*eheader;

	eheader = fmmap;
	if (memcmp(ELFMAG, eheader->e_ident, SELFMAG) == 0 && (int)(eheader->e_ident[4]) == ELFCLASS64)
		return 1;
	return 0;
}

void	pt_load_injection(void *fmmap, uint64_t original_entrypoint, Elf64_Ehdr *eheader, Elf64_Phdr *pheader)
{
	void	*loader;
	int		jmp_addr;
	char	jmp = 0xe9;

	//overwrite binary entrypoint to jump to payload
	g_stub_entrypoint = pheader->p_offset + pheader->p_memsz;
	eheader->e_entry = pheader->p_vaddr + pheader->p_memsz + MSG_SIZE;

	//load payload from g_stub_entrypoint
	loader = fmmap + g_stub_entrypoint;
	memcpy(loader, _payload, PAYLOAD_SIZE);
	loader += PAYLOAD_SIZE;

	//add at the end of the payload a jump instruction to the original entrypoint
	memcpy(loader, &jmp, sizeof(jmp));
	loader += sizeof(jmp);

	jmp_addr = original_entrypoint - (pheader->p_vaddr + pheader->p_memsz + TOTAL_PAYLOAD_SIZE);
	memcpy(loader, &jmp_addr, sizeof(int));

	//update of filesz and memsz to account for size of payload
	pheader->p_filesz += TOTAL_PAYLOAD_SIZE;
	pheader->p_memsz += TOTAL_PAYLOAD_SIZE;
}

int	try_inject_payload(void *fmmap, Elf64_Phdr* pheader)
{
	Elf64_Ehdr	*eheader = (Elf64_Ehdr *)fmmap;
	Elf64_Phdr	*next = pheader + 1;
	const uint64_t original_entrypoint = eheader->e_entry;

	if (pheader->p_type == PT_LOAD)
	{
		if (next && next->p_type == PT_LOAD && THERE_IS_ENOUGH_FREE_SPACE(next->p_offset - (pheader->p_offset + pheader->p_filesz)))
		{
			printf("Injection in RE PT_LOAD padding possible: %lu bytes free\n", next->p_offset - (pheader->p_offset + pheader->p_filesz));
			pt_load_injection(fmmap, original_entrypoint, eheader, pheader);
			return (1);
		}
		else if ( 0 ) //if the next segment is a PT_NOTE
		{
			printf("there is not enough space in RE PT_LOAD padding\n");
		}
	}
	return (0);
}

void	payload_injection(void *fmmap)
{
	Elf64_Ehdr	*eheader;
	Elf64_Phdr	*pheader;

	eheader = fmmap;
	//iterate through segments until we find a RE PT_LOAD
	pheader = fmmap + eheader->e_phoff;
	for (int i = 0; i < eheader->e_phnum; i++ )
	{
		if (pheader->p_type == PT_LOAD)
		{
			if ((pheader->p_flags & PF_X) && (pheader->p_flags & PF_R) && try_inject_payload(fmmap, pheader))
			{
				return;
			}
		}
		pheader++;
	}
}

int				text_section_offset(void *fmmap)
{
	Elf64_Ehdr	*eheader;
	Elf64_Shdr	*sheader;
	Elf64_Shdr	*snheader;
	char		*snames;

	eheader = fmmap;
	sheader = fmmap + eheader->e_shoff;
	snheader = &(sheader[eheader->e_shstrndx]);
	snames = fmmap + snheader->sh_offset;
	write(1, snames, 300);
	for (unsigned long i = 0; i < snheader->sh_size; i++)
	{
		if (strncmp(&snames[i], ".text", 5) == 0)
		{
			printf(".text is at index %lu\n", i);
			return i;
		}
	}
	return -1;
}

Elf64_Shdr		*find_text_section(void *fmmap)
{
	Elf64_Shdr *sheader;
	Elf64_Ehdr *eheader;

	eheader = fmmap;
	sheader = fmmap + eheader->e_shoff;
	int text_offset = text_section_offset(fmmap);
	if (text_offset == -1)
		printf("error there is no text section\n");
	for (int i = 0; i < eheader->e_shnum; i++)
	{
		if (sheader->sh_name == (unsigned int)text_offset)
		{
			return sheader;
		}
		sheader++;
	}

	return NULL;
}

void			encrypt_text_section(void *fmmap)
{
	Elf64_Shdr *sheader;

	//find the text section
	sheader = find_text_section(fmmap);

	//encrypt the text section
	write(1, sheader, sheader->sh_size);
}

int		main(int ac, char **av)
{
	void		*fmmap;

	if (ac != 2)
	{
		printf("Usage: ./fmmap_woodpacker [ELF64_file]\n");
	}
	else 
	{
		fmmap = copybin(av[1]);
		if (!is_ELF64(fmmap))
		{
			dprintf(2, "Error: not a ELF64 file\n");
			//clean return
			return 0;
		}
		payload_injection(fmmap);
		encrypt_text_section(fmmap);
		create_woody(fmmap);
	}
	return 0;
}
