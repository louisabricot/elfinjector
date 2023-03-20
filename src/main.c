#include "woody.h"

static void	create_woody(void *fmap, const int fsize)
{
	int	fd;

	fd = open(WOODY, O_TRUNC | O_CREAT | O_WRONLY, S_IRWXU);
	if (!fd) {
		munmap(fmap, fsize);	
		dprintf(STDERR_FILENO, "open: %s\n", strerror(errno));
		exit(ERROR);
	}

	//map fmap to woody file
	if (write(fd, fmap, fsize) == ERROR) {
		close(fd);
		munmap(fmap, fsize);
		dprintf(STDERR_FILENO, "write: %s\n", strerror(errno));
		exit(ERROR);
	}
	
	close(fd);
}

static void		*mapbin(char *bin, int *fsize)
{
	void		*map;
	int			fd;

	fd = open(bin, O_RDONLY);
	if (fd == ERROR)
	{
		dprintf(STDERR_FILENO, "open: %s\n", strerror(errno));	
		exit(ERROR);
	}

	//Calculate size of binary
	*fsize = lseek(fd, 0, SEEK_END);
	if (*fsize == ERROR)
	{
		close(fd);
		dprintf(STDERR_FILENO, "lseek: %s\n", strerror(errno));
		exit(ERROR);
	}

	if (*fsize == 0)
	{
		close(fd);
		dprintf(STDERR_FILENO, "Invalid size for binary file\n");
		exit(ERROR);
	}

	//Map binary into memory
	map = mmap(NULL, *fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED)
	{
		close(fd);
		dprintf(STDERR_FILENO, "mmap: %s\n", strerror(errno));
		exit(ERROR);
	}

	close(fd);
	return map;
}

static int		is_ELF64(void *fmap)
{
	Elf64_Ehdr	*eheader;

	eheader = (Elf64_Ehdr *)fmap;
	if (memcmp(ELFMAG, eheader->e_ident, ELFMAGSIZE) == 0 && (int)(eheader->e_ident[EI_CLASS]) == ELFCLASS64)
		return 1;
	return 0;
}

int		main(int ac, char **av)
{
	void	*fmap;
	int		fsize;

	if (ac != 2)
	{
		dprintf(STDERR_FILENO, "Usage: ./woody_woodpacker [ELF64 FILE]\n");
		return (ERROR);
	}
	
	//Map file into memory
	fmap = mapbin(av[1], &fsize);
	if (!is_ELF64(fmap))
	{
		munmap(fmap, fsize);
		dprintf(STDERR_FILENO, "%s not a ELF64 file\n", av[1]);
		return ERROR;
	}

	payload_injection(fmap);
	
	create_woody(fmap, fsize);
	
	return SUCCESS;
}
