#include "woody.h"

int		g_bin_size;

static void	usage(void)
{
	dprintf(STDERR_FILENO, "Usage: ./woody_woodpacker [ELF64 FILE]\n");
	exit(ERROR);
}

static void	create_woody(void *fmap, const int bin_size)
{
	int	fd;

	fd = open(WOODY, O_TRUNC | O_CREAT | O_WRONLY, S_IRWXU);
	if (!fd) {
		munmap(fmap, g_bin_size);	
		dprintf(STDERR_FILENO, "open: %s\n", strerror(errno));
		exit(ERROR);
	}

	//map fmap to woody file
	if (write(fd, fmap, bin_size) == ERROR) {
		close(fd);
		munmap(fmap, g_bin_size);
		dprintf(STDERR_FILENO, "write: %s\n", strerror(errno));
		exit(ERROR);
	}
	
	close(fd);
}

static void		*mapbin(char *bin, int *bin_size)
{
	void		*map;
	int			fd;

	fd = open(bin, O_RDONLY);
	if (fd == ERROR) {
		dprintf(STDERR_FILENO, "open: %s\n", strerror(errno));	
		exit(ERROR);
	}

	//calculate size of bin
	*bin_size = lseek(fd, 0, SEEK_END);
	if (*bin_size == ERROR)
	{
		close(fd);
		dprintf(STDERR_FILENO, "lseek: %s\n", strerror(errno));
		exit(ERROR);
	}

	if (*bin_size == 0)
	{
		close(fd);
		dprintf(STDERR_FILENO, "Invalid size for binary file\n");
		exit(ERROR);
	}

	//mmap the bin into map
	map = mmap(NULL, *bin_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
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

	eheader = fmap;
	if (memcmp(ELFMAG, eheader->e_ident, ELFMAGSIZE) == 0 && (int)(eheader->e_ident[EI_CLASS]) == ELFCLASS64)
		return 1;
	return 0;
}

int		main(int ac, char **av)
{
	void	*fmap;

	if (ac != 2)
		usage();	
	fmap = mapbin(av[1], &g_bin_size);
	if (!is_ELF64(fmap)) {
		munmap(fmap, g_bin_size);
		dprintf(STDERR_FILENO, "%s not a ELF64 file\n", av[1]);
		return ERROR;
	}
	payload_injection(fmap);
	create_woody(fmap, g_bin_size);
	return SUCCESS;
}
