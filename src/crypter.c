#include "../inc/woody.h"

void	xor_block(unsigned char *block, int len)
{
	for (int i = 0; i < len; i++)
	{
		block[i] += 1; 
	}
}

void	encrypt(void *fmap, Elf64_Xword old_memsz)
{
	xor_block(fmap, old_memsz);
}
