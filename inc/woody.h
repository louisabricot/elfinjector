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

# define MAGIC_NUMBER 0xCAFEBABE
# define WOODY "woody"
# define SUCCESS 0
# define ERROR -1

# define DATA_SIZE (_stub - _payload)
# define BASE_ADDRESS ((unsigned char *)0x400000)
# define PAYLOAD_SIZE (_payloadend - _payload)

extern void _payload(void);
extern void _stub(void);
extern void _payloadend(void);

int			inject(void *fmap);
void		encrypt(void *fmap, Elf64_Xword old_memsz);
#endif
