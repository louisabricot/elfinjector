NAME = woody_woodpacker
PROJECTION = woody
PAYLOAD = payload.s

CC = clang 
CFLAGS = -Wall -Wextra -Werror

RM = rm
RF = -rf

INC_DIR = ./inc
SRC_DIR = ./src
OBJ_DIR = ./obj

SRCS = main.c \
       injection.c \
       crypter.c \

vpath %.c $(SRC_DIR)
vpath %.s $(SRC_DIR)

OBJS = $(addprefix $(OBJ_DIR)/, $(SRCS:%.c=%.o) $(PAYLOAD:%.s=%.o))

all: $(NAME)

$(OBJ_DIR): 
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -I $(INC_DIR) -o $@ -c  $<

$(OBJ_DIR)/%.o: %.s
	nasm -f elf64 $< -o $@

$(NAME): $(OBJ_DIR) $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME)

clean:
	$(RM) $(RF) $(OBJ_DIR)

fclean: clean
	$(RM) $(RF) $(NAME)
	$(RM) $(RF) $(PROJECTION)

re: fclean all

.PHONY: all clean fclean re
