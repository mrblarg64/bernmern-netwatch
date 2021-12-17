default: bmnws

#override CFLAGS += -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -pipe -march=native -O3 -flto -fuse-linker-plugin
#override LDFLAGS += -pipe -march=native -O3 -flto -fuse-linker-plugin

override CFLAGS += -lgnutls -lpthread -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -pipe -march=native -O3 -flto -fuse-linker-plugin

CC=gcc

bmwc: bmnws.c
	$(CC) $(CFLAGS) bmnws.c

clean:
	$(RM) bmnws src/*.o

#SRCS = $(wildcard src/*.c)
#OBJS = $(SRCS:.c=.o)

#bmnws: $(OBJS)
#	$(CC) $(LDFLAGS) $(OBJS) -o bmnws
#OBJS: $(SRCS)
#	$(CC) $(CFLAGS) -c -I src -o $@ $(SRCS)

#clean:
#	$(RM) bmnws src/*.o
