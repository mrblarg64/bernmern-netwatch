default: bmnwc

#override CFLAGS += -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -pipe -march=native -O3 -flto -fuse-linker-plugin
#override LDFLAGS += -pipe -march=native -O3 -flto -fuse-linker-plugin

override CFLAGS += -D DEBUG -lgnutls -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -pipe -march=native -O3 -flto -fuse-linker-plugin

CC=gcc

bmwc: bmnwc.c
	$(CC) $(CFLAGS) bmnwc.c

clean:
	$(RM) bmnwc src/*.o

#SRCS = $(wildcard src/*.c)
#OBJS = $(SRCS:.c=.o)

#bmnwc: $(OBJS)
#	$(CC) $(LDFLAGS) $(OBJS) -o bmnwc
#OBJS: $(SRCS)
#	$(CC) $(CFLAGS) -c -I src -o $@ $(SRCS)

#clean:
#	$(RM) bmnwc src/*.o
