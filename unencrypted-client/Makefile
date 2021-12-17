default: bmnwuc

#override CFLAGS += -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -pipe -march=native -O3 -flto -fuse-linker-plugin
#override LDFLAGS += -pipe -march=native -O3 -flto -fuse-linker-plugin

override CFLAGS += -D DEBUG -Wall -Wextra -Wno-unused-variable -Wno-unused-parameter -pipe -march=native -O3 -flto -fuse-linker-plugin

CC=gcc

bmwc: bmnwuc.c
	$(CC) $(CFLAGS) bmnwuc.c

clean:
	$(RM) bmnwuc src/*.o

#SRCS = $(wildcard src/*.c)
#OBJS = $(SRCS:.c=.o)

#bmnwuc: $(OBJS)
#	$(CC) $(LDFLAGS) $(OBJS) -o bmnwuc
#OBJS: $(SRCS)
#	$(CC) $(CFLAGS) -c -I src -o $@ $(SRCS)

#clean:
#	$(RM) bmnwuc src/*.o
