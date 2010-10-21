CC:=gcc
DEBUG=1

CFLAGS=-I../deps/libev -DEV_STANDALONE=1

CFLAGS+=-I../deps/uthash
OBJS=radiusproxy.o md5.o
LIBS+=-lm

SYS=$(shell uname -s)

ifeq ($(SYS), Linux)
	LIBS+=-lrt -Wl,--gc-sections -ffunction-sections
endif

ifeq ($(DEBUG), 1)
	CFLAGS += -ggdb -DDEBUG
endif

all: radiusproxy


radiusproxy: $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS)

.c.o: %.c
	$(CC) $(CFLAGS) -c  $*.c

clean:
	rm -f *.o radiusproxy
