CC:=gcc
DEBUG=1

CFLAGS=-I../deps/libev -DEV_STANDALONE=1 -DEV_FEATURES=0 -DEV_MULTIPLICITY=1 -DEV_USE_POLL=1

CFLAGS+=-I../deps/uthash
OBJS=radiusproxy.o md5.o
LIBS+=-lm -lrt -Wl,--gc-sections -ffunction-sections


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
