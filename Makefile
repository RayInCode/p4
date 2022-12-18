CC     := gcc
CFLAGS := -Wall -g 

SRCS   := client.c server.c 

OBJS   := ${SRCS:c=o}
PROGS  := ${SRCS:.c=}

.PHONY: all
all: server libmfs.so mkfs.o client mkfs

server: server.c udp.o mfs.h ufs.h 
	${CC} ${CFLAGS} -fPIC server.c -o server udp.o

udp.o: udp.c udp.h
	${CC} ${CFLAGS} -fPIC -c udp.c 

libmfs.o: libmfs.c mfs.h udp.c udp.h
	${CC} ${CFLAGS} -fPIC -c libmfs.c

libmfs.so: libmfs.o libmfs.o mkfs.o udp.o
	gcc -Wall -g -shared -Wl,-soname,libmfs.so -o libmfs.so libmfs.o udp.o mkfs.o -lc

mkfs.o: mkfs.c ufs.h 
	$(CC) $(CFLAGS) -fPIC -c mkfs.c

mkfs: mkfs.c ufs.h
	$(CC) $(CFLAGS) -fPIC -o mkfs mkfs.c
    
client: client.c libmfs.so
	$(CC) $(CFLAGS) -L. -g -lmfs client.c -o client 

clean:
	rm -f server client ${OBJS} libmfs.so libmfs.o mkfs udp.o mkfs.o

%.o: %.c Makefile
	${CC} ${CFLAGS} -c $<
