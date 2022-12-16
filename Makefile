TARGET = server

CC = gcc
CFLAGS = -g -Wall
current_dir := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
.SUFFIXES: .c .o

all: server client mkfs libmfs.so

server: server.c udp.o
	$(CC) $(CFLAGS) -fPIC server.c -o server udp.o

udp.o: udp.c udp.h
	$(CC) $(CFLAGS) -fPIC -c udp.c
    
libmfs.o: libmfs.c mfs.h udp.h
	$(CC) $(CFLAGS) -fPIC -c libmfs.c

mkfs.o: mkfs.c ufs.h 
	$(CC) $(CFLAGS) -fPIC -c mkfs.c
    
libmfs.so: libmfs.o udp.o
	$(CC) -shared -o libmfs.so libmfs.o udp.o

mkfs: mkfs.c ufs.h
	$(CC) -o mkfs mkfs.c

client: client.c libmfs.so
	$(CC) -L$(current_dir) $(CFLAGS) client.c -g -o client -lmfs

clean:
	-rm -f $(OBJS) server client mkfs libmfs.so *.img *.o *~