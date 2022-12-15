CC     := gcc
CFLAGS := -Wall 

SRCS   := client_demo.c \
	server_demo.c \
	server_yang.c

OBJS   := ${SRCS:c=o}
PROGS  := ${SRCS:.c=}

.PHONY: all
all: ${PROGS}

${PROGS} : % : %.o Makefile
	${CC} $< -o $@ udp.c

clean:
	rm -f ${PROGS} ${OBJS}

%.o: %.c Makefile
	${CC} ${CFLAGS} -c $<

debug:
	rm -f ${PROGS} ${OBJS} ; rm debug.img ; ./mkfs -f debug.img ; gcc server_yang.c udp.c -o server_yang -g -Wall
