#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
 #include <sys/mman.h>

#include "udp.h"
#include "mfs.h"

#define BUFFER_SIZE (1024)

typedef struct {
    int rt;
    MFS_Stat_t stat;
} reply_state_t;

typedef struct {
    int rt;
    char buffer[4096];
} reply_read_t;

int sd;
void intHandler(int dummy);
int is_white_space(char c);
char* ltrim(char *s);
char* rtrim(char *s);
char* trim(char *s);

// client code
int main(int argc, char *argv[]) {
    signal(SIGINT, intHandler);
    // get args passed into main
    if(argc != 2){
        perror("wrong format of args into main");
        exit(1);
    }
    int server_port = atoi(argv[1]);

    int rt = MFS_Init("localhost", server_port);
    if(rt == -1) {
        exit(-1);
    }

    MFS_Stat_t stat;
    rt = MFS_Creat(0, 0, "testdir");
    rt = MFS_Stat(0, &stat);
    rt = MFS_Stat(1, &stat);
    for(int i = 0; i < 40; i++){
        char name[5];
        sprintf(name, "%d", i);
        rt = MFS_Creat(1, 1, name);

        rt = MFS_Lookup(1, name);
    }


    

}


void intHandler(int dummy) {
    UDP_Close(sd);
    exit(130);
}