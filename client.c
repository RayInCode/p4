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

    char *prompt = "\n\nclient> ";
    char *msg = (char*) calloc(BUFFER_SIZE, 1);
    char *rest;
    char *func_name;
    write(STDOUT_FILENO, prompt, strlen(prompt));
    while(fgets(msg, BUFFER_SIZE, stdin) != NULL){
        msg = trim(msg);
        if(strlen(msg) == 0){
            write(STDOUT_FILENO, prompt, strlen(prompt));
            continue;
        }
        rest = strdup(msg);
        func_name = trim(strtok_r(rest, ":", &rest));
        if(!strcmp(func_name, "lookup")){
            int pinum = atoi(trim(strtok_r(rest, "&", &rest)));
            char *name = strtok_r(rest, "&", &rest);
            rest = name;
            name = strtok_r(rest, "\"", &rest);
            name = trim(strtok_r(rest, "\"", &rest));
            rt = MFS_Lookup(pinum, name);
            //printf("client:: got reply\nrt = %d\n", rt);
        }
        
        else if(!strcmp(func_name, "stat")){
            int inum = atoi(trim(strtok_r(rest, "&", &rest)));
            MFS_Stat_t stat = {.type = -1, .size = -1};
            rt = MFS_Stat(inum, &stat);
            //printf("client:: got reply\nrt = %d\nstat.type = %d;  stat.size = %d\n", rt, stat.type, stat.size);
        }
        
        else if(!strcmp(func_name, "write")){
            int inum = atoi(trim(strtok_r(rest, "&", &rest)));
            char *wbuffer = strtok_r(rest, "&", &rest);
            char *buffer_rest = wbuffer;
            wbuffer = strtok_r(buffer_rest, "\"", &buffer_rest);
            wbuffer = trim(strtok_r(buffer_rest, "\"", &buffer_rest));
            int size = atoi(trim(strtok_r(rest, "&", &rest)));
            int offset = atoi(trim(strtok_r(rest, "&", &rest)));
            rt = MFS_Write(inum, wbuffer, offset, size);
            //printf("client:: got reply\nrt = %d\n", rt);
        }
        
        else if(!strcmp(func_name, "read")){
            int inum = atoi(trim(strtok_r(rest, "&", &rest)));
            int size = atoi(trim(strtok_r(rest, "&", &rest)));
            int offset = atoi(trim(strtok_r(rest, "&", &rest)));
            char *buffer = (char *)calloc(size + 1, 1);
            rt = MFS_Read(inum, buffer, offset, size);
            //printf("client:: got reply\nrt = %d\n", rt);
        }
        
        else if(!strcmp(func_name, "creat")){
            int pinum = atoi(trim(strtok_r(rest, "&", &rest)));
            int type = atoi(trim(strtok_r(rest, "&", &rest)));
            char *name = strtok_r(rest, "&", &rest);
            rest = name;
            name = strtok_r(rest, "\"", &rest);
            name = trim(strtok_r(rest, "\"", &rest));
            rt = MFS_Creat(pinum, type, name);
            //printf("client:: got reply\nrt = %d\n", rt);
        }
        
        else if(!strcmp(func_name, "unlink")){
            int pinum = atoi(trim(strtok_r(rest, "&", &rest)));
            char *name = strtok_r(rest, "&", &rest);
            rest = name;
            name = strtok_r(rest, "\"", &rest);
            name = trim(strtok_r(rest, "\"", &rest));
            rt = MFS_Unlink(pinum, name);
            //printf("client:: got reply\nrt = %d\n", rt);
        }
        
        else if(!strcmp(func_name, "shutdown")){
            rt = MFS_Shutdown();
            //printf("client:: got reply\nrt = %d\n", rt);
        }
        
        else {
            printf("Invalid function name!\n");
        }
        write(STDOUT_FILENO, prompt, strlen(prompt));
    }

    return 0;
}


void intHandler(int dummy) {
    UDP_Close(sd);
    exit(130);
}

int is_white_space(char c) {
    return (c == ' ' || c == '\t' || c == '\n');
}

char *ltrim(char *s) {
    while(*s != '\0' && is_white_space(*s) ) s++;
    return s;
}

char *rtrim(char *s) {
    char* back = s + strlen(s) - 1;
    while(back >= s && is_white_space(*back)) back--;
    *(back+1) = '\0';
    return s;
}

char *trim(char *s) {
    return rtrim(ltrim(s)); 
}
