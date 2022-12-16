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
void copy_str(char* dest, char* src, int nbytes);

// client code
int main(int argc, char *argv[]) {
    signal(SIGINT, intHandler);
    // get args passed into main
    if(argc != 3){
        perror("wrong format of args into main");
        exit(1);
    }
    int client_port = atoi(argv[1]);
    int server_port = atoi(argv[2]);

    struct sockaddr_in addrSnd, addrRcv;
    sd = UDP_Open(client_port); //
    int rc = UDP_FillSockAddr(&addrSnd, "localhost", server_port);

    char *prompt = "client> ";
    char *msg = (char*) calloc(BUFFER_SIZE, 1);
    char *rest;
    char *func_name;
    int rt;
    write(STDOUT_FILENO, prompt, strlen(prompt));
    while(fgets(msg, BUFFER_SIZE, stdin) != NULL){
        msg = trim(msg);
        if(strlen(msg) == 0){
            write(STDOUT_FILENO, prompt, strlen(prompt));
            continue;
        }

        // rc = UDP_Write(sd, &addrSnd, msg, BUFFER_SIZE);
        // if (rc < 0) {
	    //     printf("client:: failed to send\n");
        //     continue;
        // }
        // printf("client:: send message [%s]\n", msg);
        // printf("client:: wait for reply...\n");
        rest = strdup(msg);
        func_name = trim(strtok_r(rest, ":", &rest));
        int npara = 0;
        while(strchr(msg, '&') != NULL) npara++;
        if(!strcmp(func_name, "MFS_Lookup")){

            rt = MFS_Lookup();
            printf("client:: got reply\nrt = %d", rt);
        }
        
        else if(!strcmp(func_name, "MFS_Stat")){
            reply_state_t reply;
            rc = UDP_Read(sd, &addrRcv, (char *)&reply, sizeof(reply_state_t));
            printf("client:: got reply\nrt = %d\nstat.type = %d;  stat.size = %d\n", reply.rt, reply.stat.type, reply.stat.size);
        }
        
        else if(!strcmp(func_name, "MFS_Write")){
            rc = UDP_Read(sd, &addrRcv, (char *)&rt, sizeof(int));
            printf("client:: got reply\nrt = %d", rt);
        }
        
        else if(!strcmp(func_name, "MFS_Read")){
            reply_read_t reply;
            rc = UDP_Read(sd, &addrRcv, (char *)&reply, sizeof(reply_read_t));
            printf("client:: got reply\nrt = %d\n", reply.rt);
            if(reply.rt == 0){
                for(int i = 0; i < 1024/32; i++){
                    printf("%s\n", reply.buffer + i * 32);
                }
            }
            
        }
        
        else if(!strcmp(func_name, "MFS_Creat")){
            rc = UDP_Read(sd, &addrRcv, (char *)&rt, sizeof(int));
            printf("client:: got reply\nrt = %d", rt);
        }
        
        else if(!strcmp(func_name, "MFS_Unlink")){
            rc = UDP_Read(sd, &addrRcv, (char *)&rt, sizeof(int));
            printf("client:: got reply\nrt = %d", rt);
        }
        
        else if(!strcmp(func_name, "MFS_Shutdown")){
            rc = UDP_Read(sd, &addrRcv, (char *)&rt, sizeof(int));
            printf("client:: got reply\nrt = %d", rt);
        }
        
        else {

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

void copy_str(char* dest, char* src, int nbytes) {
    for(int i = 0; i < nbytes; i++) {
        dest[i] = src[i];
    }
}