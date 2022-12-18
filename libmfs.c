#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/select.h>
#include "mfs.h"
#include "udp.h"

#define BUFFER_SIZE (1000)

// #ifndef DEBUG
// #define DEBUG
// #endif

int sdClient;
struct sockaddr_in addrSnd, addrRcv;
enum instrType{LOOKUP, STAT, WRITE, READ, CREATE, UNLINK, SHUTDOWN};
typedef struct __MFS_Instr_t{
    enum instrType insType; // instruction type
    int pinum;
    char name[28];
    int inum;
    MFS_Stat_t stat;
    char buffer[4096];
    int offset;
    int nbytes;
    int type; //MFS_REGULAR_FILE or MFS_DIRECTORY
    int returnVal;
} MFS_Instr_t;
MFS_Instr_t *retInstr;

void display_mem(void* mem, int mem_size, int line_len) {
   /*
        mem         - pointer to beggining of memory region to be printed
        mem_size    - number of bytes mem points to
        line_len    - number of bytyes to display per line
   */

    unsigned char* data = mem;
    int full_lines = mem_size / line_len;
    unsigned char* addr = mem;

    for (int linno = 0; linno < full_lines; linno++) {
        // Print Address
        printf("0x%x\t", addr);

        // Print Hex
        for (int i = 0; i < line_len; i++) {
            printf(" %02x", data[linno*line_len + i]);
        }
        printf("\t");

        // Print Ascii
        for (int i = 0; i < line_len; i++) {
            char c = data[linno*line_len + i];
            if ( 32 < c && c < 125) {
                printf(" %c", c);
            }
            else {
                printf(" .");
            }
        }
        printf("\n");

        // Incremement addr by number of bytes printed
        addr += line_len;
    }

    // Print any remaining bytes that couldn't make a full line
    int remaining = mem_size % line_len;
    if (remaining > 0) {
        // Print Address
        printf("0x%x\t", addr);

        // Print Hex
        for (int i = 0; i < remaining; i++) {
            printf(" %02x", data[line_len*full_lines + i]);
        }
        for (int i = 0; i < line_len - remaining; i++) {
            printf("  ");
        }
        printf("\t");

        // Print Hex
        for (int i = 0; i < remaining; i++) {
            char c = data[line_len*full_lines + i];
            if ( 32 < c && c < 125) {
                printf(" %c", c);
            }
            else {
                printf(" .");
            }
        }
        printf("\n");
     }
 }


void display_msg(MFS_Instr_t* msg, int nbytes) {
    printf("function_type=%d\t", msg->insType);
    printf("pinum=%d\t", msg->pinum);
    printf("inum=%d\n", msg->inum);
    printf("offset=%d\t", msg->offset);
    printf("nbyte=%d\t", msg->nbytes);
    printf("type=%d\n",msg->type);
    printf("stat.type=%d\tstat.size=%d\n", msg->stat.type, msg->stat.size);
    printf("rt=%d\n", msg->returnVal);
    printf("name=%s\n", msg->name);
    //printf("buffer=\n");  display_mem(msg->buffer, nbytes, 100);    
    return;        
}

//method to send instruction to the server
int sendInstruction(MFS_Instr_t *instr){
    retInstr = (MFS_Instr_t *)calloc(sizeof(MFS_Instr_t), 1);
    int retval;
    do{
        fd_set rfds;
        struct timeval tv;
        FD_ZERO(&rfds);
        FD_SET(sdClient, &rfds);
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        int rc = UDP_Write(sdClient, &addrSnd, (char *)instr, sizeof(MFS_Instr_t));
        if(rc == sizeof(MFS_Instr_t)) {
            
            #ifdef DEBUG
            printf("\n\nclient :: send passage\n");
            display_msg(instr, instr->nbytes);
            printf("\n\n");
            #endif
        }
        retval = select(sdClient + 1, &rfds, NULL, NULL, &tv);
        if (retval == -1){
            perror("select()");
            return -1;
        }
        if (retval == 1){
            rc = UDP_Read(sdClient, &addrRcv, (char *)retInstr, sizeof(MFS_Instr_t));
            if(rc == sizeof(MFS_Instr_t)) {
            #ifdef DEBUG
            printf("\n\nclient :: receive passage\n");
            display_msg(retInstr, instr->nbytes);
            printf("\n\n");
            #endif
        }
            return 1;
        }
    }while(retval == 0);
    return -1;
}



int MFS_Init(char *hostname, int port){
    int MIN_PORT = 20000;
    int MAX_PORT = 40000;

    srand(time(0));
    int port_num = (rand() % (MAX_PORT - MIN_PORT) + MIN_PORT);

    // Bind random client port number
    sdClient = UDP_Open(port_num);
    assert(sdClient > -1);

    int rc = UDP_FillSockAddr(&addrSnd, hostname, port);
    if (rc == -1){
        return -1;
    }
    return 0;

}

int MFS_Lookup(int pinum, char *name){
    MFS_Instr_t *instr = (MFS_Instr_t *)calloc(sizeof(MFS_Instr_t), 1);
    instr->insType = LOOKUP;
    instr->pinum = pinum;
    memcpy(instr->name, name, 28);

    int rc = sendInstruction(instr);
    if (rc == 1){
        return retInstr->returnVal;
    }
    return -1;
}

int MFS_Stat(int inum, MFS_Stat_t *stat){
    MFS_Instr_t *instr = (MFS_Instr_t *)calloc(sizeof(MFS_Instr_t), 1);
    instr->insType = STAT;
    instr->inum = inum;

    int rc = sendInstruction(instr);
    if (rc == 1){
        if(retInstr->returnVal == 0){
            memcpy(stat, &(retInstr->stat), sizeof(MFS_Stat_t));
            return 0;
        }
    }
    return -1;
}

int MFS_Write(int inum, char *buffer, int offset, int nbytes){
    MFS_Instr_t *instr = (MFS_Instr_t *)calloc(sizeof(MFS_Instr_t), 1);
    instr->insType = WRITE;
    instr->inum = inum;
    memcpy(instr->buffer, buffer, 4096);
    instr->offset = offset;
    instr->nbytes = nbytes;

    int rc = sendInstruction(instr);
    if (rc == 1){
        return retInstr->returnVal;
    }
    return -1;

}

int MFS_Read(int inum, char *buffer, int offset, int nbytes){
    MFS_Instr_t *instr = (MFS_Instr_t *)calloc(sizeof(MFS_Instr_t), 1);
    instr->insType = READ;
    instr->inum = inum;
    memcpy(instr->buffer, buffer, 4096);
    instr->offset = offset;
    instr->nbytes = nbytes;

    int rc = sendInstruction(instr);
    if (rc == 1){
        if(retInstr->returnVal == 0){
            memcpy(buffer, retInstr->buffer, 4096);
            return 0;
        }
    }
    return -1;

}

int MFS_Creat(int pinum, int type, char *name){
    MFS_Instr_t *instr = (MFS_Instr_t *)calloc(sizeof(MFS_Instr_t), 1);
    instr->insType = CREATE;
    instr->pinum = pinum;
    instr->type = type;
    memcpy(instr->name, name, 28);

    int rc = sendInstruction(instr);
    if (rc == 1){
        return retInstr->returnVal;
    }
    return -1;
}

int MFS_Unlink(int pinum, char *name){
    MFS_Instr_t *instr = (MFS_Instr_t *)calloc(sizeof(MFS_Instr_t), 1);
    instr->inum =
    instr->insType = UNLINK;
    instr->pinum = pinum;
    memcpy(instr->name, name, 4096);

    int rc = sendInstruction(instr);
    if (rc == 1){
        return retInstr->returnVal;
    }
    return -1;
}

int MFS_Shutdown(){
    MFS_Instr_t *instr = (MFS_Instr_t *)calloc(sizeof(MFS_Instr_t), 1);
    instr->insType = SHUTDOWN;

    int rc = sendInstruction(instr);
    (void) close(sdClient);
    if (rc == 1){
        return retInstr->returnVal;
    }
    return -1;
}
