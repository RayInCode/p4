#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/select.h>
#include "mfs.h"
#include "udp.h"

#define BUFFER_SIZE (1000)

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
        retval = select(sdClient + 1, &rfds, NULL, NULL, &tv);
        if (retval == -1){
            perror("select()");
            return -1;
        }
        if (retval == 1){
            rc = UDP_Read(sdClient, &addrRcv, (char *)retInstr, sizeof(MFS_Instr_t));
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
        return retInstr->inum;
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
    if (rc == 1){
        return retInstr->returnVal;
    }
    return -1;
}