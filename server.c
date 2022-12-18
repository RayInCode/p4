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
#include "ufs.h"
#include "mfs.h"

#ifndef DEBUG
#define DEBUG
#endif

// #ifndef REGION
// #define REGION
// #endif

enum functions{Lookup, Stat, Write, Read, Creat, Unlink, Shutdown};

typedef struct {
    unsigned int bits[UFS_BLOCK_SIZE / sizeof(unsigned int)];
} bitmap_t;

typedef struct {
    inode_t inodes[UFS_BLOCK_SIZE / sizeof(inode_t)];
} inode_block;

typedef struct {
    dir_ent_t entries[128];
} dir_block_t;

typedef struct {
    int type;
    int size;
} stat_t;

typedef struct {
    enum functions func;
    int pinum;
    char name[28];
    int inum;
    stat_t stat;
    char buffer[UFS_BLOCK_SIZE];
    int offset;
    int nbytes;
    int type;
    int rt;
} message_t;

unsigned int get_bit(unsigned int *, int);
void set_bit(unsigned int *, int);
int get_dir_block(int, dir_block_t*);
int find_empty_inode_bit();
int find_empty_data_bit();
int set_inode_bit(int);
int set_data_bit(int);
void display_msg(message_t *, int);
void intHandler(int);
int isEmptyDir(int);

int ufs_lookup(int parent_inum, char *name);
int ufs_stat(int inum, stat_t *stat);
int ufs_write(int inum, char* buffer, int nbytes, int offset);
int ufs_read(int inum, char *buffer, int nbytes, int offset);
int ufs_creat(int parent_inum, int type, char *name);
int ufs_unlink(int parent_inum, char *name);
int ufs_shutdown();

int sd;    // socket descriptor
int fd_img;
int total_blocks;
int inodes_per_blocks;
int bits_per_block;
char *meta_ptr;
super_t super;
super_t *super_ptr;
bitmap_t *inode_bitmap_ptr, *data_bitmap_ptr;
inode_block *inode_table_ptr;
dir_block_t *data_region_ptr;

int main(int argc, char* argv[]) {
    signal(SIGINT, intHandler);
    int rc;
    inodes_per_blocks = UFS_BLOCK_SIZE / sizeof(inode_t);
    bits_per_block = UFS_BLOCK_SIZE * 8;

    // get args passed into main
    if(argc != 3){
        perror("wrong format of args into main");
        exit(1);
    }
    int portnum = atoi(argv[1]);
    char *fname_img = argv[2];

    #ifdef DEBUG
    printf("portnum:%d,  file_system_image:%s\n", portnum, fname_img);
    #endif

    // load file system image file
    fd_img = open(fname_img, O_RDWR);
    if(fd_img < 0){
        perror("failed to open file system image!");
        exit(1);
    }
    rc = pread(fd_img, &super, sizeof(super_t), 0);
    if(rc < 0){
        printf("fd = %d \n", fd_img);
        perror("failed to read super block from img file");
        exit(1);
    }

    total_blocks = super.data_region_addr + super.num_data; 
    super_ptr = (super_t *)mmap(NULL, (super.data_region_addr + super.data_region_len) * UFS_BLOCK_SIZE, PROT_WRITE, MAP_PRIVATE, fd_img, 0);
    inode_bitmap_ptr = (bitmap_t *)super_ptr + 1;
    data_bitmap_ptr = inode_bitmap_ptr + super.inode_bitmap_len;
    inode_table_ptr = (inode_block *)(data_bitmap_ptr + super.data_bitmap_len);
    data_region_ptr = (dir_block_t *)(data_bitmap_ptr + super.inode_region_len);

    // set up UDP socket file and bind with a socket address (port, internet address)
    sd = UDP_Open(portnum);
    assert(sd > -1);
    struct sockaddr_in addr;
    message_t message, reply;

    while(1) {
        printf("\nserver:: waiting...\n");
        memset(&message, 0, sizeof(message_t));
        memset(&reply, 0, sizeof(message_t));
        rc = UDP_Read(sd, &addr, (char*)&message, sizeof(message_t));
        assert(rc == sizeof(message_t));

        printf("\nserver:: read message.\n");
        display_msg(&message, message.nbytes);

        switch (message.func)
        {
            case Lookup:
                reply.rt = ufs_lookup(message.pinum, message.name);
                reply.func = message.func;
                reply.pinum = message.pinum;
                memcpy(reply.name, message.name, 28);
                rc = UDP_Write(sd, &addr, (char*)&reply, sizeof(message_t));
                #ifdef DEBUG
                printf("\nserver:: reply message.\n");
                display_msg(&reply, message.nbytes);
                #endif
                break;

            case Stat:
                reply.rt = ufs_stat(message.inum, &reply.stat);
                reply.func = message.func;
                reply.inum = reply.inum;
                rc = UDP_Write(sd, &addr, (char*)&reply, sizeof(message_t));
                #ifdef DEBUG
                printf("\nserver:: reply message.\n");
                display_msg(&reply, message.nbytes);
                #endif
                break;

            case Write:
                reply.rt = ufs_write(message.inum, (char*)message.buffer, message.nbytes, message.offset);
                reply.func = message.func;
                reply.inum = message.inum;
                reply.nbytes = message.nbytes;
                reply.offset = message.offset;
                rc = ufs_read(reply.inum, reply.buffer, reply.nbytes, reply.offset);
                rc = UDP_Write(sd, &addr, (char*)&reply, sizeof(message_t));
                #ifdef DEBUG
                printf("\nserver:: reply message.\n");
                display_msg(&reply, 0);
                #endif
                break;
            
            case Read:
                reply.rt = ufs_read(message.inum, (char*)reply.buffer, message.nbytes, message.offset);
                reply.func = message.func;
                reply.inum = message.inum;
                reply.nbytes = message.nbytes;
                reply.offset = message.offset;
                rc = UDP_Write(sd, &addr, (char*)&reply, sizeof(message_t));
                #ifdef DEBUG
                printf("\nserver:: reply message.\n");
                display_msg(&reply, message.nbytes);
                #endif
                break;

            case Creat:
                reply.rt = ufs_creat(message.pinum, message.type, message.name);
                reply.func = message.func;
                reply.pinum = message.pinum;
                reply.type = message.type;
                memcpy(reply.name, message.name, 28);
                rc = UDP_Write(sd, &addr, (char*)&reply, sizeof(message_t));
                #ifdef DEBUG
                printf("\nserver:: reply message.\n");
                display_msg(&reply, message.nbytes);
                #endif
                break;
            
            case Unlink:
                reply.rt = ufs_unlink(message.pinum, message.name);
                reply.func = message.func;
                reply.pinum = message.pinum;
                memcpy(reply.name, message.name, 28);
                rc = ufs_stat(reply.pinum, &reply.stat);
                rc = ufs_read(reply.pinum, reply.buffer, (reply.stat.size < UFS_BLOCK_SIZE)?reply.stat.size : UFS_BLOCK_SIZE, 0);
                rc = UDP_Write(sd, &addr, (char*)&reply, sizeof(message_t));
                #ifdef DEBUG
                printf("\nserver:: reply message.\n");
                display_msg(&reply,message.nbytes);
                #endif
                break;
            
            case Shutdown:
                reply.rt = ufs_shutdown();
                reply.func = message.func;
                rc = UDP_Write(sd, &addr, (char*)&reply, sizeof(message_t));
                #ifdef DEBUG
                printf("\nserver:: reply message.\n");
                display_msg(&reply, message.nbytes);
                #endif
                (void) close(sd);
                exit(0);

                break;
            default:
                break;
        }
    }
    (void) close(fd_img);
    return 0;
}

int ufs_lookup(int parent_inum, char *name) {
    //check length of name
    if(strlen(name)>28-1) {
        printf("(ufs_lookup) length of name is larger than 28!");
        return -1;
    }
        
    //check parent_inum
    if(parent_inum < 0 || parent_inum >= super.num_inodes || get_bit((inode_bitmap_ptr + parent_inum/bits_per_block)->bits, parent_inum % bits_per_block) == 0) {
        printf("(ufs_lookup) parent_inum is invalid");
        return -1;
    }

    // address inode region block and index
    inode_block* parent_inode_block = inode_table_ptr + (parent_inum/inodes_per_blocks);
    int index = parent_inum % inodes_per_blocks;

    // check if type of parent inode is directory
    if(parent_inode_block->inodes[index].type != UFS_DIRECTORY) {
        printf("(ufs_lookup) parent is not a directory");
        return -1; 
    }
    
    // check if there is a file with the given name under the directory
    int rc;
    int block_addr;
    dir_block_t dir_block;
    for(int i = 0; i < 30; i++){
        block_addr = parent_inode_block->inodes[index].direct[i];
        if(block_addr == -1)
            continue;
        rc = get_dir_block(block_addr, &dir_block);
        if(rc != 0)
            continue;
        for(int j = 0; j < 128; j++){
            if(dir_block.entries[j].inum != -1 && !strcmp(name, dir_block.entries[j].name)) 
                return dir_block.entries[j].inum;
        }
    }
    return -1;
}

int ufs_stat(int inum, stat_t* stat) {
    // check parent_inum
    if(inum < 0 || inum >= super.num_inodes || get_bit((inode_bitmap_ptr + inum/bits_per_block)->bits, inum % bits_per_block) == 0) {
        return -1;
    }

    // address inode region block and index
    inode_t target_inode = inode_table_ptr->inodes[inum];

    stat->type = target_inode.type;
    stat->size = target_inode.size;
    return 0;
}

int ufs_creat(int parent_inum, int type, char *name) {
    int rc;
    // check if parent_inum exists
    if(parent_inum < 0 || parent_inum >= super.num_inodes || get_bit((inode_bitmap_ptr + parent_inum/bits_per_block)->bits, parent_inum % bits_per_block) == 0) 
        return -1;

    // address partent_inode
    inode_t *parent_inode = &(inode_table_ptr->inodes[parent_inum]);

    //check if parent inode is directory
    if(parent_inode->type != UFS_DIRECTORY)
        return -1; 

    //check length of name
    if(strlen(name)>28-1) 
        return -1;

    // find a empty entry for new file and check if the name was exist (if so return 0)
    dir_block_t dir_block;
    int dir_block_addr;
    int index_dir_ent = -1;
    int index_direct = -1;
    for(int i = 0; i < 30; i++){
        dir_block_addr = parent_inode->direct[i];
        if(dir_block_addr == -1){
            // if all assigened direct blocks of parent ara full
            if (index_dir_ent == -1 && index_direct == -1){
            int dnum = find_empty_data_bit();
            if(dnum == -1) {
                printf("(ufs_create) There is no empty data bit for new dir_block");
                return -1;
            }

            // update data bitmap in memory
            rc = set_data_bit(dnum);
            if(rc < 0)
                return -1;
  
            // update parent inode direct[] in memory
            parent_inode->direct[i] = super.data_region_addr + dnum;
            index_direct = i;
            index_dir_ent = 0;
            }
            break;
        }

        rc = get_dir_block(dir_block_addr, &dir_block);
        if(rc != 0)
            continue;
        for(int j = 0; j < 128; j++){
            if(dir_block.entries[j].inum == -1 && index_dir_ent == -1 && index_direct == -1) {
                index_direct = i;
                index_dir_ent = j;
            } 
            if(dir_block.entries[j].inum != -1 && !strcmp(name, dir_block.entries[j].name)) 
                return 0;
        }
    }

    // name doesn't exist
    // there is no empty direct entry in parent directory for new file 
    if(index_dir_ent == -1 || index_direct == -1) {
        printf("(ufs_create)index_dir_ent == -1 || index_direct == -1 (all direct is full)");
        return -1;
    }
    
    // check if there is a empty inode bit for new file
    int created_inum = find_empty_inode_bit();
    if(created_inum < 0) return -1;
    // check if there is a empty data bit for new file
    int created_dnum = find_empty_data_bit();
    if(created_dnum < 0) return -1;

    // update inode bitmap in memory
    rc = set_inode_bit(created_inum);
    if(rc == -1) return -1;
    // update data bitmap in memory
    rc = set_data_bit(created_dnum);
    if(rc == -1) return -1;

    if(type == UFS_DIRECTORY) {
        // initialize new inode 
        inode_t inode;
        inode.type = type;
        inode.size = 2 * sizeof(dir_ent_t);
        inode.direct[0] = super.data_region_addr + created_dnum;
        for(int i = 1; i < 30; i++)
            inode.direct[i] = -1;
        // update inode block in memory
        inode_t *target_inode = (inode_t *)inode_table_ptr + created_inum;
        *target_inode = inode;

        
        // initialize new data block
        dir_block_t new_dir_block;
        strcpy(new_dir_block.entries[0].name, ".");
        new_dir_block.entries[0].inum = created_inum;
        strcpy(new_dir_block.entries[1].name, "..");
        new_dir_block.entries[1].inum = parent_inum;
        for(int i = 2; i < 128; i++)
	        new_dir_block.entries[i].inum = -1;
        // update data block in img file
        rc = pwrite(fd_img, &new_dir_block, UFS_BLOCK_SIZE, (super.data_region_addr + created_dnum) * UFS_BLOCK_SIZE);
        if(rc < 0){
            perror("(ufs_creat)failed to write initialized data block into img file");
            return -1;
        }
    }
    // if type is UFS_REGULAR_FILE
    else {
        // initialize new inode 
        inode_t inode;
        inode.type = type;
        inode.size = 0;
        inode.direct[0] = super.data_region_addr + created_dnum;
        for(int i = 1; i < 30; i++)
            inode.direct[i] = -1;
        // update inode block in memory
        inode_t *target_inode = (inode_t *)inode_table_ptr + created_inum;
        *target_inode = inode;
        // update inode block in img file
        rc = pwrite(fd_img, &inode, sizeof(inode_t), super.inode_region_addr * UFS_BLOCK_SIZE + created_inum * sizeof(inode_t));
        if(rc < 0){
            perror("(ufs_creat)failed to write initialized inode into img file");
            return -1;
        }

        // initialize new data block
        unsigned char *empty_buffer;
        empty_buffer = calloc(UFS_BLOCK_SIZE, 1);
        // update data block in img file
        rc = pwrite(fd_img, empty_buffer, UFS_BLOCK_SIZE, (super.data_region_addr + created_dnum) * UFS_BLOCK_SIZE);
        if(rc < 0){
            perror("(ufs_creat)failed to write initialized data block into img file");
            return -1;
        }
    }

    // update parent inode's size in memory
    if(index_direct*UFS_BLOCK_SIZE + index_dir_ent*sizeof(dir_ent_t) == parent_inode->size)
        parent_inode->size += sizeof(dir_ent_t);

    // update parent inode's direntry entry to file
    dir_block_addr = parent_inode->direct[index_direct];
    rc = get_dir_block(dir_block_addr, &dir_block);
    if(rc < 0){
        perror("(ufs_creat)failed to get_dir_block for updating parents' directory block");
        return -1;
    }
    dir_block.entries[index_dir_ent].inum = created_inum;
    strcpy(dir_block.entries[index_dir_ent].name, name);
    rc = pwrite(fd_img, &dir_block, UFS_BLOCK_SIZE, dir_block_addr * UFS_BLOCK_SIZE);
    if(rc < 0){
        perror("(ufs_creat)failed to write parent's directory block into img file");
        return -1;
    }


    // update meta blocks into img file
    rc = pwrite(fd_img, super_ptr, UFS_BLOCK_SIZE * super.data_region_addr, 0);
    if(rc < 0){
        perror("(ufs_creat)failed to write meta blocks into img file");
        return -1;
    }
    (void) fsync(fd_img);
    return 0;
}

int ufs_unlink(int parent_inum, char *name) {
    // check name
    if(!strcmp(name, ".") || !strcmp(name, "..")) {
        perror("can not unlink . or ..");
        return -1;
    }

    // check length of name
    if(strlen(name)>28-1) {
        printf("(ufs_unlink) length of name is larger than 28!");
        return -1;
    }

    // check parent_inum
    if(parent_inum < 0 || parent_inum >= super.num_inodes || get_bit((inode_bitmap_ptr + parent_inum/bits_per_block)->bits, parent_inum % bits_per_block) == 0) {
        perror("(ufs_unlink) parent_inum is invalid");
        return -1;
    }

    // address parent inode region block and index
    inode_block* parent_inode_block = inode_table_ptr + (parent_inum/inodes_per_blocks);
    int index = parent_inum % inodes_per_blocks;

    // check if type of parent inode is directory
    if(parent_inode_block->inodes[index].type != UFS_DIRECTORY) {
        perror("(ufs_unlink) parent is not a directory");
        return -1; 
    }

    
    // check if there is a file with the given name under the  parent directory
    int index_direct  = -1, index_dir_ent = -1;
    int rc;
    int dir_block_addr;
    dir_block_t dir_block;
    for(int i = 0; i < 30; i++){
        dir_block_addr = parent_inode_block->inodes[index].direct[i];
        if(dir_block_addr == -1)
            continue;
        rc = get_dir_block(dir_block_addr, &dir_block);
        if(rc != 0)
            continue;
        for(int j = 0; j < 128; j++){
            if(dir_block.entries[j].inum != -1 && !strcmp(name, dir_block.entries[j].name)) {
                index_direct = i;
                index_dir_ent = j;
                break;
            }  
        }
        if(index_dir_ent != -1 && index_direct != -1)
            break;
    }

    if(index_dir_ent == -1 || index_direct == -1)
        return 0;

    // check if unlink target is a empty direct
    int unlink_inum = dir_block.entries[index_dir_ent].inum;
    if(isEmptyDir(unlink_inum) == -1)
        return -1;

    // update parent inode's direntry entry
    dir_block_addr = parent_inode_block->inodes[index].direct[index_direct];
    rc = get_dir_block(dir_block_addr, &dir_block);
    if(rc < 0){
        perror("(ufs_unlink)failed to get_dir_block for updating parents' directory block");
        return -1;
    }
    dir_block.entries[index_dir_ent].inum = -1;
    rc = pwrite(fd_img, &dir_block, UFS_BLOCK_SIZE, dir_block_addr * UFS_BLOCK_SIZE);
    if(rc < 0){
        perror("(ufs_unlink)failed to write parent's directory block into img file");
        return -1;
    }

    (void) fsync(fd_img);
    return 0;
}

int ufs_write(int inum, char* buffer, int nbytes, int offset) {
    int rc;
    // get inum inode
    inode_t *target_inode = (inode_t *)inode_table_ptr + inum; 

    // CHECK ARGS
    // check inum
    if(inum < 0 || inum >= super.num_inodes || get_bit((inode_bitmap_ptr + inum/bits_per_block)->bits, inum % bits_per_block) == 0) {
        perror("(ufs_write)Wrong inum");
        return -1;
    }
    // check offset
    if(offset < 0 || offset > target_inode->size) {
        perror("(ufs_write) invalid offset");
        return -1;
    }
    // check bytes
    if(nbytes < 0 || nbytes > UFS_BLOCK_SIZE) {
        perror("(ufs_write) Wrong nbytes");
        return -1;
    }
    // check size after writing
    if(offset + nbytes > 30 * UFS_BLOCK_SIZE) {
        return -1;
    }
    // if inum type is directory, offset and nbytes should align with size of dir_ent_t
    if(target_inode->type == UFS_DIRECTORY) {
        if(offset % sizeof(dir_ent_t) != 0 || nbytes % sizeof(dir_ent_t) != 0) {
            perror("(ufs_write) nbytes or offset does note align wit size of dir_ent_t(32)");
            return -1;
        }
    }
    
    // GET START POSITION
    int start_direct_index = offset / UFS_BLOCK_SIZE;
    int start_block_addr = target_inode->direct[start_direct_index];
    int start_byte_index = offset % UFS_BLOCK_SIZE;

    // Write
    if(start_block_addr == -1) {
        int dnum = find_empty_data_bit();
        if(dnum == -1) {
            perror("(ufs_write) There is no empty data bit");
            return -1;
        }
        // update data bitmap in memory
        rc = set_data_bit(dnum);

        // update inode direct in memory
        start_block_addr = super.data_region_addr + dnum;
        target_inode->direct[start_direct_index] = start_block_addr;
    }

    dir_block_t *dest_block = (dir_block_t* )super_ptr + start_block_addr;
    char* curr_dest_ptr = (char *)dest_block + start_byte_index;
    char* curr_src_ptr = buffer;
    
    if(start_byte_index + nbytes <= UFS_BLOCK_SIZE) {
        // write zone just within first block
        memcpy(curr_dest_ptr, curr_src_ptr, nbytes);
    }
    else {
        // write zone spans two blocks
        memcpy(curr_dest_ptr, curr_src_ptr, UFS_BLOCK_SIZE - start_byte_index);       
        int next_block_addr = target_inode->direct[(start_direct_index + 1) % 30];
        // need to apply for a new data block 
        if(next_block_addr == -1) {
            int dnum = find_empty_data_bit();
            if(dnum == -1) {
                perror("(ufs_write) There is no empty data bit");
                return -1;
            }
            next_block_addr = super.data_region_addr + dnum;
            // update data bitmap in memory
            rc = set_data_bit(dnum);
            // update inode direct in memory
            target_inode->direct[(start_direct_index + 1) % 30] = next_block_addr;           
        }

        curr_dest_ptr = (char *)(dest_block + 1);
        curr_src_ptr += UFS_BLOCK_SIZE - start_byte_index;
        nbytes -= UFS_BLOCK_SIZE - start_byte_index;
        memcpy(curr_dest_ptr, curr_src_ptr, nbytes);
    }

    // update the size of inode
    target_inode->size = (offset+nbytes > target_inode->size)? (offset + nbytes) : target_inode->size;

    rc = pwrite(fd_img, super_ptr, total_blocks * UFS_BLOCK_SIZE, 0);
    if(rc < 0) {
        perror("(ufs_write) failed to update fs into file");
        return -1;
    } 

    (void) fsync(fd_img);
    return 0;
}

int ufs_read(int inum, char *buffer, int nbytes, int offset) {
    int rc;
    // get inum inode
    inode_t *target_inode = (inode_t *)inode_table_ptr + inum; 

    #ifdef REGION
    #pragma region check args
    #endif
    // check inum
    if(inum < 0 || inum >= super.num_inodes || get_bit((inode_bitmap_ptr + inum/bits_per_block)->bits, inum % bits_per_block) == 0) {
        perror("(ufs_read)Wrong inum");
        return -1;
    }
    // check offset
    if(offset < 0 || offset > target_inode->size) {
        perror("(ufs_read) invalid offset");
        return -1;
    }
    // check bytes
    if(nbytes < 0 || nbytes > UFS_BLOCK_SIZE || nbytes + offset > target_inode->size) {
        perror("(ufs_read) Wrong nbytes");
        return -1;
    }
    // if inum type is directory, offset and nbytes should align with size of dir_ent_t
    if(target_inode->type == UFS_DIRECTORY) {
        if(offset % sizeof(dir_ent_t) != 0 || nbytes % sizeof(dir_ent_t) != 0) {
            perror("(ufs_write) nbytes or offset does note align with size of dir_ent_t(32)");
            return -1;
        }
    }
    #ifdef REGION
    #pragma endregion
    #endif

    // GET START POSITION
    int start_direct_index = offset / UFS_BLOCK_SIZE;
    int start_block_addr = target_inode->direct[start_direct_index];
    int start_byte_index = offset % UFS_BLOCK_SIZE;

    // Read
    // get the start data block
    dir_block_t block_buffer;
    if(start_block_addr == -1) {
        return 0;
    }
    rc = pread(fd_img, &block_buffer, UFS_BLOCK_SIZE, start_block_addr * UFS_BLOCK_SIZE);
    if(rc != UFS_BLOCK_SIZE) {
        perror("(ufs_write) failed to read first data block");
        return -1;
    }
    char* curr_src_ptr = (char *)&block_buffer + start_byte_index;
    char* curr_dest_ptr = buffer;
    
    if(start_byte_index + nbytes <= UFS_BLOCK_SIZE) {
        // read zone just within first block
        memcpy(curr_dest_ptr, curr_src_ptr, nbytes);
    }
    else {
        // read zone spans two blocks
        memcpy(curr_dest_ptr, curr_src_ptr, UFS_BLOCK_SIZE - start_byte_index);    
        int next_block_addr = target_inode->direct[start_direct_index + 1];
        // need to apply for a new data block 
        if(next_block_addr == -1) {
            perror("(ufs_read) next_block_addr = -1");
            return -1;
        }
        rc = pread(fd_img, &block_buffer, UFS_BLOCK_SIZE, next_block_addr * UFS_BLOCK_SIZE);
        if(rc != UFS_BLOCK_SIZE) {
            perror("(ufs_write) failed to read first data block");
            return -1;
        }
        curr_src_ptr = (char *)&block_buffer;
        curr_dest_ptr += UFS_BLOCK_SIZE - start_byte_index;
        nbytes -= UFS_BLOCK_SIZE - start_byte_index;
        memcpy(curr_dest_ptr, curr_src_ptr, nbytes);
    }   
    return 0;
}

int ufs_shutdown() {
    (void) fsync(fd_img);
    (void) close(fd_img);
    return 0;
}

unsigned int get_bit(unsigned int *bitmap, int position) {
    int index = position / 32;
    int offset = 31 - (position % 32);
    return (bitmap[index] >> offset) & 0x1;
}

void set_bit(unsigned int *bitmap, int position) {
    int index = position / 32;
    int offset = 31 - (position % 32);
    bitmap[index] |= 0x1 << offset;
}


int get_dir_block(int block_addr, dir_block_t* dir_block) {
    // check block bounds and data bitmaps
    if(block_addr < super.data_region_addr || block_addr >= total_blocks || get_bit((data_bitmap_ptr + (block_addr-super.data_region_addr)/bits_per_block)->bits, (block_addr - super.data_region_addr)%bits_per_block) == 0) 
        return -1;
    
    int rc = pread(fd_img, dir_block, sizeof(dir_block_t), block_addr*UFS_BLOCK_SIZE);
    if(rc < 0) return -1;
    return 0;
}

int find_empty_data_bit() {
    int dnum = -1;
    int visited_data_bits = 0;
    bitmap_t *cur_data_bitmap;
    for(int i = 0; i < super.data_bitmap_len; i++) {
        cur_data_bitmap = data_bitmap_ptr + i;
        for(int j = 0; j < bits_per_block && visited_data_bits <= super.num_data; j++) {
            visited_data_bits++;
            if(get_bit((unsigned int*)cur_data_bitmap, j) == 0){
                dnum = visited_data_bits - 1;
                break;
            }
        }
        if(dnum != -1)
            break;
    }
    return dnum;
}


int find_empty_inode_bit() {
    int inum = -1;
    int visited_inode_bits = 0;
    bitmap_t *cur_inode_bitmap;
    for(int i = 0; i < super.inode_bitmap_len; i++) {
        cur_inode_bitmap = inode_bitmap_ptr + i;
        for(int j = 0; j < bits_per_block; j++) {
        // for(int j = 0; j < bits_per_block && visited_inode_bits <= super.num_inodes; j++) {
            visited_inode_bits++;
            if(get_bit((unsigned int*)cur_inode_bitmap, j) == 0){
                inum = visited_inode_bits - 1;
                break;
            }
        }
        if(inum != -1)
            break;
    }
    return inum;
}

int set_inode_bit(int inum) {
    // check inum
    // if(inum < 0 || inum >= super.num_inodes)
    if(inum < 0)
        return -1;
    
    bitmap_t *target_inode_bitmap = inode_bitmap_ptr + (inum / bits_per_block);
    int positon = inum % bits_per_block;

    set_bit((unsigned int *)target_inode_bitmap, positon);
    return 0;
}

int set_data_bit(int dnum) {
    // check dnum
    if(dnum < 0 || dnum >= super.num_data)
        return -1;
    
    bitmap_t *target_data_bitmap = data_bitmap_ptr + (dnum / bits_per_block);
    int positon = dnum % bits_per_block;

    set_bit((unsigned int *)target_data_bitmap, positon);
    return 0;
}


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

void display_msg(message_t* msg, int nbytes) {
    printf("function_type=%d\t", msg->func);
    printf("pinum=%d\t", msg->pinum);
    printf("inum=%d\n", msg->inum);
    printf("offset=%d\t", msg->offset);
    printf("nbyte=%d\t", msg->nbytes);
    printf("type=%d\n",msg->type);
    printf("stat.type=%d\tstat.size=%d\n", msg->stat.type, msg->stat.size);
    printf("rt=%d\n", msg->rt);
    printf("name=%s\n", msg->name);
    printf("buffer=\n");  display_mem(msg->buffer, nbytes, 100);    
    return;        
}

int isEmptyDir(int inum) {
    // check if target file is a directory
    stat_t stat;
    int rt = ufs_stat(inum, &stat);
    if(stat.type != UFS_DIRECTORY) return 0;

    // check if all entries'inum in this directory is -1
    inode_t unlink_inode = inode_table_ptr->inodes[inum];
    dir_block_t curr_dir_block;
    for(int i = 0; i < 30; i++) {
        if(unlink_inode.direct[i] != -1) {
            rt = get_dir_block(unlink_inode.direct[i], &curr_dir_block);
            for(int j = 0; j < 128; j++) {
                if(curr_dir_block.entries[j].inum != -1 && 
                    strcmp(curr_dir_block.entries[j].name, ".") != 0 &&
                    strcmp(curr_dir_block.entries[j].name, "..") != 0) 
                    return -1;
            }
        }
    }

    return 0;
}

void intHandler(int dummy) {
    (void) fsync(fd_img);
    (void) close(fd_img);
    UDP_Close(sd);
    exit(130);
}
