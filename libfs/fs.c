#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <sys/stat.h> 
#include <fcntl.h>
#include <unistd.h>

#include "disk.h"
#include "fs.h"

#define VALID_SIG	"ECS150FS"
#define SIGLEN          8
#define BLOCK_SIZE	4096
#define FAT_START	1
#define SPBLK_IDX       0
#define FAT_EOC         0xffff

#ifndef RETVALS
#define RETVALS
#define RET_SUCCESS 0
#define RET_FAILURE -1
#endif

typedef struct super_blk*	sb_t;
typedef uint16_t*		fat_t;
typedef struct dir*	 	dir_t;
typedef struct fd*		fd_t;

struct __attribute__((__packed__)) super_blk 
{
	uint8_t		signature[8];
	uint16_t 	total_blocks;
	uint16_t 	root_dir_idx;
	uint16_t 	data_block_idx;
	uint16_t	total_data_blocks;
	uint8_t		fat_blocks;  
	uint8_t		padding[4079]; //block size minus everything else to generalize this
};

struct __attribute__((__packed__)) dir 
{
	uint8_t		file_name[16];
	uint32_t 	file_size;
	uint16_t	data_block_idx;
	uint8_t		padding[10];
};

struct __attribute__((__packed__)) fd 
{
	dir_t file;
	size_t offset;
};

struct __attribute__((__packed__)) block
{
	uint8_t bytes[BLOCK_SIZE];
};

sb_t super_blk;
fat_t fat;
dir_t root_dir;

fd_t fd_table[FS_OPEN_MAX_COUNT];
uint8_t fd_keys[FS_OPEN_MAX_COUNT];

int mounted = 0;
int open_files = 0;
int free_entries = 0;
int fat_size = 0;

int get_rdir_free_num(void)
{
        int i;
        int res = 0;
        for (i = 0; i < FS_FILE_MAX_COUNT; i++)
                if (root_dir[i].file_name[0] == '\0')
                        res++;

        return res;
}

int get_fat_free_num(void)
{
        int i;
        int res = 0;
        for (i = 0; i < super_blk->total_data_blocks; i++)
                if (fat[i] == 0)
                        res++;

        return res;
}

/* Validate the given string filename
 * returns RET_FAILURE on failure
 * returns length of filename on success
 * string func is an error-printing parameter
 * */
int validate_filename(const char *filename)
{
	int size = 0;

	if (mounted == 0)
                return RET_FAILURE;
        if (filename == NULL)
                return RET_FAILURE;
        while (filename[size++] != '\0' && size < FS_FILENAME_LEN);
        if (size > FS_FILENAME_LEN)
                return RET_FAILURE;
        if (filename[size-1] != '\0')
                return RET_FAILURE;

	return size;
}

/* Validate the given file descriptor
 * returns RET_FAILURE on failure
 * returns RET_SUCCESS on success 
 * */
int validate_descriptor(const int fd)
{
	/* check for mounted FS */
        if (mounted == 0)
                return RET_FAILURE;
        /* Check for a valid fd */
        if (fd > FS_OPEN_MAX_COUNT || fd < 0)
                return RET_FAILURE;
        /* check if file exists */
        if (fd_keys[fd] == 0)
                return RET_FAILURE;

	return RET_SUCCESS;
}

/* returns RET_FAILURE if all fat indices are taken;
 * returns the index of the lowest available fat
 * entry otherwise.
 * */
int get_free_fat_idx(void)
{
	int idx = 1;
	while (fat[idx] != 0 && idx < super_blk->total_data_blocks-1) idx++;
	if (fat[idx] != 0)
		return RET_FAILURE;
	fat[idx] = FAT_EOC;
	return idx;
}

int fs_mount(const char *diskname)
{
	/* In the future, let's break this function
	 * into three sections in which we initialize
	 * all of our globals individually
	 * */

	/* check whether diskname is valid fs */
	if (diskname == NULL )
		return RET_FAILURE;
	if (block_disk_open(diskname))
		return RET_FAILURE;
	/* all following failure catches should close the disk */

	/* load the superblock */
	super_blk = malloc(sizeof(struct super_blk));
	root_dir = malloc(sizeof(struct dir) * FS_FILE_MAX_COUNT);
	if (super_blk == NULL || root_dir == NULL)
		return RET_FAILURE;

	/* validate super block */
	char buf[9];
	block_read(SPBLK_IDX, super_blk);
	memcpy(buf, super_blk->signature, SIGLEN);
	buf[8] = '\0';
	if (strcmp(buf, VALID_SIG))
		return RET_FAILURE;
	if (super_blk->total_blocks != block_disk_count())
		return RET_FAILURE;

	/* load root dir */
	block_read(super_blk->root_dir_idx, root_dir); // this bit was corrupting the heap
	free_entries = get_rdir_free_num();

	/* load the FAT */
	int i;
	int block_idx = 0;
	fat_size = super_blk->fat_blocks * BLOCK_SIZE;
	fat = malloc(sizeof(uint16_t) * fat_size);
	uint16_t data_blk[BLOCK_SIZE/2];
	if (fat == NULL)
		return RET_FAILURE;
	for (i = FAT_START; i <= super_blk->fat_blocks; i++) {
		block_read(i, data_blk);
		memcpy(fat + block_idx, data_blk, BLOCK_SIZE);
		block_idx += BLOCK_SIZE;
	}

	/* initialize fd_keys*/
	for (i = 0; i < FS_OPEN_MAX_COUNT; i++)
		fd_keys[i] = 0;

	mounted = 1;
	return RET_SUCCESS;
}

int fs_umount(void)
{
	/* 
	 * makes sure that the virtual disk is
	 * properly closed and that all the internal
	 * data structures of the FS layer are properly
	 * cleaned.
	 */

	if (open_files > 0 || block_disk_count() == RET_FAILURE)
		return RET_FAILURE;
	
	block_write(super_blk->root_dir_idx, root_dir);
	block_write(0, super_blk);
	
	int i;
	int offset = 0;
	for (i = FAT_START; i <= super_blk->fat_blocks; i++) {
		block_write(i, fat + offset*BLOCK_SIZE);
		offset++;
	}

	if (block_disk_close() == RET_FAILURE)
		return RET_FAILURE;

	free(root_dir);
	free(fat);
	free(super_blk);

	mounted = 0;

	return RET_SUCCESS;
}

int fs_info(void)
{	
	if (mounted == 0 || block_disk_count() == -1) // we should have a disk before printing info
		return RET_FAILURE;

	printf("FS Info:\n");
	printf("total_blk_count=%d\n", super_blk->total_blocks);
	printf("fat_blk_count=%d\n", super_blk->fat_blocks);
	printf("rdir_blk=%d\n", super_blk->root_dir_idx);
	printf("data_blk=%d\n", super_blk->data_block_idx);
	printf("data_blk_count=%d\n", super_blk->total_data_blocks);
	printf("fat_free_ratio=%d/%d\n", get_fat_free_num(), super_blk->total_data_blocks);
	printf("rdir_free_ratio=%d/%d\n", free_entries, FS_FILE_MAX_COUNT);

	return RET_SUCCESS;
}

int fs_create(const char *filename)
{
	/* variable declarations */
	int i = 0;
	int j = 0;
	int loe = -1; /* lowest open entry */
	int size = 0;
	int unique = 1;

	/* error catching */
	if ((size = validate_filename(filename)) == RET_FAILURE)
		return RET_FAILURE;
	if (free_entries <= 0)
		return RET_FAILURE;
	while ((unique = strcmp((char*)root_dir[j++].file_name, filename)) && j < FS_FILE_MAX_COUNT);
	if (!unique)
		return RET_FAILURE;

	/* find loe */
	while (root_dir[loe=i++].file_name[0] != '\0');
	/* create file */
	memcpy(root_dir[loe].file_name, filename, size);
	root_dir[loe].file_size = 0;
	root_dir[loe].data_block_idx = FAT_EOC;
	free_entries--;

	return RET_SUCCESS;
}

int fs_delete(const char *filename)
{
	/* variable declarations */
        int i = 0;
	int j = 0;
        int idx = -1; /* location of target */
        int unique = 1;

        /* error catching */
        if (validate_filename(filename) == RET_FAILURE)
                return RET_FAILURE;
	/* verify file exists and get idx */
        while ((unique = strcmp((char*)root_dir[idx=j++].file_name, filename)) && j < FS_FILE_MAX_COUNT);
        if (unique)
                return RET_FAILURE;
	/* check if file is open elsewhere */
	for (i = 0; i < FS_OPEN_MAX_COUNT; i++) {
		if (fd_keys[i] == 1)
			if (!strcmp((char*)fd_table[i]->file->file_name, filename))
				return RET_FAILURE;
	}
        /* delete file */
        memcpy(root_dir[idx].file_name, "", 1);
        i = root_dir[idx].data_block_idx;
	while (i != FAT_EOC) {
		j = fat[i];
		fat[i] = 0;
		i = j;
	}
	root_dir[idx].data_block_idx = 0;
        free_entries++;

        return RET_SUCCESS;
}

int fs_ls(void)
{
	if (mounted == 0)
		return RET_FAILURE;

	int i;
	fprintf(stdout, "FS Ls:\n");
	for (i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root_dir[i].file_name[0] != '\0') {
			char *efn = (char*)root_dir[i].file_name;
			int efs = root_dir[i].file_size;
			int idx = root_dir[i].data_block_idx;
			fprintf(stdout, "file: %s, size: %d, data_blk: %d\n", efn, efs, idx);
		}
	}

	return RET_SUCCESS;
}

int fs_open(const char *filename)
{	
	/* variable declarations */
	int fd_idx = -1;
	int file_idx = 0;
	int j = 0;
	int unique = 0;

	/* check if filename is valid */
	if (validate_filename(filename) == RET_FAILURE)
		return RET_FAILURE;
	/* check if too many files */
	if (open_files >= FS_OPEN_MAX_COUNT)
		return RET_FAILURE;
	/* check if file exists */
	while ((unique = strcmp((char*)root_dir[j++].file_name, filename)) && j < FS_FILE_MAX_COUNT);
        if (unique)
                return RET_FAILURE;
	/* find file to open */
        for (file_idx = 0; file_idx < FS_FILE_MAX_COUNT; file_idx++) {
		if (root_dir[file_idx].file_name[0] != '\0' && strcmp((char*)root_dir[file_idx].file_name, filename) == 0) {
			/* open file */
			fd_t open_file = malloc(sizeof(struct fd));
			open_file->file = &root_dir[file_idx];
			open_file->offset = 0;
			open_files++;

			/* add file to fd_table */
			for (fd_idx = 0; fd_idx < FS_OPEN_MAX_COUNT; fd_idx++) {
				if (fd_keys[fd_idx] == 0) {
					fd_keys[fd_idx] = 1;
					fd_table[fd_idx] = open_file;
					break;
				} 
			}
			break;
		}
	}
	return fd_idx;
}

int fs_close(int fd)
{
	if (validate_descriptor(fd) == RET_FAILURE)
		return RET_FAILURE;

	fd_keys[fd] = 0;
	free(fd_table[fd]);
        open_files--;

	return RET_SUCCESS;
}

int fs_stat(int fd)
{
	if (validate_descriptor(fd) == RET_FAILURE)
		return RET_FAILURE;

	return fd_table[fd]->file->file_size;
}

int fs_lseek(int fd, size_t offset)
{
	if (validate_descriptor(fd) == RET_FAILURE)
		return RET_FAILURE;
	if (fd_table[fd]->file->file_size < offset)
		return RET_FAILURE;
	
	fd_table[fd]->offset = offset;

	return RET_SUCCESS;
}

/* two cases:
 * 1) File already has a fat entry
 * 2) File does not have a fat entry
 * */
int fs_write(int fd, void *buf, size_t count)
{
	/* error catching */
	if (validate_descriptor(fd) == RET_FAILURE)
		return RET_FAILURE;
	if (buf == NULL)
		return RET_FAILURE;
	if (count == 0)
		return 0;

	/* variable initialization */
	dir_t file = fd_table[fd]->file;
	size_t offset = fd_table[fd]->offset;
	size_t num_blocks_reqd = (count+offset) / BLOCK_SIZE + 1; //change for read as well
	size_t old_offset = offset;
	int blk_offset = super_blk->data_block_idx;
	int size_written = 0; /* num bytes written */
	int target_block = -1; /* first data block to which we write*/
	int nav = 0; /* num jumps to make while navigating fat */

	/* get a fat entry if we don't have one */
	if (file->data_block_idx == FAT_EOC) {
		int retval = get_free_fat_idx();
		if (retval == RET_FAILURE)
			return size_written;
		file->data_block_idx = retval;
	}

	/* set the target block - offset MUST be valid at this point */
	nav = offset / BLOCK_SIZE;
	target_block = file->data_block_idx;
	while (nav-- > 0)
		target_block = fat[target_block];
	//target_block += blk_offset;

	/* okay, so now we're writing to block "target_block"... 
	 * but how much space will this take? and do we have enough? */
	size_t i;
	int *block_idx = malloc(sizeof(int)*(num_blocks_reqd+1));
	struct block **blocks = malloc(sizeof(struct block*)*num_blocks_reqd);
	for (i = 0; i < num_blocks_reqd+1; i++) block_idx[i] = -1;
	for (i = 0; i < num_blocks_reqd; i++) {
		blocks[i] = malloc(sizeof(struct block));
		block_read(target_block+blk_offset, (void*)blocks[i]);
		block_idx[i] = target_block+blk_offset;
		/* file needs more space? */
		if (fat[target_block] == FAT_EOC && num_blocks_reqd > 1 && i < num_blocks_reqd-1) {
			int new = get_free_fat_idx();
			if (new == RET_FAILURE) {
				/* FS is full */
				break;
			}
			fat[target_block] = new;
		}
		target_block = fat[target_block];
	}

	/* now we do the actual writing... */
	int off_r;
	if (offset >= BLOCK_SIZE)
		off_r = offset % BLOCK_SIZE;
	else
		off_r = offset;
	i = 0;
	while (block_idx[i] != -1) {
		while (off_r != BLOCK_SIZE && size_written < (int)count) {
			blocks[i]->bytes[off_r++] = ((struct block*)buf)->bytes[size_written++];
			offset++;
		}
		block_write(block_idx[i], (void*)blocks[i]);
		off_r = 0;
		i++;
	}
	free(block_idx);
	for (i = 0; i < num_blocks_reqd; i++)
		free(blocks[i]);
	free(blocks);

	/* update the file size */
	int new = size_written + old_offset - file->file_size;
	if (new > 0)
		file->file_size = file->file_size + new;
	fd_table[fd]->offset = offset;

	return size_written;
}

int fs_read(int fd, void *buf, size_t count)
{
	/* error catching */
	if (validate_descriptor(fd) == RET_FAILURE)
		return RET_FAILURE;
	if ((int)count < 0)
		return RET_FAILURE;
	if (buf == NULL)
		return RET_FAILURE;

	/* variable initialization */
	dir_t file = fd_table[fd]->file;
	int offset = fd_table[fd]->offset;
	int blk_offset = super_blk->data_block_idx;
	int target_block = -1;		/* first data block to read*/
	int nav = 0;		/* num jumps to make while navigating fat */
	int bbuf_offset = 0;
				
	if (file == NULL)
		return RET_FAILURE;

	if (file->file_size - offset < count)
		count = file->file_size - offset;

	int blk_read_offset;
	void *bbuf = (void*) malloc(BLOCK_SIZE);

	while(count > 0) {
		/* check if we reach EOF */
		if(offset >= (int) file->file_size)
			break;

		/* determine which block to start reading from */
		nav = offset / BLOCK_SIZE;
		target_block = file->data_block_idx;
		while (nav-- > 0)
			target_block = fat[target_block];

		/* read bytes into circular buffer */
		block_read(target_block + blk_offset, bbuf);
		blk_read_offset = offset % BLOCK_SIZE;

		/* determine if we actually need a circular buffer at this point */
		if(count + blk_read_offset < BLOCK_SIZE) { 
			memcpy(buf + bbuf_offset, bbuf + blk_read_offset, count);
			offset += count;
			bbuf_offset += count;
			break;
		}
		/* if we are not reading from start of blk */
		else if (blk_read_offset > 0) {
			memcpy(buf + bbuf_offset, bbuf + blk_read_offset, BLOCK_SIZE - blk_read_offset);
			bbuf_offset += BLOCK_SIZE - blk_read_offset;
			offset += BLOCK_SIZE - blk_read_offset;
			count -= BLOCK_SIZE - blk_read_offset;
		} else {
			/* copy entire blk into bbuf */
			memcpy(buf + bbuf_offset, bbuf, BLOCK_SIZE);
			bbuf_offset += BLOCK_SIZE;
			offset += BLOCK_SIZE;
			count -= BLOCK_SIZE;
		}
	}
	fd_table[fd]->offset = offset;
	free(bbuf);
	return bbuf_offset;
}
