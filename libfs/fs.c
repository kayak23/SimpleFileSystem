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
#define RDIR_ENTRIES 	128
#define BLOCK_SIZE	4096
#define FAT_START	1
#define SPBLK_IDX       0

#ifndef RETVALS
#define RETVALS
#define RET_SUCCESS 0
#define RET_FAILURE -1
#endif

typedef struct super_blk*	sb_t;
typedef uint16_t*		fat_t;
typedef struct dir*	 	dir_t;

struct __attribute__((__packed__)) super_blk 
{
	uint8_t		signature[8];
	uint16_t 	total_blocks;
	uint16_t 	root_dir_idx;
	uint16_t 	data_block_idx;
	uint16_t	total_data_blocks;
	uint8_t		fat_blocks;  
	uint8_t		padding[4079];
};

struct __attribute__((__packed__)) dir 
{
	uint8_t		file_name[16];
	uint32_t 	file_size;
	uint16_t	data_block_idx;
	uint8_t		padding[10];
};

sb_t super_blk;
fat_t fat;
dir_t root_dir;

int mounted = 0;
int open_files = 0;

int fs_mount(const char *diskname)
{
	/* check whether diskname is valid fs */
	if (diskname == NULL ) {
		fprintf(stderr, "[mnt] null diskname\n");
		return RET_FAILURE;
	}
	if (block_disk_open(diskname)) {
		fprintf(stderr, "[mnt] invalid diskname\n");
		return RET_FAILURE;
	} // all following failure catches should close the disk

	/* load the superblock */
	super_blk = malloc(sizeof(struct super_blk));
	root_dir = malloc(sizeof(struct dir) * FS_FILE_MAX_COUNT);
	//root_dir = (struct dir*) malloc(BLOCK_SIZE);
	if (super_blk == NULL || root_dir == NULL) {
		fprintf(stderr, "[mnt] malloc error\n");
		return RET_FAILURE;
	}

	/* validate super block */
	char buf[9];
	block_read(SPBLK_IDX, super_blk);
	memcpy(buf, super_blk->signature, SIGLEN);
	buf[8] = '\0';
	if (strcmp(buf, VALID_SIG)) {
		fprintf(stderr, "[mnt] invalid signature: %s\n", buf);
		return RET_FAILURE;
	}
	if (super_blk->total_blocks != block_disk_count()) {
		fprintf(stderr, "[mnt] invalid block count\n");
		return RET_FAILURE;
	}

	/* load root dir */
	block_read(super_blk->root_dir_idx, root_dir); // this bit was corrupting the heap

	/* load the FAT */
	int block_idx = 0;
	fat = malloc(sizeof(uint16_t) * super_blk->fat_blocks * BLOCK_SIZE);
	//uint16_t *data_blk = malloc(sizeof(uint16_t) * BLOCK_SIZE); //this was twice as large as it should have been
	uint16_t data_blk[BLOCK_SIZE/2];
	if (fat == NULL /*|| data_blk == NULL*/) {
		fprintf(stderr, "[mnt] malloc error\n");
		return RET_FAILURE;
	}
	for (int i = FAT_START; i <= super_blk->fat_blocks; i++) {
		block_read(i, data_blk);
		memcpy(fat + block_idx, data_blk, BLOCK_SIZE);
		block_idx += BLOCK_SIZE;
	}

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
	block_write(1, fat);
	block_write(2, fat + BLOCK_SIZE);

	if (block_disk_close() == RET_FAILURE)
		return RET_FAILURE;

	free(root_dir);
	free(fat);
	free(super_blk);

	mounted = 0;

	return RET_SUCCESS;
}

int get_rdir_free_num(void)
{	
	int res = 0;
	for (int i = 0; i < FS_FILE_MAX_COUNT; i++)
		if (root_dir[i].file_name[0] == '\0')
			res++;

	return res;
}

int get_fat_free_num(void)
{
	int res = 0;
	for (int i = 0; i < super_blk->total_data_blocks; i++)
		if (fat + i == 0)
			res++;
	return res;
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
	printf("fat_free_ratio=%d/%d\n", super_blk->total_data_blocks - get_fat_free_num(), super_blk->total_data_blocks);
	printf("rdir_free_ratio=%d/%d\n", get_rdir_free_num(), RDIR_ENTRIES);

	return RET_SUCCESS;
}

int fs_create(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_delete(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_ls(void)
{
	/* TODO: Phase 2 */
}

int fs_open(const char *filename)
{
	/* TODO: Phase 3 */
}

int fs_close(int fd)
{
	/* TODO: Phase 3 */
}

int fs_stat(int fd)
{
	/* TODO: Phase 3 */
}

int fs_lseek(int fd, size_t offset)
{
	/* TODO: Phase 3 */
}

int fs_write(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}

int fs_read(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}

// DEBUG
int main(int argc, char *argv[])
{
	int m, i, u;
	m = fs_mount("./disk.fs");
	i = fs_info();
	//fprintf(stdout, "Retvals: m=%d, i=%d\n", m, i);
	u = fs_umount();
	fprintf(stdout, "Retvals: m=%d, i=%d, u=%d\n", m, i, u);
	
	return EXIT_SUCCESS;
}
