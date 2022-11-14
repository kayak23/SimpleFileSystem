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
#define RDIR_ENTRIES 	128
#define BLOCK_SIZE	4096
#define FAT_START	1

typedef struct super_blk*	sb_t;
typedef uint16_t*		fat_t;
typedef struct dir*	 	dir_t;

struct __attribute__((__packed__)) super_blk 
{
	char		signature[8];
	uint16_t 	total_blocks;
	uint16_t 	root_dir_idx;
	uint16_t 	data_block_idx;
	uint16_t	total_data_blocks;
	uint8_t		fat_blocks;  
	uint8_t		padding[4079];
};

struct __attribute__((__packed__)) dir 
{
	char		file_name[16];
	uint16_t 	file_size;
	uint8_t		data_block_idx;
	uint8_t		padding[10];
};

sb_t super_blk;
fat_t fat;
dir_t root_dir;

int mounted = 0;
int open_files = 0;

int fs_mount(const char *diskname)
{
	if (diskname == NULL )
		return -1;

	if (block_disk_open(diskname))
		return -1;

	super_blk = (struct super_blk*) malloc(sizeof(struct super_blk));
	root_dir = (struct dir*) malloc(sizeof(struct dir) *  FS_FILE_MAX_COUNT);
	if (super_blk == NULL || root_dir == NULL)
		return -1;

	block_read(0, super_blk);
	if (strcmp(super_blk->signature, VALID_SIG) || super_blk->total_blocks != block_disk_count())
		return -1;
	
	block_read(super_blk->root_dir_idx, root_dir);
	
	fat = malloc(sizeof(uint16_t) * super_blk->fat_blocks * BLOCK_SIZE);

	uint16_t *data_blk = malloc(sizeof(uint16_t) * BLOCK_SIZE);

	int block_idx = 0;
	for (int i = FAT_START; i <= super_blk->fat_blocks; i++) {
		block_read(i, data_blk);
		memcpy(fat + block_idx, data_blk, BLOCK_SIZE);
		block_idx += BLOCK_SIZE;
	}

	//free(data_blk);
	mounted = 1;
	return 0;
}

int fs_umount(void)
{
	/* 
	 * makes sure that the virtual disk is
	 * properly closed and that all the internal
	 * data structures of the FS layer are properly
	 * cleaned.
	 */

	if (open_files > 0 || block_disk_count() == -1)
		return -1;
	
	block_write(super_blk->root_dir_idx, root_dir);
	block_write(0, super_blk);
	block_write(1, fat);
	block_write(2, fat + BLOCK_SIZE);

	if (block_disk_close() == -1)
		return -1;

	free(root_dir);
	free(fat);
	free(super_blk);

	mounted = 0;

	return 0;
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
	if (block_disk_count() == -1)
		return -1;

	printf("FS Info:\n");
	printf("total_blk_count=%d\n", super_blk->total_blocks);
	printf("fat_blk_count=%d\n", super_blk->fat_blocks);
	printf("rdir_blk=%d\n", super_blk->root_dir_idx);
	printf("data_blk=%d\n", super_blk->data_block_idx);
	printf("data_blk_count=%d\n", super_blk->total_data_blocks);
	printf("fat_free_ratio=%d/%d\n", super_blk->total_data_blocks - get_fat_free_num(), super_blk->total_data_blocks);
	printf("rdir_free_ratio=%d/%d\n", get_rdir_free_num(), RDIR_ENTRIES);
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
	fs_mount("../apps/disk.fs");
	fs_info();
	fs_umount();
}
