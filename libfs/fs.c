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
	uint8_t		padding[4079];
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
	uint8_t fd_val;
	uint8_t offset;
};

sb_t super_blk;
fat_t fat;
dir_t root_dir;

fd_t fd_table[FS_OPEN_MAX_COUNT];
uint8_t fd_keys[FS_OPEN_MAX_COUNT];

int mounted = 0;
int open_files = 0;
int free_entries = 0;

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

/*  DEBUG only func */
void print_fat(void)
{
        int i;
        for (i = 0; i < super_blk->fat_blocks*BLOCK_SIZE; i++)
                if (fat[i] != 0)
                        fprintf(stdout, "FAT entry %d: %d\n", i, fat[i]);
}

/*  DEBUG only func */
void print_dir(void)
{
        int i;
        char *fn = "Filename";
        char *fs = "Filesize";
        char *bi = "Block Index";
        for (i = 0; i < FS_FILE_MAX_COUNT; i++) {
                if (root_dir[i].file_name[0] != '\0') {
                        char *efn = root_dir[i].file_name;
                        int efs = root_dir[i].file_size;
                        int idx = root_dir[i].data_block_idx;
                        fprintf(stdout, "Root entry %d:\n\t%s:%s\n\t%s:%d\n\t%s:%d\n", i, fn, efn, fs, efs, bi, idx);
                }
        }
}

/* Validate the given string filename
 * returns RET_FAILURE == -1 on failure
 * returns length of filename on success
 * string func is an error-printing parameter
 * */
int validate_filename(const char *filename, const char *func)
{
	int size = 0;

	if (mounted == 0) {
                fprintf(stderr, "[%s] Error: no FS mounted.\n", func);
                return RET_FAILURE;
        }
        if (filename == NULL) {
                fprintf(stderr, "[%s] Error: null filename\n", func);
                return RET_FAILURE;
        }
        while (filename[size++] != '\0' && size < FS_FILENAME_LEN);
        if (size > FS_FILENAME_LEN) {
                fprintf(stderr, "[%s] Error: filename '%s' length invalid.\n", func, filename);
                return RET_FAILURE;
        }
        if (filename[size-1] != '\0') {
                fprintf(stderr, "[%s] Error: filename '%s' not null-terminated. Last char: %c\n", func, filename, filename[size-1]);
                return RET_FAILURE;
        }

	return size;
}

int fs_mount(const char *diskname)
{
	/* In the future, let's break this function
	 * into three sections in which we initialize
	 * all of our globals individually
	 * */

	/* check whether diskname is valid fs */
	if (diskname == NULL ) {
		fprintf(stderr, "[mnt] null diskname\n");
		return RET_FAILURE;
	}
	if (block_disk_open(diskname)) {
		fprintf(stderr, "[mnt] invalid diskname\n");
		return RET_FAILURE;
	} /* all following failure catches should close the disk */

	/* load the superblock */
	super_blk = malloc(sizeof(struct super_blk));
	root_dir = malloc(sizeof(struct dir) * FS_FILE_MAX_COUNT);
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
	free_entries = get_rdir_free_num();

	/* load the FAT */
	int i;
	int block_idx = 0;
	fat = malloc(sizeof(uint16_t) * super_blk->fat_blocks * BLOCK_SIZE);
	//uint16_t *data_blk = malloc(sizeof(uint16_t) * BLOCK_SIZE); //this was twice as large as it should have been
	uint16_t data_blk[BLOCK_SIZE/2];
	if (fat == NULL /*|| data_blk == NULL*/) {
		fprintf(stderr, "[mnt] malloc error\n");
		return RET_FAILURE;
	}
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
	if ((size = validate_filename(filename, "crt")) == RET_FAILURE)
		return RET_FAILURE;
	if (free_entries <= 0) {
		fprintf(stderr, "[crt] Error: root dir full.\n");
		return RET_FAILURE;
	}
	while ((unique = strcmp(root_dir[j++].file_name, filename)) && j < FS_FILE_MAX_COUNT);
	if (!unique) {
		fprintf(stderr, "[crt] Error: duplicate filename '%s'.\n", filename);
		return RET_FAILURE;
	}

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
        if (validate_filename(filename, "del") == RET_FAILURE)
                return RET_FAILURE;
	/* verify file exists and get idx */
        while ((unique = strcmp(root_dir[idx=j++].file_name, filename)) && j < FS_FILE_MAX_COUNT);
        if (unique) {
                fprintf(stderr, "[del] Error: no such filename '%s'.\n", filename);
                return RET_FAILURE;
        }

        /* delete file */
        memcpy(root_dir[idx].file_name, "", 1);
        root_dir[idx].file_size = 0;
        i = root_dir[idx].data_block_idx;
	while (i != FAT_EOC) {
		j = fat[i];
		fat[i] = 0;
		i = j;
	}
        free_entries++;

        return RET_SUCCESS;
}

int fs_ls(void)
{
	int i;
	fprintf(stdout, "FS Ls:\n");
	for (i = 0; i < FS_FILE_MAX_COUNT; i++) {
		if (root_dir[i].file_name[0] != '\0') {
			char *efn = root_dir[i].file_name;
			int efs = root_dir[i].file_size;
			int idx = root_dir[i].data_block_idx;
			fprintf(stdout, "file: %s, size: %d, data_blk: %d\n", efn, efs, idx);
		}
	}
}

int fs_open(const char *filename)
{	
	/* variable declarations */
	int fd_idx = -1;
	int file_idx = 0;
	int j = 0;
	int unique = 0;

	/* check if filename is valid */
	if (validate_filename(filename, "open") == RET_FAILURE)
		return RET_FAILURE;
	/* check if too many files */
	if (open_files >= FS_OPEN_MAX_COUNT) {
		fprintf(stderr, "[open] Error: too many open files.\n");
		return RET_FAILURE;
	}
	/* check if file exists */
	while ((unique = strcmp(root_dir[j++].file_name, filename)) && j < FS_FILE_MAX_COUNT);
        if (unique) {
                fprintf(stderr, "[open] Error: no such filename '%s'.\n", filename);
                return RET_FAILURE;
        }
	/* find file to open */
        for (file_idx = 0; file_idx < FS_FILE_MAX_COUNT; file_idx++) {
		if (root_dir[file_idx].file_name[0] != '\0' && strcmp(root_dir[file_idx].file_name, filename) == 0) {
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
					open_file->fd_val = fd_idx;
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
	/* check for mounted FS */
	if (mounted == 0) {
		fprintf(stderr, "[close] Error: no FS mounted.\n");
		return RET_FAILURE;
	}
	/* Check for a valid fd */
	if (fd > FS_OPEN_MAX_COUNT || fd < 0) {
		fprintf(stderr, "[close] Error: fd out-of-bounds.\n");
		return RET_FAILURE;
	}
	/* check if file exists */
	if (fd_keys[fd] == 0) {
		fprintf(stderr, "[close] Error: fd DNE.\n");
		return RET_FAILURE;
	}
	
	fd_keys[fd] = 0;
	free(fd_table[fd]);
        open_files--;

	return RET_SUCCESS;
}

int fs_stat(int fd)
{
	/* error catching */
	if (mounted == 0) {
                fprintf(stderr, "[stat] Error: no FS mounted.\n");
                return RET_FAILURE;
        }
        /* check fd exists and in bounds */
        if (fd > FS_OPEN_MAX_COUNT || fd < 0) {
                fprintf(stderr, "[stat] Error: fd out-of-bounds.\n");
                return RET_FAILURE;
        }
        if (fd_keys[fd] == 0) {
                fprintf(stderr, "[stat] Error: fd DNE.\n");
                return RET_FAILURE;
        }
	
	return fd_table[fd]->file->file_size;
}

int fs_lseek(int fd, size_t offset)
{
	/* error catching */
	if (mounted == 0) {
                fprintf(stderr, "[seek] Error: no FS mounted.\n");
                return RET_FAILURE;
        }
        /* check fd exists and in bounds */
	if (fd > FS_OPEN_MAX_COUNT || fd < 0) {
                fprintf(stderr, "[seek] Error: fd out-of-bounds.\n");
                return RET_FAILURE;
        }
        if (fd_keys[fd] == 0) {
                fprintf(stderr, "[seek] Error: fd DNE.\n");
                return RET_FAILURE;
        }
	if (fd_table[fd]->file->file_size < offset) {
		fprintf(stderr, "[seek] Error: offset out-of-bounds.\n");
		return RET_FAILURE;
	}
	
	fd_table[fd]->offset = offset;

	return RET_SUCCESS;
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
	int retval_print = 0;
	unsigned int dcode = 0b00000000;
	int m, i, u, f1, f2;
	for(i = 0; i < argc; i++) {
		if(!strcmp(argv[i], "-pf"))
			dcode = dcode | 0b00000001;
		if(!strcmp(argv[i], "-pd"))
			dcode = dcode | 0b00000010;
		if(!strcmp(argv[i], "-rv"))
			dcode = dcode | 0b00000100;
	}
	/* begin debugging track */
	m = fs_mount("./disk.fs");
	i = fs_info();
	f1 = fs_create("file1");
	f2 = fs_create("file2");
	fs_delete("file1");
	/* end debugging track */

	if(dcode & 0b00000001)
		print_fat();
	if(dcode & 0b00000010)
		print_dir();
	if(dcode & 0b00000100)
		retval_print = 1;
	/* unmount FS */
	u = fs_umount();
	
	if(retval_print)
		fprintf(stdout, "Retvals: m=%d, i=%d, u=%d, f1=%d, f2=%d\n", m, i, u, f1, f2);
	
	return EXIT_SUCCESS;
}
