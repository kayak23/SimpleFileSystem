#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fs.h"

#ifndef RETVALS
#define RETVALS
#define RET_SUCCESS 1
#define RET_FAILURE -1
#endif

#define LONGEST 16
#define ASSERT(cond, func)                               \
do {                                                     \
	if (!(cond)) {                                       \
		fprintf(stderr, "Function '%s' failed\n", func); \
		exit(EXIT_FAILURE);                              \
	}                                                    \
} while (0)

#define TEST_ASSERT(assert)\
do {\
        if (assert) {\
                printf(" ... \033[0;32m[PASS]\033[0m\n");\
        } else	{\
                printf(" ... \033[0;31m[FAIL]\033[0m\n");\
        }\
} while(0)

static int format;

static int test_hello_world()
{	
	fprintf(stdout, "*** TEST hello world ***%n", &format);

	int fd;
	int ret;
	char data[50];
	
	/* Open file */
	fd = fs_open("file1.txt");
	ASSERT(fd >= 0, "fs_open");
	
	/* Read some data */
	ret = fs_read(fd, data, 13);
	ASSERT(ret == 13, "fs_read");
	ASSERT(!strncmp(data, "hello world!", 12), "fs_read");

	/* Close file and unmount */
	fs_close(fd);

	return RET_SUCCESS;
}

static int test_read_first_5()
{	
	fprintf(stdout, "*** TEST read first 5 ***%n", &format);

	int fd;
	int ret;
	char data[50];
	
	/* Open file */
	fd = fs_open("nums.txt");
	ASSERT(fd >= 0, "fs_open");

	/* Read first 5 bytes of data */
	ret = fs_read(fd, data, 5);
	ASSERT(ret == 5, "fs_read");
	ASSERT(!strncmp(data, "01234", 5), "fs_read");

	/* Close file */
	fs_close(fd);

	return RET_SUCCESS;
}

static int test_read_last_5()
{	
	fprintf(stdout, "*** TEST read last 5 ***%n", &format);

	int fd;
	int ret;
	char data[50];

	/* Open file */
	fd = fs_open("nums.txt");
	ASSERT(fd >= 0, "fs_open");

	fs_lseek(fd, 5);

	/* Read last 5 bytes of data */
	ret = fs_read(fd, data, 5);
	ASSERT(ret == 5, "fs_read");
	ASSERT(!strncmp(data, "56789", 5), "fs_read");

	/* Close file */
	fs_close(fd);

	return RET_SUCCESS;
}

static int test_read_middle_5()
{	
	fprintf(stdout, "*** TEST read middle 5 ***%n", &format);

	int fd;
	int ret;
	char data[50];

	/* Open file */
	fd = fs_open("nums.txt");
	ASSERT(fd >= 0, "fs_open");

	fs_lseek(fd, 3);

	/* Read middle 5 bytes of data */
	ret = fs_read(fd, data, 5);
	ASSERT(ret == 5, "fs_read");
	ASSERT(!strncmp(data, "34567", 5), "fs_read");

	/* Close file */
	fs_close(fd);

	return RET_SUCCESS;
}

static int test_read_big_file()
{	
	fprintf(stdout, "*** TEST read big_file ***%n", &format);

	int fd;
	int N = 28672;
	int ret;
	char test_buf[N];

	/* Open file */
	fd = fs_open("big_file.txt");
	ASSERT(fd >= 0, "fs_open");
	
	// char ctrl_buf[N];
	// char symbol;
	// /* Open actual file */
	// FILE *fp = fopen("big_file.txt", "r");
	// if(fp != NULL) {
	// 	while((symbol = getc(fp)) != EOF) {
	// 		strcat(ctrl_buf, &symbol);
	// 	}
	// 	fclose(fp);
	// }
	// fclose(fp);

	/* Read data */
	ret = fs_read(fd, test_buf, N);
	ASSERT(ret == N, "fs_read");

	//ASSERT(!strncmp(test_buf, ctrl_buf, N), "fs_read");

	/* Close file */
	fs_close(fd);

	return RET_SUCCESS;
}

static int test_read_lseek()
{	
	fprintf(stdout, "*** TEST read lseek ***%n", &format);

	int fd;
	int ret;
	char data[50];

	/* Open file */
	fd = fs_open("nums.txt");
	ASSERT(fd >= 0, "fs_open");

	/* Read middle 5 bytes of data */
	fs_lseek(fd, 3);
	ret = fs_read(fd, data, 5);
	ASSERT(ret == 5, "fs_read");
	ASSERT(!strncmp(data, "34567", 5), "fs_read");

	/* Read first 5 bytes of data */
	fs_lseek(fd, 0);
	ret = fs_read(fd, data, 5);
	ASSERT(ret == 5, "fs_read");
	ASSERT(!strncmp(data, "01234", 5), "fs_read");

	/* Close file */
	fs_close(fd);

	return RET_SUCCESS;
}

static int test_read_invalid_fd()
{	
	fprintf(stdout, "*** TEST read invalid fd ***%n", &format);

	int fd;
	int ret;
	char data[50];

	/* Open file */
	fd = fs_open("nums.txt");
	ASSERT(fd >= 0, "fs_open");

	ret = fs_read(-5, data, 5);
	ASSERT(ret == -1, "fs_read");

	ret = fs_read(100000, data, 5);
	ASSERT(ret == -1, "fs_read");

	/* Close file */
	fs_close(fd);

	return RET_SUCCESS;
}

static int test_read_invalid_offset()
{	
	fprintf(stdout, "*** TEST read invalid offset ***%n", &format);

	int fd;
	int ret;
	char data[50];

	/* Open file */
	fd = fs_open("nums.txt");
	ASSERT(fd >= 0, "fs_open");

	ret = fs_read(fd, data, -10);
	ASSERT(ret == -1, "fs_read");

	ret = fs_read(fd, data, 900);
	ASSERT(ret == 11, "fs_read");

	fs_lseek(fd, 5);
	ret = fs_read(fd, data, 900);
	ASSERT(ret == 6, "fs_read");

	/* Close file */
	fs_close(fd);

	return RET_SUCCESS;
}

static int test_read_null_buf()
{	
	fprintf(stdout, "*** TEST read null buf ***%n", &format);

	int fd;
	int ret;
	void *data = NULL;

	/* Open file */
	fd = fs_open("nums.txt");
	ASSERT(fd >= 0, "fs_open");

	ret = fs_read(fd, data, 11);
	ASSERT(ret == -1, "fs_read");


	/* Close file */
	fs_close(fd);

	return RET_SUCCESS;
}

int main(int argc, char *argv[])
{
	int ret;
	char *diskname;

	if (argc < 1) {
		printf("Usage: %s <diskimage>\n", argv[0]);
		exit(1);
	}

	/* Mount disk */
	diskname = argv[1];
	ret = fs_mount(diskname);
	ASSERT(!ret, "fs_mount");

	TEST_ASSERT(test_hello_world());
	TEST_ASSERT(test_read_first_5());
	TEST_ASSERT(test_read_last_5());
	TEST_ASSERT(test_read_middle_5());
	TEST_ASSERT(test_read_big_file());
	TEST_ASSERT(test_read_lseek());
	TEST_ASSERT(test_read_invalid_fd());
	TEST_ASSERT(test_read_invalid_offset());
	TEST_ASSERT(test_read_null_buf());
	
	fs_umount();

	return 0;
}
