#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "fs.h"

#define LONGEST 36

#ifndef RETVALS
#define RETVALS
#define RET_SUCCESS 0
#define RET_FAILURE -1
#endif

#define TEST_ASSERT(assert)\
do {\
        int k;\
        for(k = 0; k < LONGEST-format; k++) fprintf(stdout, " ");\
        if (assert) {\
                printf(" ... \033[0;32m[PASS]\033[0m\n");\
        } else  {\
                printf(" ... \033[0;31m[FAIL]\033[0m\n");\
        }\
} while(0)

static int format;
uint8_t *data = (uint8_t*)"hello my name is Kaya 123.";
uint8_t *data2 = (uint8_t*)"hello my name is Kaya 123.45678";
uint8_t *data3 = (uint8_t*)"----------------"; //16 in length

void test_large_write(int fd)
{
	printf("*** TEST BOUNDARY WRITE ***%n", &format);
	int i = 0;
	int len = 5000;
	uint8_t large[len];
	uint8_t buf[len];
	uint8_t *cross = (uint8_t*)"hello";
	size_t index = 4094;
	for (i = 0; i < len; i++)
		large[i] = (uint8_t)'f';
	fs_write(fd, (void*)large, len);
	fs_lseek(fd, index);
	fs_write(fd, (void*)cross, 5);
	fs_lseek(fd, 0);
	fs_read(fd, (void*)buf, len);
	TEST_ASSERT((char)buf[4094] == 'h' && (char)buf[4095] == 'e' && (char)buf[4096] == 'l' && (char)buf[4097] == 'l' && (char)buf[4098] == 'o');
}

void test_four_desc()
{
	printf("*** TEST MULTI OVRWRITE ***%n", &format);
	int fd1 = fs_open("file2.txt");
	int fd2 = fs_open("file2.txt");
	int fd3 = fs_open("file2.txt");
	int fd4 = fs_open("file2.txt");
	size_t len = strlen((char*)data3) + 1;
	uint8_t *buf = malloc(len);
	fs_write(fd1, (void*)data3, len);
	fs_write(fd2, (void*)"2222", 4);
	fs_write(fd3, (void*)"3333", 4);
	fs_write(fd4, (void*)"4444", 4);
	fs_lseek(fd1, 0);
	fs_read(fd1, (void*)buf, len);
	TEST_ASSERT(!strncmp("4444------------", (char*)buf, len));
	printf("*** TEST MULTI CPRWRITE ***%n", &format);
	fs_lseek(fd1, 0);
	fs_lseek(fd2, 4);
	fs_lseek(fd3, 8);
	fs_lseek(fd4, 12);
	fs_write(fd1, (void*)"1111", 4);
        fs_write(fd2, (void*)"2222", 4);
        fs_write(fd3, (void*)"3333", 4);
        fs_write(fd4, (void*)"4444", 4);
	fs_lseek(fd3, 0);
	fs_read(fd3, (void*)buf, len);
	TEST_ASSERT(!strncmp("1111222233334444", (char*)buf, len));
	free(buf);
	fs_close(fd1);
	fs_close(fd2);
	fs_close(fd3);
	fs_close(fd4);
}

void test_append(int fd)
{
	printf("*** TEST APPEND TO FILE ***%n", &format);
	uint8_t *new = (uint8_t*)"45678";
	size_t len = strlen((char*)new) + 1;
	size_t new_len = len + strlen((char*)data);
	uint8_t *buf = malloc(new_len);
	fs_lseek(fd, fs_stat(fd)-1); //overwrite old null byte
	int bytes = fs_write(fd, (void*)new, len);
	fs_lseek(fd, 0);
	fs_read(fd, (void*)buf, new_len);
	TEST_ASSERT(!strncmp((char*)data2, (char*)buf, new_len) && bytes == len);
	free(buf);
}

void test_write(int fd)
{
	printf("*** TEST WRITE FROM ZERO ***%n", &format);
	size_t len = strlen((char*)data) + 1;
	uint8_t *buf = malloc(len);
	int bytes = fs_write(fd, (void*)data, len);
	fs_lseek(fd, 0);
	fs_read(fd, (void*)buf, len);
	TEST_ASSERT(!strncmp((char*)data, (char*)buf, len) && bytes == len);
	free(buf);
}

void test_write_error(int fd)
{
	size_t len = strlen((char*)data) + 1;
	printf("*** TEST ERRONEOUS PARAMS ***%n", &format);
	int res1 = fs_write(-1, (void*)data, len); //fd out of bounds
	int res2 = fs_write(16, (void*)data, len); //fd not open
	int res3 = fs_write(fd, NULL, len); //buf is null
	TEST_ASSERT(res1 == -1 && res2 == -1 && res3 == -1);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: ./test_write.x <disk>\n");
		return RET_FAILURE;
	}
	
	char *diskname = argv[1];
	if (fs_mount(diskname))
		return RET_FAILURE;
	
	int fd;	

	/* test writing data */
	fs_create("file1.txt");
	fd = fs_open("file1.txt");
	test_write_error(fd);
	test_write(fd);
	test_append(fd);
	fs_close(fd);
	
	/* test multiple descriptors */
	fs_create("file2.txt");
	test_four_desc();
	
	/* test reading/writing across block boundary */
	fs_create("file3.txt");
	fd = fs_open("file3.txt");
	test_large_write(fd);
	fs_close(fd);

	fs_umount();
	return RET_SUCCESS;
}
