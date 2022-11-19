# Target library
lib := libfs.a
objs := fs.o disk.o

CC := gcc
CFLAGS := -Wall -Wextra -Werror -MMD

all: $(lib)

deps := $(patsubst %.o,%.d,$(objs))
-include $(deps)

$(lib): $(objs)
	@ar rcs $(lib) $(objs)

%.o: %.c
	@$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@echo "CLEAN"
	@rm -f $(lib) $(objs) $(deps)
