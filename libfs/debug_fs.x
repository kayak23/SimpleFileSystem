#!
gcc -o fs_debug fs.c disk.c
../apps/fs_make.x disk.fs 4096
echo FS_DEBUG
