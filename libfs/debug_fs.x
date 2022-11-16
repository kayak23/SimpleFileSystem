#!
gcc -o fs_debug fs.c disk.c
../apps/fs_make.x disk.fs 1024
echo FS_DEBUG
