#!
make
rm disk.fs
rm disk_control.fs
./fs_make.x disk.fs 10
./fs_make.x disk_control.fs 10
./test_fs.x add disk.fs file1.txt
./fs_ref.x add disk_control.fs file1.txt
xxd disk.fs > dtest.txt
xxd disk_control.fs > dcon.txt
