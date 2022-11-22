#!
make
rm disk.fs
rm disk_control.fs
./fs_make.x disk.fs 10
./fs_make.x disk_control.fs 10
./test_fs.x add disk.fs file1.txt
./fs_ref.x add disk_control.fs file1.txt
./test_fs.x add disk.fs file2.txt
./fs_ref.x add disk_control.fs file2.txt
./test_fs.x rm disk.fs file1.txt
./fs_ref.x rm disk_control.fs file1.txt
./test_fs.x add disk.fs big_file.txt
./fs_ref.x add disk_control.fs big_file.txt
xxd disk.fs > dtest.txt
xxd disk_control.fs > dcon.txt
