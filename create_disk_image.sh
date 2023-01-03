#!/bin/sh

### create the disk file
dd if=/dev/zero of=disk.img bs=1M count=64

### create the file system 
mkfs.vfat -I -F 32 -S 512 -s 8 disk.img

### mount it
mkdir -p mnt
sudo mount -o rw,uid=${UID} -t vfat disk.img mnt

### create a few files / dir
echo "this is the file contents" > mnt/myfile.txt

# creating a few files
echo “Hello World” > mnt/hello.txt
echo “file contents” > mnt/note.txt
# creating a few directories
mkdir mnt/mydir
echo “Hello Subdir” > mnt/mydir/hello.txt
echo “subdir file contents” > mnt/mydir/note.txt

### umount it again
sudo umount mnt

gcc stub_disk_access.c -o stub_disk_access
./stub_disk_access
