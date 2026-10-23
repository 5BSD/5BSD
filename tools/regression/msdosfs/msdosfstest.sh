#!/bin/sh
# A really simple script to create a swap-backed msdosfs filesystem, copy a few
# files to it, unmount/remount the filesystem, and make sure all is well.
# 
# Not very advanced, but better than nothing. 
mkdir /tmp/msdosfstest/
mdconfig -a -t swap -s 128m -u 10
gpart create -s mbr md10
gpart add -t fat16 md10
newfs_msdos -F 16 -b 8192 /dev/md10s1
mount_msdosfs /dev/md10s1 /tmp/msdosfstest/
cp -R /usr/src/bin/ /tmp/msdosfstest/
umount /tmp/msdosfstest/
mount_msdosfs /dev/md10s1 /tmp/msdosfstest/
diff -u -r /usr/src/bin /tmp/msdosfstest/
if [ $? -eq 0 ]; then
	echo "ok 1";
else
	echo "not ok 1";
fi
umount /tmp/msdosfstest/
mdconfig -d -u 10
rmdir /tmp/msdosfstest/
