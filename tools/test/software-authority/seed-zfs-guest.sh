#!/bin/sh
set -eux
[ "$(hostname)" = auth-policy-vm ]
[ "$(kenv vfs.root.mountfrom)" = ufs:/dev/vtbd0p2 ]
# Only the disposable, explicitly identified destination disk may be changed.
[ "$(geom disk list vtbd1 | awk '/ident:/ {print $2}')" = context-zfs-target ]
if gpart show vtbd1; then exit 1; fi
gpart create -s gpt vtbd1
gpart add -t freebsd-boot -s 512k -a 4k vtbd1
gpart add -t freebsd-zfs -a 1m vtbd1
gpart bootcode -b /boot/pmbr -p /boot/gptzfsboot -i 1 vtbd1
mkdir -p /mnt/context-root
zpool create -R /mnt/context-root -O mountpoint=none -O atime=off policyvm /dev/vtbd1p2
zfs create -o mountpoint=none policyvm/ROOT
zfs create -o mountpoint=/ -o canmount=noauto policyvm/ROOT/default
zfs mount policyvm/ROOT/default
zpool set bootfs=policyvm/ROOT/default policyvm
# Copy from the seed filesystem only, never recurse into the destination pool.
tar --one-file-system -cpf /mnt/context-root/seed.tar -C / --exclude ./mnt --exclude ./dev --exclude ./proc --exclude ./tmp --exclude ./usr/src .
tar -xpf /mnt/context-root/seed.tar -C /mnt/context-root
rm /mnt/context-root/seed.tar
mkdir -p /mnt/context-root/dev /mnt/context-root/proc /mnt/context-root/tmp /mnt/context-root/mnt
chmod 1777 /mnt/context-root/tmp
cp /root/integration-profile /mnt/context-root/root/.profile
printf '%s\n' 'tmpfs /Capabilities/Run tmpfs rw,mode=0700 0 0' > /mnt/context-root/etc/fstab
printf '%s\n' 'vfs.root.mountfrom="zfs:policyvm/ROOT/default"' > /mnt/context-root/boot/loader.conf.local
sync
zpool export policyvm
echo REAL_ZFS_SEED_PASS
/usr/sbin/capsulectl poweroff
