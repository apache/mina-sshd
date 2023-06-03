#!/bin/sh

# This file is ISO-8859-1 encoded!

export LANG=en_US.iso885915
export LC_ALL=en_US.iso885915

echo "test1" > /home/bob/file1.txt
echo "test2" > /home/bob/הצü.txt

cat <<'EOF' >> /home/bob/.bashrc

export LANG=en_US.iso885915
export LC_ALL=en_US.iso885915
EOF

chown -R bob /home/bob
chmod 0600 /home/bob/.ssh/*

/usr/sbin/sshd -D -ddd
