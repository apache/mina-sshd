#!/bin/sh

chown -R bob /home/bob
chmod 0600 /home/bob/.ssh/*

/usr/sbin/sshd -D -ddd
