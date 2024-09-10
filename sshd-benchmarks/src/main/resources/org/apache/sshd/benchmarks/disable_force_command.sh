#!/bin/bash

# Remove the ForceCommand and the chroot jail to enable the cat upload benchmark
sed -i 's/ForceCommand internal-sftp//g' /etc/ssh/sshd_config
sed -i 's/ChrootDirectory %h//g' /etc/ssh/sshd_config
