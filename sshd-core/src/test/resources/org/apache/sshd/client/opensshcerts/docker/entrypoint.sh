#!/bin/sh

# check that SSH_HOST_KEY is set
if [ -z "$SSH_HOST_KEY" ]; then
  echo "env SSH_HOST_KEY must be set to a host keypair file path"
  exit 1
fi

# setup the configured host keypair to a known location
ln -s ${SSH_HOST_KEY} /keys/host_key
ln -s ${SSH_HOST_KEY}.pub /keys/host_key.pub

# run supervisord (which runs sshd)
/usr/bin/supervisord -c /etc/supervisor/supervisord.conf
