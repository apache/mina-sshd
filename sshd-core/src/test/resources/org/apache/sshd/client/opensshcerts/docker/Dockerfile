FROM alpine:3.13

RUN apk --update add supervisor openssh openssh-server bash \
  && rm -rf /var/cache/apk/* \
# sshd requires a "privilege separation directory"
  && mkdir /var/run/sshd \
# add a group for all the ssh users
  && addgroup customusers \
# add a non-root local users
  && adduser -D user01 -G customusers \
  && adduser -D user02 -G customusers \
# unlock the users (but dont set a password)
  && passwd -u user01 \
  && passwd -u user02 \
# create a keys directory for the users authorized_keys
  && mkdir -p /keys/user/user01 \
  && mkdir -p /keys/user/user02 \
# set passwords
  && echo 'user01:password01' | chpasswd \
  && echo 'user02:password02' | chpasswd

COPY entrypoint.sh /entrypoint.sh

# copy users pub keys into authorized_keys files
COPY user01_authorized_keys /keys/user/user01/authorized_keys
COPY user02_authorized_keys /keys/user/user02/authorized_keys

# copy SSH host keypairs
COPY host01 /keys/host/host01
COPY host01.pub /keys/host/host01.pub
COPY host02 /keys/host/host02
COPY host02.pub /keys/host/host02.pub

# copy CA pub key
COPY ca.pub /ca.pub

# copy sshd_config
COPY sshd_config /etc/ssh/sshd_config

# supervisord conf
COPY supervisord.conf /etc/supervisor/supervisord.conf

EXPOSE 22

CMD ["/entrypoint.sh"]
