# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

# Small, multi-arch (linux/amd64, linux/arm64) OpenSSH server with PURE ML-KEM
# key exchange (mlkem768-sha256, ...) and pure ML-DSA host/user keys
# (ssh-mldsa-44/65/87), for MINA SSHD interoperability tests (GH-928).
#
# Based on the Open Quantum Safe OpenSSH fork (branch OQS-v10, OpenSSH 10.3p1).
# Everything is compiled in the BUILD stage. The final image only has the
# runtime files, so tests pull a small prebuilt image and need no compiler.
#
# Build:   docker buildx build --platform linux/amd64,linux/arm64 -t <name> .
# Run:     docker run --rm -p 2222:22 <name>

# Alpine 3.22.6 multi-arch index (includes linux/amd64 and linux/arm64).
# The digest wins over the tag; update the digest to change the base image.
FROM alpine:3.22.6@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS build
# Pinned versions. Change them together and re-run the interop tests.
# LIBOQS_REF is the commit of the 0.16.0 tag.
ARG LIBOQS_REF=5a1a854b0dc9f2141bdc771c555ee60c37950183
ARG OQS_OPENSSH_REF=10d74f8b27da43705cfab85923ac7e1d769416f1
RUN apk add --no-cache build-base cmake ninja git autoconf automake \
        openssl-dev zlib-dev linux-headers
WORKDIR /src

# liboqs. Do NOT use OQS_MINIMAL_BUILD: ssh-oqs.c references many signature
# algorithms (mayo, ...), so the fork does not compile against a trimmed liboqs.
RUN git init liboqs \
 && git -C liboqs fetch --depth 1 https://github.com/open-quantum-safe/liboqs.git "${LIBOQS_REF}" \
 && git -C liboqs checkout FETCH_HEAD \
 && cmake -S liboqs -B liboqs/build -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/opt/oqs \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_DIST_BUILD=ON \
        -DOQS_USE_OPENSSL=ON \
 && cmake --build liboqs/build \
 && cmake --install liboqs/build

# OQS-OpenSSH, installed under /opt/ssh.
# The fork calls sshkey_clear_pkey() without a visible prototype (an upstream
# header quirk). Its own CI hides this with -Wno-implicit-function-declaration;
# GCC 14 (Alpine 3.22) needs the "-Wno-error=" form.
RUN git init openssh \
 && git -C openssh fetch --depth 1 https://github.com/open-quantum-safe/openssh.git "${OQS_OPENSSH_REF}" \
 && git -C openssh checkout FETCH_HEAD \
 && cd openssh \
 && autoreconf -i \
 && ./configure --prefix=/opt/ssh --sysconfdir=/etc/ssh \
        --with-ssl-dir=/usr --with-liboqs-dir=/opt/oqs \
        --with-ldflags="-Wl,-rpath,/opt/oqs/lib" --with-libs=-lm \
        --with-cflags="-Wno-error=implicit-function-declaration" \
        --without-pam --without-selinux --with-privsep-path=/var/empty \
 && make -j"$(nproc)" \
 && make install-nokeys \
 && strip /opt/ssh/sbin/sshd /opt/ssh/bin/ssh /opt/ssh/bin/ssh-keygen

FROM alpine:3.22.6@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache libcrypto3 zlib \
 && adduser -D -s /bin/sh test \
 && passwd -u test \
 && mkdir -p /var/empty /etc/ssh /home/test/.ssh \
 && chown test:test /home/test/.ssh && chmod 700 /home/test/.ssh
COPY --from=build /opt/oqs /opt/oqs
COPY --from=build /opt/ssh /opt/ssh
COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV PATH="/opt/ssh/bin:/opt/ssh/sbin:${PATH}"
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
