#!/bin/sh
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

# Generate host keys on first start, optionally enable password login for the test user, run sshd.
set -e
K=/etc/ssh
[ -f "$K/ssh_host_ed25519_key" ] || ssh-keygen -q -t ed25519    -N '' -f "$K/ssh_host_ed25519_key"
[ -f "$K/ssh_host_mldsa44_key" ] || ssh-keygen -q -t ssh-mldsa-44 -N '' -f "$K/ssh_host_mldsa44_key"
[ -f "$K/ssh_host_mldsa65_key" ] || ssh-keygen -q -t ssh-mldsa-65 -N '' -f "$K/ssh_host_mldsa65_key"
[ -f "$K/ssh_host_mldsa87_key" ] || ssh-keygen -q -t ssh-mldsa-87 -N '' -f "$K/ssh_host_mldsa87_key"

if [ -n "${TEST_PASSWORD:-}" ]; then
    nl='
'
    cr=$(printf '\r')
    case $TEST_PASSWORD in
        *"$nl"* | *"$cr"*)
            echo "TEST_PASSWORD must not contain line breaks" >&2
            exit 1
            ;;
    esac
    printf 'test:%s\n' "$TEST_PASSWORD" | chpasswd
    set -- -o PasswordAuthentication=yes "$@"
fi
exec /opt/ssh/sbin/sshd -D -e "$@"
