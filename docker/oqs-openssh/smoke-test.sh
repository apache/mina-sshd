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

# Smoke test for the OQS-OpenSSH test image.
# Usage: smoke-test.sh <image> [docker|podman]
# Checks that pure ML-KEM and pure ML-DSA work in a real connection.
set -eu
IMAGE=${1:?usage: smoke-test.sh <image> [docker|podman]}
CT=${2:-docker}
NAME=oqs-smoke-$$
trap '$CT rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

$CT run -d --name "$NAME" "$IMAGE" >/dev/null
# Wait for sshd (host key generation happens at start).
i=0
until $CT logs "$NAME" 2>&1 | grep -q "Server listening"; do
    i=$((i + 1)); [ $i -gt 60 ] && { echo "sshd did not start"; $CT logs "$NAME"; exit 1; }
    sleep 1
done

ctr() { $CT exec "$NAME" sh -c "$1"; }

echo "== architecture: $(ctr 'uname -m')"
for k in mlkem512-sha256 mlkem768-sha256 mlkem1024-sha384; do
    ctr 'ssh -Q kex' | grep -qx "$k" || { echo "FAIL kex $k is not available"; exit 1; }
    echo "OK kex $k"
done
for k in ssh-mldsa-44 ssh-mldsa-65 ssh-mldsa-87; do
    ctr 'ssh -Q key' | grep -qx "$k" || { echo "FAIL key $k is not available"; exit 1; }
    echo "OK key $k"
done

ctr 'su test -c "ssh-keygen -q -t ssh-mldsa-44 -N \"\" -f ~/.ssh/id \
   && cp ~/.ssh/id.pub ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"'

for kex in mlkem512-sha256 mlkem768-sha256 mlkem1024-sha384; do
  for hk in ssh-mldsa-44 ssh-mldsa-65 ssh-mldsa-87; do
    out=$(ctr "su test -c 'ssh -v -o StrictHostKeyChecking=no -o KexAlgorithms=$kex \
        -o HostKeyAlgorithms=$hk -o PubkeyAcceptedAlgorithms=ssh-mldsa-44 -i /home/test/.ssh/id \
        localhost echo CONNECTED_OK' 2>&1")
    echo "$out" | grep -q "kex: algorithm: $kex" || { echo "FAIL kex $kex"; echo "$out"; exit 1; }
    echo "$out" | grep -q "Server host key: $hk" || { echo "FAIL host key $hk"; echo "$out"; exit 1; }
    echo "$out" | grep -q CONNECTED_OK || { echo "FAIL connect $kex/$hk"; echo "$out"; exit 1; }
    echo "OK session kex=$kex hostkey=$hk user-key=ssh-mldsa-44"
  done
done
echo "ALL OK"
