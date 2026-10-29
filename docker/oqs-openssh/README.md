<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
-->

# OQS-OpenSSH test container (pure ML-KEM and pure ML-DSA)

Interoperability test server for GH-928. It runs the Open Quantum Safe fork of OpenSSH
(branch `OQS-v10`, OpenSSH 10.3p1 based) on Alpine 3.22.6. Compilation happens once, in the image build;
the final image has only the runtime files, so tests pull a small prebuilt multi-arch image
(`linux/amd64`, `linux/arm64`).

The Alpine base image, liboqs (commit of the `0.16.0` tag) and OQS-OpenSSH are pinned in the
[Dockerfile](Dockerfile).

## What it supports

- Pure ML-KEM key exchange, with the names of `draft-harrison-sshm-mlkem`:
  `mlkem512-sha256`, `mlkem768-sha256`, `mlkem1024-sha384`.
  (Hybrids such as `mlkem768x25519-sha256` are in the binary, but `sshd_config` does not enable them.)
- Pure ML-DSA host and user keys, with the names of `draft-sfluhrer-ssh-mldsa`:
  `ssh-mldsa-44`, `ssh-mldsa-65`, `ssh-mldsa-87`.
- OQS composite keys (`ssh-rsa3072-mldsa-44`, ...). These are **not** the same as the
  `ssh-mldsa44-ed25519` of OpenSSH 10.5.

## Build and run

```
docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/mina-sshd-oqs-openssh:<tag> --push .
docker run --rm -p 2222:22 <registry>/mina-sshd-oqs-openssh:<tag>
```

- User `test`. Password login is disabled by default. Set the `TEST_PASSWORD` environment variable to set that
  password and enable password login (the value must not contain line breaks).
- Public keys: write `/home/test/.ssh/authorized_keys` (Testcontainers `withCopyToContainer`).
  The file must belong to `test` with mode 600.
- Host keys are generated at first start. Read the `.pub` files from `/etc/ssh` to build `known_hosts`.
- Additional arguments are passed to `sshd`, for example `-o LogLevel=DEBUG3`. The default log level is `VERBOSE`.

## Sanity test

```
./smoke-test.sh <image> docker   # or: podman
```

It prints `ALL OK` at the end. It checks the algorithm lists, then opens sessions with all three pure
ML-KEM key exchanges and all three ML-DSA host keys, using an `ssh-mldsa-44` user key.

Manual test:

1. Start the server: `docker run -d --name oqs -p 2222:22 <image>`
2. A stock OpenSSH client must be refused, since only pure ML-KEM is offered:
   `ssh -p 2222 test@localhost true`
   Expected: `no matching key exchange method found. Their offer: mlkem768-sha256,mlkem1024-sha384,mlkem512-sha256,...`
3. Connect with the client inside the image:
   ```
   docker exec -u test oqs ssh-keygen -q -t ssh-mldsa-44 -N '' -f /home/test/.ssh/id
   docker exec -u test oqs sh -c 'cp ~/.ssh/id.pub ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
   docker exec -u test oqs ssh -v -o StrictHostKeyChecking=no \
       -o KexAlgorithms=mlkem768-sha256 -o HostKeyAlgorithms=ssh-mldsa-65 \
       -o PubkeyAcceptedAlgorithms=ssh-mldsa-44 -i /home/test/.ssh/id localhost echo OK
   ```
   Expected in the output: `kex: algorithm: mlkem768-sha256`, `Server host key: ssh-mldsa-65` and `OK`.
4. Stop it: `docker rm -f oqs`

## Notes

1. **Fork.** The OQS fork describes itself as experimental. No other implementation with pure ML-KEM and
   pure ML-DSA in a small image was found.
2. **GCC 14 workaround.** The fork calls `sshkey_clear_pkey()` without a prototype.
   `-Wno-error=implicit-function-declaration` hides it, as the fork's own CI does.
3. **liboqs is not trimmed.** `OQS_MINIMAL_BUILD` breaks the build, because `ssh-oqs.c` references
   many signature algorithms. `/opt/oqs` is therefore the largest part of the image.
4. **ML-DSA private key format.** The format written by the fork's `ssh-keygen` is not checked against the
   seed-only format of `draft-ietf-sshm-composite-sigs`.
5. Host key algorithms in `sshd_config` are limited to the ML-DSA names and `ssh-ed25519`.

## CI: build and publish (`.github/workflows/oqs-openssh-image.yml`)

- Runs on `workflow_dispatch` (input: tag, default `dev`) and on pushes that touch this directory.
- Builds each architecture on a native runner (`ubuntu-24.04`, `ubuntu-24.04-arm`), without QEMU.
- Runs `smoke-test.sh` on each image.
- Pushes each image by digest to `ghcr.io/<owner>/mina-sshd-oqs-openssh`, then joins them into one multi-arch tag.
- All actions are pinned to commit hashes of ASF-approved versions.
- Publishing under `ghcr.io/apache` needs to be enabled by ASF Infra.
