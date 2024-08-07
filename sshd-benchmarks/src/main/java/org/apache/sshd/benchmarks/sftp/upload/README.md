# SFTP benchmarks

This is a suite of benchmarks for file uploading via SFTP. The benchmarks time the upload of a 20MB file to an SFTP server.

The benchmarks can be run using the `RunBenchmarks` runner with option `--run SftpUploadBenchmark`.

The benchmark suite has three parts:

* `CatUpload` uploads the file not via SFTP but using the equivalent of `ssh user@host 'cat > upload/testfile.bin' < localfile.bin`. This gives a crude baseline that should always be faster than SFTP. First, there is no overhead for SFTP message headers, so it should need a little less SSH packets, and second, there are no SFTP ACKs at all.

* `JschBenchmark` uploads the file via Jsch.

* `SshBenchmark` uploads the file in various ways using Apache MINA sshd.

All benchmarks time the raw time for the file transfer. SSH session setup and SFTP session setup are not measured. All benchmarks also download the uploaded file and compare it to the original, and fail on differences. This sanity check is also not part of the timing.

Benchmarks are run twice, once with the default cipher settings of JSch (`aes128-ctr` cipher and `hmac-sha2-256-etm@openssh.com` MAC), and once with the default cipher of Apache MINA sshd (`chacha20-poly1305@openssh.com`).

