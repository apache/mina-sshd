# [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)

# [Version 2.2.0 to 2.3.0](./docs/changes/2.3.0.md)

# [Version 2.3.0 to 2.4.0](./docs/changes/2.4.0.md)

# [Version 2.4.0 to 2.5.0](./docs/changes/2.5.0.md)

# [Version 2.5.0 to 2.5.1](./docs/changes/2.5.1.md)

# [Version 2.5.1 to 2.6.0](./docs/changes/2.6.0.md)

# [Version 2.6.0 to 2.7.0](./docs/changes/2.7.0.md)

# Planned for next version

## Major code re-factoring

## Potential compatibility issues

## Minor code helpers

* [SSHD-1193](https://issues.apache.org/jira/browse/SSHD-1193) Provide a more user-friendly text in case disconnecting due to timeout(s).
* [SSHD-1196](https://issues.apache.org/jira/browse/SSHD-1196) Provide configurable support for SFTP output stream chunking behavior.

## Behavioral changes and enhancements

* [SSHD-704](https://issues.apache.org/jira/browse/SSHD-704) Add support for RFC 8731 (curve25519 and curve448 key exchange algorithms)
* [SSHD-1017](https://issues.apache.org/jira/browse/SSHD-1017) Add support for the chacha20-poly1305@openssh.com cipher
* [SSHD-1161](https://issues.apache.org/jira/browse/SSHD-1161) Support OpenSSH client certificates for publickey authentication
* [SSHD-1163](https://issues.apache.org/jira/browse/SSHD-1163) Wrong server key signature algorithm chosen in DH group key exchange
* [SSHD-1164](https://issues.apache.org/jira/browse/SSHD-1164) Parsing of ~/.ssh/config Host patterns fails with extra whitespace
* [SSHD-1166](https://issues.apache.org/jira/browse/SSHD-1166) Support creating signed OpenSSH certificates
* [SSHD-1168](https://issues.apache.org/jira/browse/SSHD-1168) OpenSSH certificates: check certificate type
* [SSHD-1172](https://issues.apache.org/jira/browse/SSHD-1172) Expiration of OpenSshCertificates needs to compare timestamps as unsigned long
* [SSHD-1202](https://issues.apache.org/jira/browse/SSHD-1202) Provide SftpErrorDataHandler callback support for SFTP client.
* [SSHD-1215](https://issues.apache.org/jira/browse/SSHD-1215) Treat ACE4_APPEND_DATA as a hint only in SFTP write mode determination
* [SSHD-1216](https://issues.apache.org/jira/browse/SSHD-1216) Implement RFC 8332 server-sig-algs on the server
* [SSHD-1217](https://issues.apache.org/jira/browse/SSHD-1217) Add special handling of SFTP directory entries listing if underlying file system is also SFTP
* [SSHD-1218](https://issues.apache.org/jira/browse/SSHD-1218) SshAgentFactory.createClient() gets passed the session
* [SSHD-1219](https://issues.apache.org/jira/browse/SSHD-1219) Obtaining rsa-sha2-256 or rsa-sha2-512 signatures from an SSH agent
* [SSHD-1220](https://issues.apache.org/jira/browse/SSHD-1220) Reduce number of L(STAT) calls made by the SftpFileSystem
* [SSHD-1221](https://issues.apache.org/jira/browse/SSHD-1221) Support key constraints when adding a key to an SSH agent
