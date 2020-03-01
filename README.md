![Apache MINA SSHD](https://mina.apache.org/staticresources/images/header-sshd.png "Apache MINA SSHD")
# Apache MINA SSHD

Apache SSHD is a 100% pure java library to support the SSH protocols on both the client and server side. This library can
leverage [Apache MINA](http://mina.apache.org), a scalable and high performance asynchronous IO library. SSHD does not really
aim at being a replacement for the SSH client or SSH server from Unix operating systems, but rather provides support for Java
based applications requiring SSH support.

# Supported standards

## Reference implementation documentation
* [RFC 4251 - The Secure Shell (SSH) Protocol Architecture](https://tools.ietf.org/html/rfc4251)
* [RFC 4252 - The Secure Shell (SSH) Authentication Protocol](https://tools.ietf.org/html/rfc4252)
* [RFC 4253 - The Secure Shell (SSH) Transport Layer Protocol](https://tools.ietf.org/html/rfc4253)
* [RFC 4254 - The Secure Shell (SSH) Connection Protocol](https://tools.ietf.org/html/rfc4254)
* [RFC 4256 - Generic Message Exchange Authentication for the Secure Shell Protocol (SSH)](https://tools.ietf.org/html/rfc4256)
* [RFC 4335 - The Secure Shell (SSH) Session Channel Break Extension](https://tools.ietf.org/html/rfc4335)
* [RFC 4344 - The Secure Shell (SSH) Transport Layer Encryption Modes](https://tools.ietf.org/html/rfc4344)
* [RFC 4345 - Improved Arcfour Modes for the Secure Shell (SSH) Transport Layer Protocol](https://tools.ietf.org/html/rfc4345)
* [RFC 4419 - Diffie-Hellman Group Exchange for the Secure Shell (SSH) Transport Layer Protocol](https://tools.ietf.org/html/rfc4419)
* [RFC 4716 - The Secure Shell (SSH) Public Key File Format](https://tools.ietf.org/html/rfc4716)
* [RFC 5480 - Elliptic Curve Cryptography Subject Public Key Information](https://tools.ietf.org/html/rfc5480)
* [RFC 5656 - Elliptic Curve Algorithm Integration in the Secure Shell Transport Layer](https://tools.ietf.org/html/rfc5656)
* [RFC 6668 - SHA-2 Data Integrity Verification for the Secure Shell (SSH) Transport Layer Protocol](https://tools.ietf.org/html/rfc6668)
* [RFC 8160 - IUTF8 Terminal Mode in Secure Shell (SSH)](https://tools.ietf.org/html/rfc8160)
* [RFC 8268 - More Modular Exponentiation (MODP) Diffie-Hellman (DH) Key Exchange (KEX) Groups for Secure Shell (SSH)](https://tools.ietf.org/html/rfc8268)
* [RFC 8308 - Extension Negotiation in the Secure Shell (SSH) Protocol](https://tools.ietf.org/html/rfc8308)
    * **Note:** - the code contains [**hooks**](./docs/event-listeners.md#kexextensionhandler) for implementing the RFC but
    beyond allowing convenient support for the required protocol details, it does not implement any default logic that handles
    the messages or manages the actual extension negotiation (though some **experimental** code is available).
* [RFC 8332 - Use of RSA Keys with SHA-256 and SHA-512 in the Secure Shell (SSH) Protocol](https://tools.ietf.org/html/rfc8332)
    * **Note:** - the server side supports these signatures by default. The client side requires specific
    initialization - see [section 3.3](https://tools.ietf.org/html/rfc8332#section-3.3) and also the
    above mentioned hooks for [RFC 8308](https://tools.ietf.org/html/rfc8308).
* [Key Exchange (KEX) Method Updates and Recommendations for Secure Shell](https://tools.ietf.org/html/draft-ietf-curdle-ssh-kex-sha2-03)
* [OpenSSH support for U2F/FIDO security keys](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f)
    * **Note:** the server side supports these keys by default. The client side requires specific initialization
* SFTP version 3-6 + extensions
    * `supported` - [DRAFT 05 - section 4.4](http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-05.tx)
    * `supported2` - [DRAFT 13 section 5.4](https://tools.ietf.org/html/draft-ietf-secsh-filexfer-13#page-10)
    * `versions` - [DRAFT 09 Section 4.6](http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt)
    * `vendor-id` - [DRAFT 09 - section 4.4](http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt)
    * `acl-supported` - [DRAFT 11 - section 5.4](https://tools.ietf.org/html/draft-ietf-secsh-filexfer-11)
    * `newline` - [DRAFT 09 Section 4.3](http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt)
    * `md5-hash`, `md5-hash-handle` - [DRAFT 09 - section 9.1.1](http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt)
    * `check-file-handle`, `check-file-name` - [DRAFT 09 - section 9.1.2](http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt)
    * `copy-file`, `copy-data` - [DRAFT 00 - sections 6, 7](http://tools.ietf.org/id/draft-ietf-secsh-filexfer-extensions-00.txt)
    * `space-available` - [DRAFT 09 - section 9.3](http://tools.ietf.org/wg/secsh/draft-ietf-secsh-filexfer/draft-ietf-secsh-filexfer-09.txt)
    * Several [OpenSSH SFTP extensions](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)

## Implemented/available support

* **Ciphers**: aes128cbc, aes128ctr, aes192cbc, aes192ctr, aes256cbc, aes256ctr, arcfour128, arcfour256, blowfishcbc, tripledescbc
* **Digests**: md5, sha1, sha224, sha256, sha384, sha512
* **Macs**: hmacmd5, hmacmd596, hmacsha1, hmacsha196, hmacsha256, hmacsha512, hmac-sha2-256-etm@openssh.com
, hmac-sha2-512-etm@openssh.com, hmac-sha1-etm@openssh.com
* **Key exchange**: diffie-hellman-group1-sha1, diffie-hellman-group-exchange-sha256, diffie-hellman-group14-sha1, diffie-hellman-group14-sha256
, diffie-hellman-group15-sha512, diffie-hellman-group16-sha512, diffie-hellman-group17-sha512, diffie-hellman-group18-sha512
, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521
* **Compressions**: none, zlib, zlib@openssh.com
* **Signatures/Keys**: ssh-dss, ssh-rsa, rsa-sha2-256, rsa-sha2-512, nistp256, nistp384, nistp521
, ed25519 (requires `eddsa` optional module), sk-ecdsa-sha2-nistp256@openssh.com, sk-ssh-ed25519@openssh.com

# [Release notes](./CHANGES.md)

# Core requirements

* Java 8+ (as of version 1.3)

* [Slf4j](http://www.slf4j.org/)

The code only requires the core abstract [slf4j-api](https://mvnrepository.com/artifact/org.slf4j/slf4j-api) module. The actual
implementation of the logging API can be selected from the many existing adaptors.

# Basic artifacts structure

* *sshd-common* - contains basic classes used throughout the project as well as code that does not require client or server network support.

* *sshd-core* - contains the basic SSH client/server code implementing the connection, transport, channels, forwarding, etc..
    * *sshd-mina*, *sshd-netty* - replacements for the default NIO2 connector used to establish and manage network connections using
[MINA](https://mina.apache.org/mina-project/index.html) and/or [Netty](https://netty.io/) libraries respectively.

* *sshd-sftp* - contains the server side SFTP subsystem and the SFTP client code.
    * *sshd-spring-sftp* - contains a [Spring Integration](https://spring.io/projects/spring-integration) compatible SFTP adapter

* *sshd-scp* - contains the server side SCP command handler and the SCP client code.

* *sshd-ldap* - contains server-side password and public key authenticators that use and LDAP server.

* *sshd-git* - contains replacements for [JGit](https://www.eclipse.org/jgit/) SSH session factory.

* *sshd-osgi* - contains an artifact that combines *sshd-common* and *sshd-core* so it can be deployed in OSGi environments.

* *sshd-putty* - contains code that can parse [PUTTY](https://www.putty.org/) key files.

* *sshd-openpgp* - contains code that can parse [OpenPGP](https://www.openpgp.org/) key files (with some limitations - see relevant section)

* *sshd-cli* - contains simple templates for command-line client/server - used to provide look-and-feel similar to the Linux *ssh/sshd* commands.

* *sshd-contrib* - **experimental** code that is currently under review and may find its way into one of the other artifacts
(or become an entirely new artifact - e.g., *sshd-putty* evolved this way).

# [Optional dependencies](./docs/dependencies.md)

# Quick reference

## [Set up an SSH client in 5 minutes](./docs/client-setup.md)

## [Embedding an SSHD server instance in 5 minutes](./docs/server-setup.md)

# SSH functionality breakdown

## [Security providers setup](./docs/security-providers.md)

## [Commands infrastructure](./docs/commands.md)

## [SCP](./docs/scp.md)

## [SFTP](./docs/sftp.md)

## [Port forwarding](./docs/port-forwarding.md)

## [Internal support classes](./docs/internals.md)

## [Event listeners and handlers](./docs/event-listeners.md)

## [Command line clients](./docs/cli.md)

## [GIT support](./docs/git.md)

## [Configuration/data files parsing support](./docs/files-parsing.md)

## [Extension modules](./docs/extensions.md)
