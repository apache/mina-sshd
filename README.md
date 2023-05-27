![Apache MINA SSHD](https://mina.apache.org/assets/img/header-sshd.png "Apache MINA SSHD")
# Apache MINA SSHD

Apache MINA SSHD is a 100% pure java library to support the SSH protocols on both the client and server side. It does not
aim at being a replacement for the SSH client or SSH server from Unix operating systems, but rather provides support for Java
based applications requiring SSH support.

The library can leverage several I/O back-ends:

* The default transport is built-in and uses Java's `AsynchronousSocketChannel`s.
* [Apache MINA](https://mina.apache.org), a scalable and high performance asynchronous I/O library, can be used instead, or
* the [Netty](https://netty.io) asynchronous event-driven network framework is also supported.

# Releases

Releases of Apache MINA sshd are available at [Maven Central](https://mvnrepository.com/artifact/org.apache.sshd). `tar.gz` and
ZIP source and binary distributions are available at the [Apache MINA sshd](https://mina.apache.org/sshd-project/downloads.html)
web site.

*Snapshot* releases from the main branch are published on each push or merge on the main branch, if the tests pass successfully.
These snapshot releases are available at the [Apache Snapshot](https://repository.apache.org/content/repositories/snapshots)
maven repository.

## [Release notes](./CHANGES.md)

# Issue reporting

Bug reports and improvement or feature requests can be filed at the [GitHub issue tracker](https://github.com/apache/mina-sshd/issues)
or at the [Apache issue tracker](https://issues.apache.org/jira/projects/SSHD).

Sensitive issues such as security vulnerabilities must be reported through [private channels](./SECURITY.md), not via either issue tracker.

# [Supported standards](./docs/standards.md)

# Core requirements

* Java 8+ (as of version 1.3)

* [Slf4j](https://www.slf4j.org/)

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

* *sshd-ldap* - contains server-side password and public key authenticators that use an LDAP server.

* *sshd-git* - contains replacements for [JGit](https://www.eclipse.org/jgit/) SSH session factory.

* *sshd-osgi* - contains an artifact that combines *sshd-common* and *sshd-core* so it can be deployed in OSGi environments.

* *sshd-putty* - contains code that can parse [PUTTY](https://www.putty.org/) key files.

* *sshd-openpgp* - contains code that can parse [OpenPGP](https://www.openpgp.org/) key files (with some limitations - see relevant section)

* *sshd-cli* - contains simple templates for command-line client/server - used to provide look-and-feel similar to the Linux *ssh/sshd* commands.

* *sshd-contrib* - **experimental** code that is currently under review and may find its way into one of the other artifacts
(or become an entirely new artifact - e.g., *sshd-putty* evolved this way).

# [Optional dependencies](./docs/dependencies.md)

# Quick reference

## Building the code

Including tests

```
mvn clean install
```

Without tests

```
mvn -Pquick clean install
```

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

# [HOWTO(s)](./docs/howto.md)

# Technical Documentation

## [SSH Key Exchange](./docs/technical/kex.md)

## [TCP/IP Port Forwarding](./docs/technical/tcpip-forwarding.md)

## [Global Requests](./docs/technical/global_requests.md)

## [Android support](./docs/android.md)
