# [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)

# [Version 2.2.0 to 2.3.0](./docs/changes/2.3.0.md)

# [Version 2.3.0 to 2.4.0](./docs/changes/2.4.0.md)

# [Version 2.4.0 to 2.5.0](./docs/changes/2.5.0.md)

# [Version 2.5.0 to 2.5.1](./docs/changes/2.5.1.md)

# [Version 2.5.1 to 2.6.0](./docs/changes/2.6.0.md)

# [Version 2.6.0 to 2.7.0](./docs/changes/2.7.0.md)

# [Version 2.7.0 to 2.8.0](./docs/changes/2.8.0.md)

# [Version 2.8.0 to 2.9.0](./docs/changes/2.9.0.md)

# [Version 2.9.0 to 2.9.1](./docs/changes/2.9.1.md)

# [Version 2.9.1 to 2.9.2](./docs/changes/2.9.2.md)

# [Version 2.9.2 to 2.10.0](./docs/changes/2.10.0.md)

# Planned for next version

## Bug Fixes

* [GH-370](https://github.com/apache/mina-sshd/issues/370) Also compare file keys in `ModifiableFileWatcher`.
* [GH-371](https://github.com/apache/mina-sshd/issues/371) Fix channel pool in `SftpFileSystem`.
* [GH-383](https://github.com/apache/mina-sshd/issues/383) Use correct default `OpenOption`s in `SftpFileSystemProvider.newFileChannel()`.
* [GH-384](https://github.com/apache/mina-sshd/issues/384) Use correct lock modes for SFTP `FileChannel.lock()`.
* [GH-388](https://github.com/apache/mina-sshd/issues/388) `ScpClient`: support issuing commands to a server that uses a non-UTF-8 locale.

* [SSHD-1259](https://issues.apache.org/jira/browse/SSHD-1259) Consider all applicable host keys from the known_hosts files.
* [SSHD-1310](https://issues.apache.org/jira/browse/SSHD-1310) `SftpFileSystem`: do not close user session.
* [SSHD-1327](https://issues.apache.org/jira/browse/SSHD-1327) `ChannelAsyncOutputStream`: remove write future when done.

## New Features

* [GH-356](https://github.com/apache/mina-sshd/issues/356) Publish snapshot maven artifacts to the [Apache Snapshots](https://repository.apache.org/content/repositories/snapshots) maven repository.


## Major Code Re-factoring

As part of the fix for [GH-371](https://github.com/apache/mina-sshd/issues/371)
the channel pool in `SftpFileSystem` was rewritten completely. Previous code also
used `ThreadLocal`s to store `SftpClient`s, which could cause memory leaks.

These `ThreadLocal`s have been removed, and the channel pool has been rewritten
to function similar to a Java `ThreadPool`: the pool has a maximum size; it has
an expiration duration after which an idle channel is removed and closed, and
it has a "core size" of channels to keep even if they are idle. If a channel is
closed for any reason it is evicted from the pool.

Properties to configure these pool parameters have been added to `SftpModuleProperties`.