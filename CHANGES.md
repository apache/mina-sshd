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

* [GH-328](https://github.com/apache/mina-sshd/issues/328) Added configurable timeout(s) to `DefaultSftpClient`.
* [GH-370](https://github.com/apache/mina-sshd/issues/370) Also compare file keys in `ModifiableFileWatcher`.
* [GH-371](https://github.com/apache/mina-sshd/issues/371) Fix channel pool in `SftpFileSystem`.
* [GH-383](https://github.com/apache/mina-sshd/issues/383) Use correct default `OpenOption`s in `SftpFileSystemProvider.newFileChannel()`.
* [GH-384](https://github.com/apache/mina-sshd/issues/384) Use correct lock modes for SFTP `FileChannel.lock()`.
* [GH-388](https://github.com/apache/mina-sshd/issues/388) `ScpClient`: support issuing commands to a server that uses a non-UTF-8 locale.
* [GH-398](https://github.com/apache/mina-sshd/issues/398) `SftpInputStreamAsync`: fix reporting EOF on zero-length reads.
* [GH-403](https://github.com/apache/mina-sshd/issues/403) Work-around a bug in WS_FTP <= 12.9 SFTP clients.
* [GH-407](https://github.com/apache/mina-sshd/issues/407) (Regression in 2.10.0) SFTP performance fix: override `FilterOutputStream.write(byte[], int, int)`.
* [GH-410](https://github.com/apache/mina-sshd/issues/410) Fix a race condition to ensure `SSH_MSG_CHANNEL_EOF` is always sent before `SSH_MSG_CHANNEL_CLOSE`.
* [GH-414](https://github.com/apache/mina-sshd/issues/414) Fix error handling while flushing queued packets at end of KEX.

* [SSHD-789](https://issues.apache.org/jira/browse/SSHD-789) Fix detection of Android O/S from system properties.
* [SSHD-1259](https://issues.apache.org/jira/browse/SSHD-1259) Consider all applicable host keys from the known_hosts files.
* [SSHD-1310](https://issues.apache.org/jira/browse/SSHD-1310) `SftpFileSystem`: do not close user session.
* [SSHD-1327](https://issues.apache.org/jira/browse/SSHD-1327) `ChannelAsyncOutputStream`: remove write future when done.
* [SSHD-1332](https://issues.apache.org/jira/browse/SSHD-1332) (Regression in 2.10.0) Resolve ~ in IdentityFile file names in `HostConfigEntry`.

## New Features

* [SSHD-1330](https://issues.apache.org/jira/browse/SSHD-1330) Use `KeepAliveHandler` global request instance in client as well
* [GH-356](https://github.com/apache/mina-sshd/issues/356) Publish snapshot maven artifacts to the [Apache Snapshots](https://repository.apache.org/content/repositories/snapshots) maven repository.
* Bundle _sshd-contrib_ has support classes for the [HAProxy protocol V2](https://www.haproxy.org/download/2.7/doc/proxy-protocol.txt).

# Behavioral changes and enhancements

### SFTP file handle size

Previous versions of Apache MINA sshd used SFTP file handles that were twice
as large as configured via `SftpModuleProperties.FILE_HANDLE_SIZE`. The reason for
this was that the file handle bytes were stringified, representing each byte
as two hex characters. This stringified file handle was then send over the wire.
If `SftpModuleProperties.FILE_HANDLE_SIZE` was configured as 16, the actual file
handle size was thus 32 bytes.

This has been fixed in this version.

Additionally, the default setting for the size of file handles has been changed
from 16 to 4 bytes. OpenSSH also uses 4-byte SFTP file handles. Using the same
size not only means that there is a little more space left in SSH packets for
actual data transfer, it also completely avoids the WS_FTP bug mentioned in
[GH-403](https://github.com/apache/mina-sshd/issues/403).

## Potential compatibility issues

### `KeepAliveHandler` global request handler moved from server to common global requests package

Was previously only on server-side - now also for client (see [SSHD-1330](https://issues.apache.org/jira/browse/SSHD-1330)).
This should be fully backward compatible since most servers do not send this request. However, if users have somehow added this
handler to the client side independently, the code should be re-examined and the independent handler removed or make it replace the global one.

### Server-side SFTP file handle encoding

The aforementioned fix for the size of SFTP file handles has the potential to
have undesired effects on existing server-side code that assumed that such SFTP
file handles contained only printable characters. This is no longer the case. For
historical reasons, Apache MINA sshd stores these SFTP file handles as Java
`String`s, and it's not possible to change this without breaking a lot of APIs.
So this was kept, but the strings are now encoded as ISO-8859-1 and may
contain arbitrary characters in the range from 0 to 255. This change
*should* be transparent as SFTP file handles are supposed to be opaque, but
there is one caveat:

If you have implemented your own server and have subclassed `SftpSubsystem` or
if you install an `SftpEventListener` that stores or logs raw SFTP file handles,
your code may need to be adapted. There is a new method
`String Handle.safe(String rawHandle)` that can be used to convert an SFTP file
handle to a printable string.

Otherwise the change is transparent to server implementors and to SFTP clients.
(On the client side, Apache MINA sshd already used `byte[]` to represent SFTP
file handles.) 

### Major Code Re-factoring

As part of the fix for [GH-371](https://github.com/apache/mina-sshd/issues/371)
the channel pool in `SftpFileSystem` was rewritten completely. Previous code also
used `ThreadLocal`s to store `SftpClient`s, which could cause memory leaks.

These `ThreadLocal`s have been removed, and the channel pool has been rewritten
to function similar to a Java `ThreadPool`: the pool has a maximum size; it has
an expiration duration after which an idle channel is removed and closed, and
it has a "core size" of channels to keep even if they are idle. If a channel is
closed for any reason it is evicted from the pool.

Properties to configure these pool parameters have been added to `SftpModuleProperties`.