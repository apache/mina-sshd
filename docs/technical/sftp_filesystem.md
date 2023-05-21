# The `SftpFileSystem`

Class `SftpFileSystem` is an implementation of `java.nio.file.FileSystem` and
lets client code treat an SFTP server like any other file system. It is a
*remote* file system, though, and that has some effects that clients have
to aware of. Because operations are *remote* operations involving network
requests and answers, the performance characteristics are different than
most other file systems.

# Creating an `SftpFileSystem`

An `SftpFileSystem` needs an SSH session to be able to talk to the SFTP server.

There are two ways to create an `SftpFileSystem`:

1. If you already have an SSH `ClientSession`, you can create the file system
   off that session using `SftpClientFactory.instance().createSftpFileSystem()`.
   The file system remains valid until it is closed, or until the session is
   closed. When the file system is closed, the session will *not* be closed.
   
2. You can create an `SftpFileSystem` with a `sftp://` URI using the standard
   Java factory `java.nio.file.FileSystems.newFileSystem()`. This will automatically
   create an `SshClient` with default settings, and the file system will open
   an SSH session itself. This session has heartbeats enabled to keep it open
   for as long as the file system is open. The file system remains valid until
   closed, at which point it will close the session it had created.

In either case, the file system will be closed if the session closes.

# SSH Resource Management

Most operations on an `SftpFileSystem`, or on streams returned, produce SFTP
requests over the network, and wait for a reply to be received. This works
internally by using `SftpClient` to talk to the SFTP server. An `SftpClient`
is the client-side implementation of the SFTP protocol over an SSH channel
(a `ChannelSession`).

The SSH channel and the `SftpClient` are tightly coupled: the channel is
opened when the `SftpClient`is initialized, and the channel is closed when
the `SftpClient` is closed, and when the channel closes, so is the `SftpClient`.

For `SftpFileSystem` it would be rather inefficient to use a new `SftpClient`
for each new operation. That would create a new channel every time, and tear
it down after the operation. But channels have a setup cost, and the SFTP
protocol also has to initialized, both of which involve exchanging messages
over the network. This is not efficient if one wants to perform multiple
operations, such as transferring multiple files with `java.nio.file.Files.copy()`.

## The Channel Pool

The `SftpFileSystem` thus employs a *pool* of `SftpClient`s. This pool is
initially empty. The first operation will create an `SftpClient`, initialize
it, and then perform its operation. But then it will add the still open
`SftpClient` to the pool for use by subsequent operations instead of closing
it. The next operation can then simply grab this already initialized `SftpClient`
with its open channel and perform its operation.

The pool is limited by a maximum size of `SftpModuleProperties.POOL_SIZE` (by
default 8). The pool can grow to this size if there are that many threads that
perform operations on the `SftpFileSystem` concurrently.

`SftpClient`s in the pool need to be closed at some point. Consider an application
that has a burst of file transfers and uses 8 threads to perform them. Afterwards,
the pool will contain 8 `SftpClient`s: that's 8 open SSH channels, each with an SFTP
subsystem at the server's end. If the application then does only little, like
transferring a few files sequentially over the next few hours, until the next burst
(which may never come), then we don't want to keep all 8 channels open and consuming
resources not only in the client but also on the server side.

(This assumes that the whole SSH session remains open for that long, which can be
accomplished by using heartbeats on the session.)

The `SftpFileSystem` handles this by expiring inactive clients from the pool. If a
client has been in the pool for `SftpModuleProperties.POOL_LIFE_TIME` (default is 10
seconds), it is removed from the pool and closed. (If it was in the pool for that
time, this means it was idle for that time: no operation was performed on it.) If
no operation on the `SftpFileSystem` occurs at all for this time, it's possible that
the pool is emptied, and the next operation has to create and initialize a new
`SftpClient`and channel.

If an application doesn't want this, it can define `SftpModuleProperties.POOL_CORE_SIZE`,
which must be smaller than `POOL_SIZE`. By default, it is zero. If greater than zero,
that many `SftpClient`s are kept in the pool (and that many channels are kept open)
even if they are idle.

It should be noted that the SFTP server may also decide to close channels whenever
it wants. This will close the channel and the `SftpClient`on the client side. If it
happens while a client-side operation is ongoing, the operation will fail with an
exception; it it happens on an idle `SftpClient` in the pool, the `SftpClient` is
simply removed from the pool.

If the whole SSH session is closed, the `SftpFileSystem` is closed. When a
`SftpFileSystem` is closed, all `SftpClient`s in the pool are closed, and no new
clients will be added to the pool.

## Choosing the Pool Size

If there are more then `POOL_SIZE` threads using the same `SftpFileSystem`, it is
possible that all `POOL_SIZE` clients are already in use when a thread tries to
do a file system operation. In this case, a new `SftpClient` is created, which
will be closed after the operation. This is a sign of the `POOL_SIZE` being too 
small for the application, or that the application is badly designed. Using too
many threads for remote file operations is not a good idea in SFTP: all traffic
in the end goes over a single network connection anyway. Using a limited number
of threads may bring some speedup compared to strictly sequential operations
because the handling of the data received is offloaded to these threads, while
the next message can already be sent or received. But copying 1000 files using
1000 threads and SSH channels is nonsense; it's far better to handle that many
files in batches with a smaller number of threads (maybe 8).

In any case, `SftpModuleProperties.POOL_SIZE` should be large enough to accommodate
the number of threads the client application is going to use for operations on
the `SftpFileSystem`. If there are more threads, performance may degrade.

Versions of Apache MINA sshd <= 2.10.0 tried to mitigate this performance drop
for such "extra" threads by keeping the `SftpClient` in a `ThreadLocal`, so that
such "extra" threads could re-use the `SftpClient`. This mechanism has been *removed*
because it sometimes caused memory leaks. The mechanism was also flawed because
there were use cases where it just could not work correctly.

Design your application such that is uses a small maximum number of threads that
perform operations on a `SftpFileSystem`instance. Set `SftpModuleProperties.POOL_SIZE`
such that it is >= the maximum number of threads that operate concurrently on the
file system. The default pool size is 8.
