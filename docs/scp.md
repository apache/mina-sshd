## SCP

Both client-side and server-side SCP are supported. Starting from version 2.0, the SCP related code is located in the `sshd-scp` module, so you need
to add this additional dependency to your maven project:

```xml

    <dependency>
        <groupId>org.apache.sshd</groupId>
        <artifactId>sshd-sscp</artifactId>
        <version>...same as sshd-core...</version>
    </dependency>

```

### `ScpTransferEventListener`

Callback to inform about SCP related events. `ScpTransferEventListener`(s) can be registered on *both* client and server side:

```java

    // Server side
    ScpCommandFactory factory = new ScpCommandFactory(...with/out delegate..);
    factory.addEventListener(new MyServerSideScpTransferEventListener());
    sshd.setCommandFactory(factory);

    // Client side
    try (ClientSession session = client.connect(user, host, port)
            .verify(...timeout...)
            .getSession()) {
        session.addPasswordIdentity(password);
        session.auth().verify(...timeout...);

        ScpClientCreator creator = ... obtain an instance ...
        ScpClient client = creator.createScpClient(session, new MySuperDuperListener());

        ...scp.upload/download...
    }
```

### Client-side SCP

In order to obtain an `ScpClient` one needs to use an `ScpClientCreator`:

```java

ClientSession session = ... obtain an instance ...
ScpClientCreator creator = ... obtain an instance ...
ScpClient client = creator.createScpClient(session);

```

A default `ScpClientCreator` instance is provided as part of the module - see `ScpClientCreator.instance()`

The `ScpClientCreator` can also be used to attach a default `ScpTransferEventListener` that will be automatically
add to **all** created SCP client instances through that creator - unless specifically overridden:

```java

ClientSession session = ... obtain an instance ...
ScpClientCreator creator = ... obtain an instance ...
creator.setScpTransferEventListener(new MySuperDuperListener());

ScpClient client1 = creator.createScpClient(session);   // <<== automatically uses MySuperDuperListener
ScpClient client2 = creator.createScpClient(session, new SomeOtherListener());   // <<== uses SomeOtherListener instead of MySuperDuperListener

```

#### ScpFileOpener(s)

As part of the `ScpClientCreator`, the SCP module also uses a `ScpFileOpener` instance in order to access
the local files. The default implementation simply opens an [InputStream](https://docs.oracle.com/javase/8/docs/api/java/io/InputStream.html)
or [OutputStream](https://docs.oracle.com/javase/8/docs/api/java/io/OutputStream.html) on the requested local path. However,
the user may replace it and intercept the calls - e.g., for logging, monitoring transfer progess, wrapping/filtering the streams, etc...
The user may attach a default opener that will be automatically attached to **all** clients created unless specifically overridden:

```java

/**
 * Example of using a non-default opener for monitoring and reporting on transfer progress
 */
public class ScpTransferProgressMonitor extends DefaultScpFileOpener {
    public static final ScpTransferProgressMonitor MONITOR = new ScpTransferProgressMonitor();

    public ScpTransferProgressMonitor() {
        super();
    }

    @Override
    public InputStream openRead(
            Session session, Path file, long size, Set<PosixFilePermission> permissions, OpenOption... options)
                throws IOException {
        return new MyProgressReportingInputStream(super.openRead(session, file, size, permissions, options), size /* how much is expected */);
    }

    @Override
    public OutputStream openWrite(
            Session session, Path file, long size, Set<PosixFilePermission> permissions, OpenOption... options)
                throws IOException {
        return new MyProgressReportingOutputStream(super.openWrite(session, file, size, permissions, options), size /* how much is expected */);
    }
}

ClientSession session = ... obtain an instance ...
ScpClientCreator creator = ... obtain an instance ...
creator.setScpFileOpener(ScpTransferProgressMonitor.INSTANCE);

ScpClient client1 = creator.createScpClient(session);   // <<== automatically uses ScpTransferProgressMonitor
ScpClient client2 = creator.createScpClient(session, new SomeOtherOpener());   // <<== uses SomeOtherOpener instead of ScpTransferProgressMonitor

```

**Note(s):**

* Due to SCP protocol limitations one cannot change the **size** of the input/output since it is passed as part of the command
**before** the file opener is invoked - so there are a few limitations on what one can do within this interface implementation.

* By default, SCP synchronizes the local copied file data with the file system using the [Java SYNC open option](https://docs.oracle.com/javase/8/docs/api/java/nio/file/StandardOpenOption.html#SYNC).
This behavior can be controlled by setting the `scp-auto-sync-on-write` (a.k.a. `ScpFileOpener#PROP_AUTO_SYNC_FILE_ON_WRITE`) property to _false_
or overriding the `DefaultScpFileOpener#resolveOpenOptions`, or even overriding the `ScpFileOpener#openWrite` method altogether.

* Patterns used in `ScpFileOpener#getMatchingFilesToSend` are matched using case sensitivity derived from the O/S as detected by
the internal `OsUtils`. If a different behavior is required, then one needs to replace the default opener with one that uses a
different sensitivity via `DirectoryScanner#setCaseSensitive` call (or executes the pattern matching in another way).

    * `Windows` - case insensitive
    * `Unix` - case sensitive

### Server-side SCP

The `ScpCommandFactory` allows users to attach an `ScpFileOpener` and/or `ScpTransferEventListener` having the same behavior as the client - i.e.,
monitoring and intervention on the accessed local files.
