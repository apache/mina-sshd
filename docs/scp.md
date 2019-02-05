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

### Client-side SCP

In order to obtain an `ScpClient` one needs to use an `ScpClientCreator`:

```java

ClientSession session = ... obtain an instance ...
ScpClientCreator creator = ... obtain an instance ...
ScpClient client = creator.createScpClient(session);

```

A default `ScpClientCreator` instance is provided as part of the module - see `ScpClientCreator.instance()`

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
    public static ScpTransferProgressMonitor MONITOR = new ScpTransferProgressMonitor();

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

**Note:** due to SCP protocol limitations one cannot change the **size** of the input/output since it is passed as part of the command
**before** the file opener is invoked - so there are a few limitations on what one can do within this interface implementation.

#### ScpTransferEventListener(s)

The `ScpClientCreator` can also be used to attach a default `ScpTransferEventListener` that will be attached to
**all** created SCP client instances through that creator - unless specifically overridden:

```java

ClientSession session = ... obtain an instance ...
ScpClientCreator creator = ... obtain an instance ...
creator.setScpTransferEventListener(new MySuperDuperListener());

ScpClient client1 = creator.createScpClient(session);   // <<== automatically uses MySuperDuperListener
ScpClient client2 = creator.createScpClient(session, new SomeOtherListener());   // <<== uses SomeOtherListener instead of MySuperDuperListener

```

### Server-side SCP

The `ScpCommandFactory` allows users to attach an `ScpFileOpener` and/or `ScpTransferEventListener` having the same behavior as the client - i.e.,
monitoring and intervention on the accessed local files.
