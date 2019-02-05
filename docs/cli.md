## Command line clients

The _apache-sshd.zip_ distribution provides `Windows/Linux` scripts that use the MINA SSHD code base to implement the common
_ssh, scp, sftp_ commands. The clients accept most useful switches from the original commands they mimic, where the `-o Option=Value`
arguments can be used to configure the client/server in addition to the system properties mechanism. For more details, consult
the _main_ methods code in the respective `SshClientMain`, `SftpCommandMain` and `ScpClientMain` classes. The code also includes
`SshKeyScanMain` that is a simple implementation for [ssh-keyscan(1)](https://www.freebsd.org/cgi/man.cgi?query=ssh-keyscan&sektion=1).

The distribution also includes also an _sshd_ script that can be used to launch a server instance - see `SshServerMain#main`
for activation command line arguments and options.

In order to use this CLI code as part of another project, one needs to include the _sshd-cli_ module:

```xml
    <dependency>
        <groupId>org.apache.sshd</groupId>
        <artifactId>sshd-cli</artifactId>
        <version>...same version as the core...</version>
    </dependency>
```

### Command line clients

* **SftpCommandMain** - by default uses an internal `SftpClientFactory`. This can be overridden as follows:

1. Provide a `-o SftpClientFactory=XXX` command line argument where the option specifies the fully-qualified name of
the class that implements this interface.

2. Add a `META-INF\services\org.apache.sshd.client.subsystem.sftp.SftpClientFactory` file containing the fully-qualified name of
the class that implements this interface. **Note:** if more than one such instance is detected an exception is thrown.

**Note:** The specified class(es) must be public and contain a public no-args constructor.

### Command line SSH daemon

* **Port** - by default the SSH server sets up to list on port 8000 in order to avoid conflicts with any running SSH O/S daemon.
This can be modified by providing a `-p NNNN` or `-o Port=NNNN` command line option.

* **Subsystem(s)** - the server automatically detects subsystems using the
[Java ServiceLoader mechanism](https://docs.oracle.com/javase/8/docs/api/java/util/ServiceLoader.html).

This can be overwritten as follows (in this order):

1. Provide a `org.apache.sshd.server.subsystem.SubsystemFactory` system property containing comma-separated fully-qualified names of classes implementing
this interface. The implementations must be public and have a public no-args constructor for instantiating them. The order of the provided subsystems will
be according to their order in the specified list.

2. Provide a `-o Subsystem=xxx,yyy` command line argument where value is a comma-separated list of the **name**(s) of the auto-detected factories via
the `ServiceLoader` mechanism. The special value `none` may be used to indicate that no subsystem is to be configured. **Note:** no specific order is
provided when subsystems are auto-detected and/or filtered.

* **Shell** - unless otherwise instructed, the default SSH server uses an internal shell (see `InteractiveProcessShellFactory`). The shell can be overridden
or disabled by specifying a `-o ShellFactory=XXX` option where the value can either be `none` to specify that no shell is to be used, or the fully-qualified
name of a class that implements the `ShellFactory` interface. The implementation must be public and have a public no-args constructor for instantiating it.
