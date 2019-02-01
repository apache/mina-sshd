![Apache MINA SSHD](https://mina.apache.org/staticresources/images/header-sshd.png "Apache MINA SSHD")
# Apache MINA SSHD

Apache SSHD is a 100% pure java library to support the SSH protocols on both the client and server side. This library can
leverage [Apache MINA](http://mina.apache.org), a scalable and high performance asynchronous IO library. SSHD does not really
aim at being a replacement for the SSH client or SSH server from Unix operating systems, but rather provides support for Java
based applications requiring SSH support.

# Core requirements

* Java 8+ (as of version 1.3)


* [Slf4j](http://www.slf4j.org/)


The code only requires the core abstract [slf4j-api](https://mvnrepository.com/artifact/org.slf4j/slf4j-api) module. The actual
implementation of the logging API can be selected from the many existing adaptors.

# Optional dependencies


## [Bouncy Castle](https://www.bouncycastle.org/)


Required mainly for writing keys to PEM files or for special keys/ciphers/etc. that are not part of the standard
[Java Cryptography Extension](https://en.wikipedia.org/wiki/Java_Cryptography_Extension). See
[Java Cryptography Architecture (JCA) Reference Guide](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)
for key classes and explanations as to how _Bouncy Castle_ is plugged in (other security providers).

**Caveat**: If _Bouncy Castle_ modules are registered, then the code will use its implementation of the ciphers,
keys, signatures, etc. rather than the default JCE provided in the JVM.

 **Note:**

 - The security provider can also be registered for keys/ciphers/etc. that are already supported by the standard JCE as a **replacement** for them.


 - The _BouncyCastle_ code can also be used to load keys from PEM files instead or in parallel with the built-in code that
already parses the standard PEM formats for the default JCE supported key types.


- One can use the `BouncyCastleKeyPairResourceParser` to load standard PEM files instead of the core one - either directly
or via `SecurityUtils#setKeyPairResourceParser` for **global** usage - even without registering or enabling the provider.


 - The required _Maven_ module(s) are defined as `optional` so must be added as an **explicit** dependency in order to be included in the classpath:


```xml

    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcpg-jdk15on</artifactId>
    </dependency>
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcpkix-jdk15on</artifactId>
    </dependency>

```

## NIO2 default socket factory replacements

Optional dependency to enable choosing between NIO asynchronous sockets (the default - for improved performance), and "legacy" sockets.
**Note:** the required Maven module(s) are defined as `optional` so must be added as an **explicit** dependency in order to be included
in the classpath.

### [MINA core](https://mina.apache.org/mina-project/)

```xml

    <dependency>
        <groupId>org.apache.mina</groupId>
        <artifactId>mina-core</artifactId>
            <!-- see SSHD POM for latest tested known version of MINA core -->
        <version>2.0.17</version>
    </dependency>

    <dependency>
        <groupId>org.apache.sshd</groupId>
        <artifactId>sshd-mina</artifactId>
        <version>...same as sshd-core...</version>
    </dependency>

```

### [Netty](https://netty.io/)

Another a NIO client server framework option that can be used as a replacement for the default NIO asynchronous sockets core
implementation. This is also an **optional** dependency and must be add explicitly via the `sshd-netty` artifact.

```xml

    <dependency>
        <groupId>io.netty</groupId>
        <artifactId>netty-transport</artifactId>
        <version>...Netty version...</version>
    </dependency>
    <dependency>
        <groupId>io.netty</groupId>
        <artifactId>netty-handler</artifactId>
        <version>...Netty version...</version>
    </dependency>

    <dependency>
        <groupId>org.apache.sshd</groupId>
        <artifactId>sshd-netty</artifactId>
        <version>...same as sshd-core...</version>
    </dependency>

```

### Selecting an `IoServiceFactoryFactory`

As part of the their initialization, both client and server code require the specification of a `IoServiceFactoryFactory`
that is used to initialize network connections.

```java

    SshServer server = ...create server instance...
    server.setIoServiceFactoryFactory(new MyIoServiceFactoryFactory());

    SshClient client = ... create client instance ...
    client.setIoServiceFactoryFactory(new MyIoServiceFactoryFactory());

```

If not set explicitly during the client/server setup code, then a factory is automatically detected and selected when the
client/server is `#start()`-ed. The used `IoServiceFactoryFactory` is a **singleton** that is lazy created the 1st time
`DefaultIoServiceFactoryFactory#create` is invoked. The selection process is as follows:

* The `org.apache.sshd.common.io.IoServiceFactoryFactory` system property is examined for a factory specification. The
specification can be either a **fully-qualified** class name or one of the `BuiltinIoServiceFactoryFactories` values.

* If no specific factory is specified, then the [ServiceLoader#load](https://docs.oracle.com/javase/tutorial/ext/basics/spi.html#register-service-providers)
mechanism is used to detect and instantiate any registered services in any `META-INF\services\org.apache.sshd.common.io.IoServiceFactoryFactory`
location in the classpath. If **exactly one** implementation was instantiated, then it is used. If several such implementations are found then
an exception is thrown.

* Otherwise, the built-in `Nio2ServiceFactoryFactory` is used.

**Note:** the default command line scripts for SSH/SCP/SFTP client/server are set up to use NIO2 as their default provider,
unless overridden via the `-io` command line option. The `org.apache.sshd.common.io.IoServiceFactoryFactory` system property does
not apply for the command line wrappers since they look only for the `-io` option and use it to initialize the client/server **explicitly**
before starting the client/server. Therefore, the default selection process described in this section does not apply for them.

## [ed25519-java](https://github.com/str4d/ed25519-java)


Required for supporting [ssh-ed25519](https://tools.ietf.org/html/draft-bjh21-ssh-ed25519-02) keys
and [ed25519-sha-512](https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-02) signatures. **Note:**
the required Maven module(s) are defined as `optional` so must be added as an **explicit** dependency in
order to be included in the classpath:


```xml

        <!-- For ed25519 support -->
    <dependency>
        <groupId>net.i2p.crypto</groupId>
        <artifactId>eddsa</artifactId>
    </dependency>

```

The code contains support for reading _ed25519_ [OpenSSH formatted private keys](https://issues.apache.org/jira/browse/SSHD-703).

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

# Set up an SSH client in 5 minutes

SSHD is designed to easily allow setting up and using an SSH client in a few simple steps. The client needs to be configured
and then started before it can be used to connect to an SSH server. There are a few simple steps for creating a client
instance - for more details refer to the `SshClient` class.

## Creating an instance of the `SshClient` class

This is simply done by calling

```java

    SshClient client = SshClient.setupDefaultClient();

```

The call will create an instance with a default configuration suitable for most use cases - including ciphers,
compression, MACs, key exchanges, signatures, etc... If your code requires some special configuration, one can
look at the code for `setupDefaultClient` and `checkConfig` as a reference for available options and configure
the SSH client the way you need.

## Set up client side security

The SSH client contains some security related configuration that one needs to consider

### `ServerKeyVerifier`

`client.setServerKeyVerifier(...);` sets up the server key verifier. As part of the SSH connection initialization
protocol, the server proves its "identity" by presenting a public key. The client can examine the key (e.g., present
it to the user via some UI) and decide whether to trust the server and continue with the connection setup. By default
the client is initialized with an `AcceptAllServerKeyVerifier` that simply logs a warning that an un-verified server
key was accepted. There are other out-of-the-box verifiers available in the code:

* `RejectAllServerKeyVerifier` - rejects all server key - usually used in tests or as a fallback verifier if none
of it predecesors validated the server key


* `RequiredServerKeyVerifier` - accepts only **one** specific server key (similar to certificate pinning for SSL)


* `KnownHostsServerKeyVerifier` - uses the [known_hosts](https://en.wikibooks.org/wiki/OpenSSH/Client_Configuration_Files#Public_Keys_from_other_Hosts_.E2.80.93_.7E.2F.ssh.2Fknown_hosts)
file to validate the server key. One can use this class + some existing code to **update** the file when new servers are detected and their keys are accepted.


Of course, one can implement the verifier in whatever other manner is suitable for the specific code needs.

### ClientIdentityLoader/KeyPairProvider

One can set up the public/private keys to be used in case a password-less authentication is needed. By default, the client is configured to automatically
detect and use the identity files residing in the user's *~/.ssh* folder (e.g., *id_rsa*, *id_ecdsa*) and present them as part of the authentication process.
**Note:** if the identity files are encrypted via a password, one must configure a `FilePasswordProvider` so that the code can decrypt them before using
and presenting them to the server as part of the authentication process. Reading key files in PEM format (including encrypted ones) is supported by default
for the standard keys and formats. Using additional non-standard special features requires that the [Bouncy Castle](https://www.bouncycastle.org/) supporting
artifacts be available in the code's classpath.

#### Providing passwords for encrypted key files

The `FilePasswordProvider` is required for all private key files that are encrypted and being loaded (not just the "identity" ones). If the user
knows ahead of time that the file being currently decoded is not encrypted, a *null* provider may be used (if the file turns out to be encrypted
though an exception will be thrown in this case).

The `FilePasswordProvider`has support for a **retry mechanism** via its `handleDecodeAttemptResult`. When the code detects an encrypted private key,
it will start a loop where it prompts for the password, attempts to decode the key using the provided password and then informs the provider of
the outcome - success or failure. If failure is signaled, then the provider can decide whether to retry using a new password, abort (with exception)
or ignore. If the provider chooses to ignore the failure, then the code will make a best effort to proceed without the (undecoded) key.

The invoked methods are provided with a `NamedResource` that provides an indication of the key source "name" that is being attempted. This name
can be used in order to prompt the user interactively and provide a useful "hint" as to the password that needs to be provided. Furthermore, the
vast majority of the provided `NamedResource`-s also implement `IoResource` - which means that the code can find out what type of resource
is being attempted - e.g., a file [Path](https://docs.oracle.com/javase/8/docs/api/index.html?java/nio/file/Path.html),
a [URL](https://docs.oracle.com/javase/8/docs/api/java/net/URL.html), a [URI](https://docs.oracle.com/javase/8/docs/api/java/net/URI.html),
etc. - and modify it's behavior accordingly.

#### OpenSSH file format support

The code supports [OpenSSH](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key?rev=1.1&content-type=text/x-cvsweb-markup)
formatted files without any specific extra artifacts (although for reading _ed25519_ keys one needs to add the _EdDSA_ support artifacts). For
**encrypted** files only the the `bcrypt` key derivation function (KDF) is [currently supported](https://issues.apache.org/jira/browse/SSHD-708).
In this context, the maximum allowed number of rounds has been set to ~255 in order to protect the decryption process from
malformed or malicious data. However, since the protocol allows for 2^31 values, it is possible to modify the default by
calling `BCryptKdfOptions#setMaxAllowedRounds()` **programmatically** at any time - please note that

* The setting is **global** - i.e., affects all decryption attempts from then on and not just for the current SSH session or thread.

* The setting value is never allowed to be non-positive - any attempt to set such a value programmatically
throws an exception.

The usual _OpenSSH_ default seems to be 16, but users can ask for more (or less) by generating an encrypted key via
[`ssh-keygen -a NNN`](http://man7.org/linux/man-pages/man1/ssh-keygen.1.html). However, this comes at a cost:

>> -a rounds
>>
>>    When saving a private key this option specifies the number of
>>    KDF (key derivation function) rounds used.  Higher numbers
>>    result in slower passphrase verification

Various discussions on the net seem to indicate that 64 is the value at which many computers start to slow down noticeably, so
our default limit seems quite suitable (and beyond) for most cases we are likely to encounter "in the wild".

### UserInteraction

This interface is required for full support of `keyboard-interactive` authentication protocol as described in [RFC 4256](https://www.ietf.org/rfc/rfc4256.txt).
The client can handle a simple password request from the server, but if more complex challenge-response interaction is required, then this interface must be
provided - including support for `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ` as described in [RFC 4252 section 8](https://www.ietf.org/rfc/rfc4252.txt).

While RFC-4256 support is the primary purpose of this interface, it can also be used to retrieve the server's welcome banner as described
in [RFC 4252 section 5.4](https://www.ietf.org/rfc/rfc4252.txt) as well as its initial identification string as described
in [RFC 4253 section 4.2](https://tools.ietf.org/html/rfc4253#section-4.2).

## Using the `SshClient` to connect to a server

Once the `SshClient` instance is properly configured it needs to be `start()`-ed in order to connect to a server.
**Note:** one can use a single `SshClient` instance to connnect to multiple servers as well as modifying the default
configuration (ciphers, MACs, keys, etc.) on a per-session manner (see more in the *Advanced usage* section).
Furthermore, one can change almost any configured `SshClient` parameter - although its influence on currently established
sessions depends on the actual changed configuration. Here is how a typical usage would look like

```java

    SshClient client = SshClient.setupDefaultClient();
    // override any default configuration...
    client.setSomeConfiguration(...);
    client.setOtherConfiguration(...);
    client.start();

        // using the client for multiple sessions...
        try (ClientSession session = client.connect(user, host, port)
                    .verify(...timeout...)
                    .getSession()) {
            session.addPasswordIdentity(...password..); // for password-based authentication
            // or
            session.addPublicKeyIdentity(...key-pair...); // for password-less authentication
            // Note: can add BOTH password AND public key identities - depends on the client/server security setup

            session.auth().verify(...timeout...);
            // start using the session to run commands, do SCP/SFTP, create local/remote port forwarding, etc...
        }

        // NOTE: this is just an example - one can open multiple concurrent sessions using the same client.
        //      No need to close the previous session before establishing a new one
        try (ClientSession anotherSession = client.connect(otherUser, otherHost, port)
                    .verify(...timeout...)
                    .getSession()) {
            anotherSession.addPasswordIdentity(...password..); // for password-based authentication
            anotherSession.addPublicKeyIdentity(...key-pair...); // for password-less authentication
            anotherSession.auth().verify(...timeout...);
            // start using the session to run commands, do SCP/SFTP, create local/remote port forwarding, etc...
        }

    // exiting in an orderly fashion once the code no longer needs to establish SSH session
    // NOTE: this can/should be done when the application exits.
    client.stop();

```

# Embedding an SSHD server instance in 5 minutes

SSHD is designed to be easily embedded in your application as an SSH server. The embedded SSH server needs
to be configured before it can be started. Essentially, there are a few simple steps for creating the
server - for more details refer to the `SshServer` class.

## Creating an instance of the `SshServer` class

Creating an instance of `SshServer` is as simple as creating a new object

```java

    SshServer sshd = SshServer.setUpDefaultServer();

```

It will configure the server with sensible defaults for ciphers, macs, key exchange algorithm, etc...
If different behavior is required, one should consult the code of the `setUpDefaultServer` as well as
`checkConfig` methods as a reference for available options and configure the SSH server the way it is needed.

## Configuring the server instance

There are a few things that need to be configured on the server before being able to actually use it:

* Port - `sshd.setPort(22);` - sets the listen port for the server instance. If not set explicitly then a
**random** free port is selected by the O/S. In any case, once the server is `start()`-ed one can query the
instance as to the assigned port via `sshd.getPort()`.


In this context, the listen bind address can also be specified explicitly via `sshd.setHost(...some IP address...)`
that causes the server to bind to a specific network address rather than **all** addresses (the default). Using
`"0.0.0.0"` as the bind address is also tantamount to binding to all addresses.


* `KeyPairProvider` - `sshd.setKeyPairProvider(...);` - sets the host's private keys used for key exchange with
clients as well as representing the host's "identities". There are several choices - one can load keys from standard
PEM files or generate them in the code.  It's usually a good idea to save generated keys, so that if the SSHD server
is restarted, the same keys will be used to authenticate the server and avoid the warning the clients might get if
the host keys are modified. **Note**: saving key files in PEM format requires  that the [Bouncy Castle](https://www.bouncycastle.org/)
supporting artifacts be available in the code's classpath.


* `ShellFactory` - That's the part one usually has to write to customize the SSHD server. The shell factory will
be used to create a new shell each time a user logs in and wants to run an interactive shell. SSHD provides a simple
implementation that you can use if you want. This implementation will create a process and delegate everything to it,
so it's mostly useful to launch the OS native shell. E.g.,


```java

    sshd.setShellFactory(new ProcessShellFactory(new String[] { "/bin/sh", "-i", "-l" }));

```


There is an out-of-the-box `InteractiveProcessShellFactory` that detects the O/S and spawns the relevant shell. Note
that the `ShellFactory` is not required. If none is configured, any request for an interactive shell will be denied to clients.


* `CommandFactory` - The `CommandFactory` provides the ability to run a **single** direct command at a time instead
of an interactive session (it also uses a **different** channel type than shells). It can be used **in addition** to the `ShellFactory`.


SSHD provides a `CommandFactory` to support SCP that can be configured in the following way:


```java

    sshd.setCommandFactory(new ScpCommandFactory());

```

One can also use the `ScpCommandFactory` on top of one's own `CommandFactory` by placing the command factory as a **delegate**
of the `ScpCommandFactory`. The `ScpCommandFactory` will intercept SCP commands and execute them by itself, while passing all
other commands to the delegate `CommandFactory`


```java

    sshd.setCommandFactory(new ScpCommandFactory(myCommandFactory));

```

Note that using a `CommandFactory` is also **optional**. If none is configured, any direct command sent by clients will be rejected.

## Server side security setup

The SSHD server security layer has to be customized to suit your needs. This layer is pluggable and uses the following interfaces:

* `PasswordAuthenticator` for password based authentication - [RFC 4252 section 8](https://www.ietf.org/rfc/rfc4252.txt)
* `PublickeyAuthenticator` for key based authentication - [RFC 4252 section 7](https://www.ietf.org/rfc/rfc4252.txt)
* `HostBasedAuthenticator` for host based authentication - [RFC 4252 section 9](https://www.ietf.org/rfc/rfc4252.txt)
* `KeyboardInteractiveAuthenticator` for user interactive authentication - [RFC 4256](https://www.ietf.org/rfc/rfc4256.txt)


These custom classes can be configured on the SSHD server using the respective setter methods:


```java

    sshd.setPasswordAuthenticator(new MyPasswordAuthenticator());
    sshd.setPublickeyAuthenticator(new MyPublickeyAuthenticator());
    sshd.setKeyboardInteractiveAuthenticator(new MyKeyboardInteractiveAuthenticator());
    ...etc...

```

Several useful implementations are available that can be used as-is or extended in order to provide some custom behavior. In any
case, the default initializations are:

* `DefaultAuthorizedKeysAuthenticator` - uses the _authorized_keys_ file the same way as the SSH daemon does
* `DefaultKeyboardInteractiveAuthenticator` - for password-based or interactive authentication. **Note:** this authenticator
requires a `PasswordAuthenticator` to be configured since it delegates some of the functionality to it.

## Configuring ciphers, macs, digest...

SSH supports pluggable factories to define various configuration parts such as ciphers, digests, key exchange, etc...
The list of supported implementations can be changed to suit one's needs, or one can also implement one's own factories.

Configuring supported factories can be done with the following code:

```java

    sshd.setCipherFactories(Arrays.asList(BuiltinCiphers.aes256ctr, BuiltinCiphers.aes192ctr, BuiltinCiphers.aes128ctr));
    sshd.setKeyExchangeFactories(Arrays.asList(new MyKex1(), new MyKex2(), BuiltinKeyExchange.A, ...etc...));

```

One can configure other security components using built-in factories the same way. It is important to remember though
that the **order** of the factories is important as it affects the key exchange phase where the client and server decide
what options to use out of each peer's reported preferences.

## Starting the Server

Once we have configured the server, one need only call `sshd.start();`. **Note**: once the server is started, all of the
configurations (except the port) can still be *overridden* while the server is running (caveat emptor). In such cases,
only **new** clients that connect to the server after the change will be affected - with the exception of the negotiation
options (keys, macs, ciphers, etc...) which take effect the next time keys are re-exchanged, that can affect live sessions
and not only new ones.

# SSH functionality breakdown

## Security providers setup

While the code supports _BouncyCastle_ and _EdDSA_ security providers out-of-the-box,
it also provides a way to [add security providers](https://issues.apache.org/jira/browse/SSHD-713) via the `SecurityProviderRegistrar`
interface implementation. In order to add support for a new security provider one needs to implement the registrar interface and make
the code aware of it.

### Default/built-in security provider registrars

The code contains built-in security provider registrars for _BouncyCastle_ and _EdDSA_ (a.k.a. `ed25519`). It automatically detects
the existence of the required artifacts (since they are optional dependencies) and executes the respective security provider registration.
This behavior is controlled by the `org.apache.sshd.security.registrars` system property. This property contains a comma-separated list
of **fully-qualified** class names implementing the `SecurityProviderRegistrar` interface and assumed to contain a default **public**
no-arguments constructor. The code automatically parses the list and attempts to instantiate and invoke the registrar.

**Note:**


- The registration code automatically parses the configured registrars list and instantiates them. In this context, one can use the
special `none` value to indicate that the code should not attempt to automatically register the default providers.

- A registrar instance might be created but eventually discarded and not invoked if it is disabled, unsupported or already registered
programmatically via `SecurityUtils#registerSecurityProvider`.


- The registration attempt is a **one-shot** deal - i.e., once the registrars list is parsed and successfully resolved, any modifications
to the registered security providers must be done **programatically**. One can call `SecurityUtils#isRegistrationCompleted()` to find out
if the registration phase has already been executed.


- The registrars are consulted in the same **order** as they were initially registered - either programmatically or via the system property
configuration. Therefore, if two or more registrars support the same algorithm, then the earlier registered one will be used.


- If no matching registrar was found, then the default security provider is used. If none set, the JCE defaults are invoked. The default
security provider can be configured either via the `org.apache.sshd.security.defaultProvider` system property or by programmatically
invoking `SecurityUtils#setDefaultProviderChoice`. **Note:** if the system property option is used, then it is assumed to contain a security
provider's **name** (rather than its `Provider` class name...).


- If programmatic selection of the default security provider choice is required, then the code flow must ensure that
`SecurityUtils#setDefaultProviderChoice` is called before **any** security entity (e.g., ciphers, keys, etc...) are
required. Theoretically, one could change the choice after ciphers have been been requested but before keys were generated
(e.g....), but it is dangerous and may yield unpredictable behavior.


### Implementing a new security provider registrar

See `AbstractSecurityProviderRegistrar` helper class for a default implementation of most of the required functionality, as
well as the existing implementations for _BouncyCastle_ and _EdDSA_ for examples of how to implement it. The most important
issues to consider when adding such an implementation are:

* Try using reflection API to detect the existence of the registered provider class and/or instantiate it. The main reason
for this recommendation is that it isolates the code from a direct dependency on the provider's classes and makes class loading
issue less likely.


* Decide whether to use the provider's name or instance when creating security related entities such as ciphers, keys, etc...
**Note:** the default preference is to use the provider name, thus registering via `Security.addProvider` call. In order to
change that, either register the instance yourself or override the `isNamedProviderUsed` method. In this context, **cache**
the generated `Provider` instance if the instance rather than the name is used. **Note:** using only the provider instance
instead of the name is a rather new feature and has not been fully tested. It is possible though to decide and use it anyway
as long as it can be configurably disabled.


* The default implementation provides fine-grained control over the declared supported security entities - ciphers, signatures,
key generators, etc... By default, it is done via consulting a system property composed of `org.apache.sshd.security.provider`,
followed by the security provider name and the relevant security entity - e.g., `org.apache.sshd.security.provider.BC.KeyFactory`
is assumed to contain a comma-separated list of supported `KeyFactory` algorithms.

**Note:**


* The same naming convention can be used to enable/disable the registrar - even if supported - e.g.,
`org.apache.sshd.security.provider.BC.enabled=false` disables the _BouncyCastle_ registrar.


* One can use `all` or `*` to specify that all entities of the specified type are supported - e.g.,
`org.apache.sshd.security.provider.BC.MessageDigest=all`. In this context, one can override the
`getDefaultSecurityEntitySupportValue` method if no fine-grained configuration is required per-entity type,


* The result of an `isXxxSupported` call is/should be **cached** (see `AbstractSecurityProviderRegistrar`).


* For ease of implementation, all support query calls are routed to the `isSecurityEntitySupported` method
so that one can concentrate all the configuration in a single method. This is done for **convenience**
reasons - the code will invoke the correct support query as per the type of entity it needs. E.g., if it
needs a cipher, it will invoke `isCipherSupported` - which by default will invoke `isSecurityEntitySupported`
with the `Cipher` class as its argument.


* Specifically for **ciphers** the argument to the support query contains a **transformation** (e.g., `AES/CBC/NoPadding`)
so one should take that into account when parsing the input argument to decide which cipher is referenced - see
`SecurityProviderRegistrar.getEffectiveSecurityEntityName(Class<?>, String)` helper method


## `FileSystemFactory` usage

This interface is used to provide "file"-related services - e.g., SCP and SFTP - although it can be used for remote command execution
as well (see the section about commands and the `Aware` interfaces). The default implementation is a `NativeFileSystemFactory`
that simply exposes the [FileSystems.getDefault()](https://docs.oracle.com/javase/8/docs/api/java/nio/file/FileSystems.html#getDefault)
result. However, for "sandboxed" implementations one can use the `VirtualFileSystemFactory`. This implementation provides a way for
deciding what is the logged-in user's file system view and then use a `RootedFileSystemProvider` in order to provide a "sandboxed"
file system where the logged-in user can access only the files under the specified root and no others.

```java

    SshServer sshd = SshServer.setupDefaultServer();
    sshd.setFileSystemFactory(new VirtualFileSystemFactory() {
        @Override
        protected Path computeRootDir(Session session) throws IOException  {
            String username = session.getUsername(); // or any other session related parameter
            Path path = resolveUserHome(username);
            return path;
        }
    });

```

The usage of a `FileSystemFactory` is not limited though to the server only - the `ScpClient` implementation also uses
it in order to retrieve the *local* path for upload/download-ing files/folders. This means that the client side can also
be tailored to present different views for different clients

## `ExecutorService`-s

The framework requires from time to time spawning some threads in order to function correctly - e.g., commands, SFTP subsystem,
port forwarding (among others) require such support. By default, the framework will allocate an [ExecutorService](https://docs.oracle.com/javase/8/docs/api/java/util/concurrent/ExecutorService.html)
for each specific purpose and then shut it down when the module has completed its work - e.g., session was closed. Note that
SSHD uses the `CloseableExecutorService` interface instead of the usual `ExecutorService` in order to provide graceful shutdown.
Users may provide their own `CloseableExecutorService`(s) instead of the internally auto-allocated ones - e.g., in order to
control the max. spawned threads, stack size, track threads, etc... but they can leverage the `SshThreadPoolExecutor` implementation
which should cover most use cases.

Users who want to provide their own `ExecutorService` and not use `SshThreadPoolExecutor` should wrap it as a `NoCloseExecutor`
and take care of shutting it down when SSHD is done with (provided, of course, that the user's own code does not need it to
remain active afterwards...).

```java

    /*
     * An example user-provided executor service for SFTP - there are other such locations.
     * By default, the SftpSubsystem implementation creates a single-threaded executor
     * for each session, uses it to spawn the SFTP command handler and shuts
     * it down when the command is destroyed
     */
    SftpSubsystemFactory factory = new SftpSubsystemFactory.Builder()
        .withExecutorService(new NoCloseExecutor(mySuperDuperExecutorService))
        .build();
    SshServer sshd = SshServer.setupDefaultServer();
    sshd.setSubsystemFactories(Collections.<NamedFactory<Command>>singletonList(factory));

```

If a single `CloseableExecutorService` is shared between several services, it needs to be wrapped with the
`ThreadUtils.noClose(executor)` method.

```java
    CloseableExecutorService sharedService = ...obtain/create an instance...;

    SftpSubsystemFactory factory = new SftpSubsystemFactory.Builder()
        .withExecutorService(ThreadUtils.noClose(sharedService))
        .build();

   ChannelAgentForwarding forward = new ChannelAgentForwarding(ThreadUtils.noClose(sharedService));
```

**Note:** Do not share the instance returned by `ThreadUtils.noClose` between services as it interferes with
the graceful closing mechanism. Use a new wrapper instance for each service.

## Remote command execution

All command execution - be it shell or single command - boils down to a `Command` instance being created, initialized and then
started. In this context, it is **crucial** to notice that the command's `start()` method implementation **must spawn a new thread** - even
for the simplest or most trivial command. Any attempt to communicate via the established session will most likely **fail** since
the packets processing thread may be blocked by this call. **Note:** one might get away with executing some command in the
context of the thread that called the `start()` method, but it is **extremely dangerous** and should not be attempted.

The command execution code can communicate with the peer client via the input/output/error streams that are provided as
part of the command initialization process. Once the command is done, it should call the `ExitCallback#onExit` method to indicate
that it has finished. The framework will then take care of propagating the exit code, closing the session and (eventually) `destroy()`-ing
the command. **Note**: the command may not assume that it is done until its `destroy()` method is called - i.e., it should not
release or null-ify any of its internal state even if `onExit()` was called.

Upon calling the `onExit` method the code sends an [SSH_MSG_CHANNEL_EOF](https://tools.ietf.org/html/rfc4254#section-5.3) message,
and the provided result status code is sent as an `exit-status` message as described in [RFC4254 - section 6.10](https://tools.ietf.org/html/rfc4254#section-6.10).
The provided message is simply logged at DEBUG level.

```java

    // A simple command implementation example
    class MyCommand implements Command, Runnable {
        private InputStream in;
        private OutputStream out, err;
        private ExitCallback callback;

        public MyCommand() {
            super();
        }

        @Override
        public void setInputStream(InputStream in) {
            this.in = in;
        }

        @Override
        public void setOutputStream(OutputStream out) {
            this.out = out;
        }

        @Override
        public void setErrorStream(OutputStream err) {
            this.err = err;
        }

        @Override
        public void setExitCallback(ExitCallback callback) {
            this.callback = callback;
        }

        @Override
        public void start(Environment env) throws IOException {
            spawnHandlerThread(this);
        }

        @Override
        public void run() {
            while(true) {
                try {
                    String cmd = readCommand(in);
                    if ("exit".equals(cmd)) {
                        break;
                    }

                    handleCommand(cmd, out);
                } catch (Exception e) {
                    writeError(err, e);
                    callback.onExit(-1, e.getMessage());
                    return;
            }

            callback.onExit(0);
        }
    }
```

### `Aware` interfaces

Once created, the `Command` instance is checked to see if it implements one of the `Aware` interfaces that enables
injecting some dynamic data before the command is `start()`-ed.

* `SessionAware` - Injects the `Session` instance through which the command request was received.

* `ChannelSessionAware` - Injects the `ChannelSession` instance through which the command request was received.

* `FileSystemAware` - Injects the result of consulting the `FileSystemFactory` as to the [FileSystem](https://docs.oracle.com/javase/8/docs/api/java/nio/file/FileSystem.html)
associated with this command.


### Data stream(s) sizing consideration

Some commands may send/receive large amounts of data over their STDIN/STDOUT/STDERR streams. Since (by default) the sending mechanism in SSHD is
**asynchronous** it may cause _Out of memory_ errors due to one side (client/server) generating `SSH_MSG_CHANNEL_DATA` or `SSH_MSG_CHANNEL_EXTENDED_DATA`
at a much higher rate than the other side can consume. This leads to a build-up of a packets backlog that eventually consumes all available memory
(as described in [SSHD-754](https://issues.apache.org/jira/browse/SSHD-754) and [SSHD-768](https://issues.apache.org/jira/browse/SSHD-768)). As of
version 1.7 one can register a `ChannelStreamPacketWriterResolver` at the client/server/session/channel level that can enable the user to replace
the raw channel with some throttling mechanism that will be used for stream packets. Such an (experimental) example is the `ThrottlingPacketWriter`
available in the `sshd-contrib` module. **Note:** if the `ChannelStreamPacketWriterResolver` returns a wrapper instance instead of a `Channel` then
it will be **closed** automatically when the stream using it is closed.

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

## SFTP

Both client-side and server-side SFTP are supported. Starting from version 2.0, the SFTP related code is located
in the `sshd-sftp` artifact, so one needs to add this additional dependency to one's maven project:

```xml

    <dependency>
        <groupId>org.apache.sshd</groupId>
        <artifactId>sshd-sftp</artifactId>
        <version>...same as sshd-core...</version>
    </dependency>

```

### Server-side SFTP

On the server side, the following code needs to be added:

```java

    SftpSubsystemFactory factory = new SftpSubsystemFactory.Builder()
        .build();
    server.setSubsystemFactories(Collections.singletonList(factory));

```

### `SftpEventListener`

(See above more details...) - users may register an `SftpEventListener` (or more...) in the `SftpSubsystemFactory` in
order to monitor and even intervene in the susbsytem's functionality.

### Client-side SFTP

In order to obtain an `SftpClient` instance one needs to use an `SftpClientFactory`:


```java

    ClientSession session = ...obtain session...
    SftpClientFactory factory = ...obtain factory...
    SftpClient client = factory.createSftpClient(session);

```

A default client factory implementations is provided in the module - see `SftpClientFactory.instance()`


### Using a custom `SftpClientFactory`

The code creates `SftpClient`-s and `SftpFileSystem`-s using a default built-in `SftpClientFactory` instance (see
`DefaultSftpClientFactory`). Users may choose to use a custom factory in order to provide their own
implementations - e.g., in order to override some default behavior - e.g.:

```java

    SshClient client = ... setup client...

    try (ClientSession session = client.connect(user, host, port).verify(timeout).getSession()) {
        session.addPasswordIdentity(password);
        session.auth.verify(timeout);

        // User-specific factory
        try (SftpClient sftp = MySpecialSessionSftpClientFactory.INSTANCE.createSftpClient(session)) {
            ... instance created through SpecialSessionSftpClientFactory ...
        }
    }

```

### Version selection via `SftpVersionSelector`


The SFTP subsystem code supports versions 3-6 (inclusive), and by default attempts to negotiate the **highest**
possible one - on both client and server code. The user can intervene and force a specific version or a narrower
range.


```java

    SftpVersionSelector myVersionSelector = new SftpVersionSelector() {
        @Override
        public int selectVersion(ClientSession session, int current, List<Integer> available) {
            int selectedVersion = ...run some logic to decide...;
            return selectedVersion;
        }
    };

    try (ClientSession session = client.connect(user, host, port).verify(timeout).getSession()) {
        session.addPasswordIdentity(password);
        session.auth.verify(timeout);

        SftpClientFactory factory = SftpClientFactory.instance();
        try (SftpClient sftp = factory.createSftpClient(session, myVersionSelector)) {
            ... do SFTP related stuff...
        }
    }

```

On the server side, version selection restriction is more complex - please remember that the **client** chooses
the version, and all we can do at the server is require a **specific** version via the `SftpSubsystem#SFTP_VERSION`
configuration key. For more advanced restrictions one needs to sub-class `SftpSubSystem` and provide a non-default
`SftpSubsystemFactory` that uses the sub-classed code.

### Using `SftpFileSystemProvider` to create an `SftpFileSystem`


The code automatically registers the `SftpFileSystemProvider` as the handler for `sftp://` URL(s). Such URLs are
interpreted as remote file locations and automatically exposed to the user as [Path](https://docs.oracle.com/javase/8/docs/api/java/nio/file/Path.html)
objects. In effect, this allows the code to "mount" a remote directory via SFTP and treat it as if it were local using
standard [java.nio](https://docs.oracle.com/javase/8/docs/api/java/nio/package-frame.html) calls like any "ordinary" file
system.

```java

    // Direct URI
    Path remotePath = Paths.get(new URI("sftp://user:password@host/some/remote/path"));
    // Releasing the file-system once no longer necessary
    try (FileSystem fs = remotePath.getFileSystem()) {
        ... work with the remote path...
    }

    // "Mounting" a file system
    URI uri = SftpFileSystemProvider.createFileSystemURI(host, port, username, password);
    try (FileSystem fs = FileSystems.newFileSystem(uri, Collections.<String, Object>emptyMap())) {
        Path remotePath = fs.getPath("/some/remote/path");
        ...
    }

    // Full programmatic control
    SshClient client = ...setup and start the SshClient instance...
    SftpFileSystemProvider provider = new SftpFileSystemProvider(client);
    URI uri = SftpFileSystemProvider.createFileSystemURI(host, port, username, password);
    try (FileSystem fs = provider.newFileSystem(uri, Collections.<String, Object>emptyMap())) {
        Path remotePath = fs.getPath("/some/remote/path");
    }

```

 The obtained `Path` instance can be used in exactly the same way as any other "regular" one:


 ```java

    try (InputStream input = Files.newInputStream(remotePath)) {
        ...read from remote file...
    }

    try (DirectoryStream<Path> ds = Files.newDirectoryStream(remoteDir)) {
        for (Path remoteFile : ds) {
            if (Files.isRegularFile(remoteFile)) {
                System.out.println("Delete " + remoteFile + " size=" + Files.size(remoteFile));
                Files.delete(remoteFile);
            } else if (Files.isDirectory(remoteFile)) {
                System.out.println(remoteFile + " - directory");
            }
        }
    }
```

It is highly recommended to `close()` the mounted file system once no longer necessary in order to release the
associated SFTP session sooner rather than later - e.g., via a `try-with-resource` code block.

**Caveat:** Due to URI encoding of the username/password as a basic authentication, the system currently
does not allow colon (`:`) in either one in order to avoid parsing confusion. See [RFC 3986 - section 3.2.1](https://tools.ietf.org/html/rfc3986#section-3.2.1):

>> Use of the format "user:password" in the userinfo field is
>> deprecated ... Applications may choose to ignore or reject such
>> data when it is received as part of a reference...

#### Configuring the `SftpFileSystemProvider`

When "mounting" a new file system one can provide extra configuration parameters using either the
environment map in the [FileSystems#newFileSystem](https://docs.oracle.com/javase/8/docs/api/java/nio/file/FileSystems.html#newFileSystem)
method or via the URI query parameters. See the `SftpFileSystemProvider` for the available
configuration keys and values.


```java

    // Using explicit parameters
    Map<String, Object> params = new HashMap<>();
    params.put("param1", value1);
    params.put("param2", value2);
    ...etc...

    URI uri = SftpFileSystemProvider.createFileSystemURI(host, port, username, password);
    try (FileSystem fs = FileSystems.newFileSystem(uri, params)) {
        Path remotePath = fs.getPath("/some/remote/path");
        ... work with the remote path...
    }

    // Using URI parameters
    Path remotePath = Paths.get(new URI("sftp://user:password@host/some/remote/path?param1=value1&param2=value2..."));
    // Releasing the file-system once no longer necessary
    try (FileSystem fs = remotePath.getFileSystem()) {
        ... work with the remote path...
    }

```

**Note**: if **both** options are used then the URI parameters **override** the environment ones


```java

    Map<String, Object> params = new HashMap<>();
    params.put("param1", value1);
    params.put("param2", value2);

    // The value of 'param1' is overridden in the URI
    try (FileSystem fs = FileSystems.newFileSystem(new URI("sftp://user:password@host/some/remote/path?param1=otherValue1", params)) {
        Path remotePath = fs.getPath("/some/remote/path");
        ... work with the remote path...
    }

```

#### Configuring the client session used to create an `SftpFileSystem`

It is possible to register a `SftpFileSystemClientSessionInitializer` with the provider instead of the default one
and thus better control the `ClientSession` used to generate the file-system instance. The default implementation
simply connects and authenticates before creating a default `SftpFileSystem` instance. Users may wish
to override some options or provide their own - e.g., execute a password-less authentication instead of
the (default) password-based one:

```java

    SftpFileSystemProvider provider = ... obtain/create a provider ...
    provider.setSftpFileSystemClientSessionInitializer(new SftpFileSystemClientSessionInitializer() {
        @Override
        public void authenticateClientSession(
                SftpFileSystemProvider provider, SftpFileSystemInitializationContext context, ClientSession session)
                    throws IOException {
            /*
             * Set up password-less login instead of password-based using the specified key
             *
             * Note: if SSH client and/or session already have a KeyPairProvider set up and the code
             * knows that these keys are already registered with the remote server, then no need to
             * add the public key identitiy - can simply call sesssion.auth().verify(context.getMaxAuthTime()).
             */
            KeyPair kp = ... obtain a registered key-pair...
            session.addPublicKeyIdentity(kp);
            return sesssion.auth().verify(context.getMaxAuthTime());
        }
    });

```

#### Tracking accessed locations via `SftpFileSystemAccessor`

One can override the default `SftpFileSystemAccessor` and thus be able to track all opened files and folders
throughout the SFTP server subsystem code. The accessor is registered/overwritten in via the `SftpSubSystemFactory`:

```java

    SftpSubsystemFactory factory = new SftpSubsystemFactory.Builder()
        .withFileSystemAccessor(new MySftpFileSystemAccessor())
        .build();
    server.setSubsystemFactories(Collections.singletonList(factory));

```

### SFTP sent/received names encoding

By default, the SFTP client uses UTF-8 to encode/decode any referenced file/folder name. However, some servers do not properly encode such names,
and thus the "visible" names by the client become corrupted, or even worse - cause an exception upon decoding attempt. The `SftpClient` exposes
a `get/setNameDecodingCharset` method which enables the user to modify the charset - even while the SFTP session is in progress - e.g.:

```java

    try (SftpClient client = ...obtain an instance...) {
        client.setNameDecodingCharset(Charset.forName("ISO-8859-8"));
        for (DirEntry entry : client.readDir(...some path...)) {
            ...handle entry assuming ISO-8859-8 encoded names...
        }

        client.setNameDecodingCharset(Charset.forName("ISO-8859-4"));
        for (DirEntry entry : client.readDir(...some other path...)) {
            ...handle entry assuming ISO-8859-4 encoded names...
        }
    }

```

The initial charset can be pre-configured on the client/session by using the `sftp-name-decoding-charset` property - if none specified then
UTF-8 is used. **Note:** the value can be a charset name or a `java.nio.charset.Charset` instance - e.g.:

```java

    SshClient client = ... setup/obtain an instance...
    // default for ALL SFTP clients obtained through this client
    PropertyResolverUtils.updateProperty(client, SftpClient.NAME_DECODING_CHARSET, "ISO-8859-8");

    try (ClientSession session = client.connect(...)) {
         // default for ALL SFTP clients obtained through the session - overrides client setting
         PropertyResolverUtils.updateProperty(session, SftpClient.NAME_DECODING_CHARSET, "ISO-8859-4");
         session.authenticate(...);

         SftpClientFactory factory = SftpClientFactory.instance();
         try (SftpClient sftp = factory.createSftpClient(session)) {
             for (DirEntry entry : sftp.readDir(...some path...)) {
                 ...handle entry assuming ISO-8859-4 (inherited from the session) encoded names...
             }

             // override the inherited default from the session
             sftp.setNameDecodingCharset(Charset.forName("ISO-8859-1"));

             for (DirEntry entry : sftp.readDir(...some other path...)) {
                 ...handle entry assuming ISO-8859-1 encoded names...
             }
         }
    }

```

Both client and server support several of the SFTP extensions specified in various drafts:

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

Furthermore several [OpenSSH SFTP extensions](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL) are also supported:

* `fsync@openssh.com`
* `fstatvfs@openssh.com`
* `hardlink@openssh.com`
* `posix-rename@openssh.com`
* `statvfs@openssh.com`


On the server side, the reported standard extensions are configured via the `SftpSubsystem.CLIENT_EXTENSIONS_PROP` configuration
key, and the _OpenSSH_ ones via the `SftpSubsystem.OPENSSH_EXTENSIONS_PROP`.

On the client side, all the supported extensions are classes that implement `SftpClientExtension`. These classes can be used
to query the client whether the remote server supports the specific extension and then obtain a parser for its contents. Users
can easily add support for more extensions in a similar manner as the existing ones by implementing an appropriate `ExtensionParser`
and then registering it at the `ParserUtils` - see the existing ones for details how this can be achieved.


```java

    // properietary/special extension parser
    ParserUtils.registerExtension(new MySpecialExtension());

    try (ClientSession session = client.connect(username, host, port).verify(timeout).getSession()) {
        session.addPasswordIdentity(password);
        session.auth().verify(timeout);

        SftpClientFactory factory = SftpClientFactory.instance();
        try (SftpClient sftp = factory.createSftpClient(session)) {
            Map<String, byte[]> extensions = sftp.getServerExtensions();
            // Key=extension name, value=registered parser instance
            Map<String, ?> data = ParserUtils.parse(extensions);
            for (Map.Entry<String, ?> de : data.entrySet()) {
                String extName = de.getKey();
                Object extValue = de.getValue();
                if (SftpConstants.EXT_ACL_SUPPORTED.equalsIgnoreCase(extName)) {
                    AclCapabilities capabilities = (AclCapabilities) extValue;
                    ...see what other information can be gleaned from it...
                } else if (SftpConstants.EXT_VERSIONS.equalsIgnoreCase(extName)) {
                    Versions versions = (Versions) extValue;
                    ...see what other information can be gleaned from it...
                } else if ("my-special-extension".equalsIgnoreCase(extName)) {
                    MySpecialExtension special = (MySpecialExtension) extValue;
                    ...see what other information can be gleaned from it...
                } // ...etc....
            }
        }
    }

```

One can skip all the conditional code if a specific known extension is required:


```java

    try (ClientSession session = client.connect(username, host, port).verify(timeout).getSession()) {
        session.addPasswordIdentity(password);
        session.auth().verify(timeout);

        SftpClientFactory factory = SftpClientFactory.instance();
        try (SftpClient sftp = factory.createSftpClient(session)) {
            // Returns null if extension is not supported by remote server
            SpaceAvailableExtension space = sftp.getExtension(SpaceAvailableExtension.class);
            if (space != null) {
                ...use it...
            }
        }
    }

```

### Internal exceptions and error message handling

If an exception is thrown during processing of an SFTP command, then the exception is translated into a `SSH_FXP_STATUS` message
using a registered `SftpErrorStatusDataHandler`. The default implementation provides a short description of the failure based on the thrown
exception type. However, users may override it when creating the `SftpSubsystemFactory` and provide their own codes and/or messages - e.g.,
for debugging one can register a `DetailedSftpErrorStatusDataHandler` (see `sshd-contrib`) that "leaks" more information in the generated message.


## Port forwarding

### Standard port forwarding

Port forwarding as specified in [RFC 4254 - section 7](https://tools.ietf.org/html/rfc4254#section-7) is fully
supported by the client and server. From the client side, this capability is exposed via the `start/stopLocal/RemotePortForwarding`
method. The key player in this capability is the configured `ForwardingFilter` that controls this feature - on **both** sides - client
and server. By default, this capability is **disabled** - i.e., the user must provide an implementation and call the appropriate
`setForwardingFilter` method on the client/server.

The code contains 2 simple implementations - an accept-all and a reject-all one that can be used for these trivial
policies. **Note:** setting a _null_ filter is equivalent to rejecting all such attempts.

### SOCKS

The code implements a [SOCKS](https://en.wikipedia.org/wiki/SOCKS) proxy for versions 4 and 5. The proxy capability is
invoked via the `start/stopDynamicPortForwarding` methods.

### Proxy agent

The code provides to some extent an SSH proxy agent via the available `SshAgentFactory` implementations. As of latest version
both [Secure Shell Authentication Agent Protocol Draft 02](https://tools.ietf.org/html/draft-ietf-secsh-agent-02) and its
[OpenSSH](https://www.libssh.org/features/) equivalent are supported. **Note:** in order to support this feature the
[Apache Portable Runtime Library](https://apr.apache.org/) needs to be added to the Maven dependencies:

```xml

    <dependency>
        <groupId>tomcat</groupId>
        <artifactId>tomcat-apr</artifactId>
    </dependency>

```

**Note:** Since the portable runtime library uses **native** code, one needs to also make sure that the appropriate _.dll/.so_ library
is available in the LD\_LIBRARY\_PATH.

# Advanced configuration and interaction

## Properties and inheritance model
The code's behavior is highly customizable not only via non-default implementations of interfaces but also as far as
the **parameters** that govern its behavior - e.g., timeouts, min./max. values, allocated memory size, etc... All the
customization related code flow implements a **hierarchical** `PropertyResolver` inheritance model where the "closest"
entity is consulted first, and then its "owner", and so on until the required value is found. If the entire hierarchy
yielded no specific result, then some pre-configured default is used. E.g., if a channel requires some parameter in order
to decide how to behave, then the following configuration hierarchy is consulted:

* The channel-specific configuration
* The "owning" session configuration
* The "owning" client/server instance configuration
* The system properties - **Note:** any configuration value required by the code can be provided via a system property bearing
the `org.apache.sshd.config` prefix - see `SyspropsMapWrapper` for the implementation details.


### Using the inheritance model for fine-grained/targeted configuration

As previously mentioned, this hierarchical lookup model is not limited to "simple" configuration values (strings, integers, etc.), but
used also for **interfaces/implementations** such as cipher/MAC/compression/authentication/etc. factories - the exception being that
the system properties are not consulted in such a case. This code behavior provides highly customizable fine-grained/targeted control
of the code's behavior - e.g., one could impose usage of specific ciphers/authentication methods/etc. or present different public key
"identities"/welcome banner behavior/etc., based on address, username or whatever other decision parameter is deemed relevant by the
user's code. This can be done on __both__ sides of the connection - client or server. E.g., the client could present different keys
based on the server's address/identity string/welcome banner, or the server could accept only specific types of authentication methods
based on the client's address/username/etc... This can be done in conjunction with the usage of the various `EventListener`-s provided
by the code (see below).

One of the code locations where this behavior can be leveraged is when the server provides __file-based__ services (SCP, SFTP) in
order to provide a different/limited view of the available files based on the username - see the section dealing with `FileSystemFactory`-ies.

## Welcome banner configuration

According to [RFC 4252 - section 5.4](https://tools.ietf.org/html/rfc4252#section-5.4) the server may send a welcome
banner message during the authentication process. Both the message contents and the phase at which it is sent can be
configured/customized.

### Welcome banner content customization

The welcome banner contents are controlled by the `ServerAuthenticationManager.WELCOME_BANNER` configuration
key - there are several possible values for this key:

* A simple string - in which case its contents are the welcome banner.


* A file [URI](https://docs.oracle.com/javase/8/docs/api/java/net/URI.html) - or a string starting with `"file:/"` followed by the file path - see below.


* A [URL](https://docs.oracle.com/javase/8/docs/api/java/net/URL.html) - or a string containing "://" - in which
case the [URL#openStream()](https://docs.oracle.com/javase/8/docs/api/java/net/URL.html#openStream) method is invoked
and its contents are read.


* A [File](https://docs.oracle.com/javase/8/docs/api/java/io/File.html) or
a [Path](https://docs.oracle.com/javase/8/docs/api/java/nio/file/Path.html) - in this case, the file's contents are __re-loaded__ every time it is required and sent as the banner contents.


* The special value `ServerAuthenticationManager.AUTO_WELCOME_BANNER_VALUE` which generates a combined "random art" of
all the server's keys as described in `Perrig A.` and `Song D.`-s article
[Hash Visualization: a New Technique to improve Real-World Security](http://sparrow.ece.cmu.edu/~adrian/projects/validation/validation.pdf) - _International Workshop on Cryptographic Techniques and E-Commerce (CrypTEC '99)_


* One can also override the `ServerUserAuthService#resolveWelcomeBanner` method and use whatever other content customization one sees fit.

**Note:**


1. If any of the sources yields an empty string or is missing (in the case of a resource) then no welcome banner message is sent.

2. If the banner is loaded from a file or URL resource, then one can configure the [Charset](https://docs.oracle.com/javase/8/docs/api/java/nio/charset/Charset.html) used to convert the file's contents into a string via the `ServerAuthenticationManager.WELCOME_BANNER_CHARSET` configuration key (default=`UTF-8`).

3. In this context, see also the `ServerAuthenticationManager.WELCOME_BANNER_LANGUAGE` configuration key - which
provides control over the declared language tag, although most clients seem to ignore it.


### Welcome banner sending phase

According to [RFC 4252 - section 5.4](https://tools.ietf.org/html/rfc4252#section-5.4):

> The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any time after this authentication protocol starts and before authentication is successful.


The code contains a `WelcomeBannerPhase` enumeration that can be used to configure via the `ServerAuthenticationManager.WELCOME_BANNER_PHASE`
configuration key the authentication phase at which the welcome banner is sent (see also the `ServerAuthenticationManager.DEFAULT_BANNER_PHASE` value).
In this context, note that if the `NEVER` phase is configured, no banner will be sent even if one has been configured via one of the methods mentioned previously.


## `HostConfigEntryResolver`

This interface provides the ability to intervene during the connection and authentication phases and "re-write"
the user's original parameters. The `DefaultConfigFileHostEntryResolver` instance used to set up the default
client instance follows the [SSH config file](https://www.digitalocean.com/community/tutorials/how-to-configure-custom-connection-options-for-your-ssh-client)
standards, but the interface can be replaced so as to implement whatever proprietary logic is required.


```java

    SshClient client = SshClient.setupDefaultClient();
    client.setHostConfigEntryResolver(new MyHostConfigEntryResolver());
    client.start();

    /*
     * The resolver might decide to connect to some host2/port2 using user2 and password2
     * (or maybe using some key instead of the password).
     */
    try (ClientSession session = client.connect(user1, host1, port1).verify(...timeout...).getSession()) {
        session.addPasswordIdentity(...password1...);
        session.auth().verify(...timeout...);
    }
```


## `SshConfigFileReader`

Can be used to read various standard SSH [client](http://linux.die.net/man/5/ssh_config)
or [server](http://manpages.ubuntu.com/manpages/precise/en/man5/sshd_config.5.html) configuration files
and initialize the client/server respectively. Including (among other things), bind address, ciphers,
signature, MAC(s), KEX protocols, compression, welcome banner, etc..

## Event listeners

The code supports registering many types of event listeners that enable receiving notifications about important events
as well as sometimes intervening in the way these events are handled. All listener interfaces extend `SshdEventListener`
so they can be easily detected and distinguished from other `EventListener`(s).

In general, event listeners are **cumulative** - e.g., any channel event listeners registered on the `SshClient/Server` are
automatically added to all sessions, *in addition* to any such listeners registered on the `Session`, as well as any specific
listeners registered on a specific `Channel` - e.g.,


```java

    // Any channel event will be signalled to ALL the registered listeners
    sshClient/Server.addChannelListener(new Listener1());
    sshClient/Server.addSessionListener(new SessionListener() {
        @Override
        public void sessionCreated(Session session) {
            session.addChannelListener(new Listener2());
            session.addChannelListener(new ChannelListener() {
                @Override
                public void channelInitialized(Channel channel) {
                    channel.addChannelListener(new Listener3());
                }
            });
        }
    });

```

### `IoServiceEventListener`

This listener provides low-level events regarding connection establishment (by the client) or acceptance (by the server). The listener is registered
on the `IoServiceFactory` via the `FactoryManager`-s (i.e., `SshClient/Server#setIoServiceEventListener`). Unlike other listeners defined in this
section, it is **not cumulative** - i.e., one can `setIoServiceEventListener` but not `addIoServiceEventListener` - thus **replacing** any previously
registered listener.

### `SessionListener`

Informs about session related events. One can modify the session - although the modification effect depends on the session's **state**. E.g., if one
changes the ciphers *after* the key exchange (KEX) phase, then they will take effect only if the keys are re-negotiated. It is important to read the
documentation very carefully and understand at which stage each listener method is invoked and what are the repercussions of changes at that stage.
In this context, it is worth mentioning that one can attach to sessions **arbitrary attributes** that can be retrieved by the user's code later on:


```java

    public static final AttributeKey<String> STR_KEY = new AttributeKey<>();
    public static final AttributeKey<Long> LONG_KEY = new AttributeKey<>();

    sshClient/Server.addSessionListener(new SessionListener() {
        @Override
        public void sessionCreated(Session session) {
            session.setAttribute(STR_KEY, "Some string value");
            session.setAttribute(LONG_KEY, 3777347L);
            // ...etc...
        }

        @Override
        public void sessionClosed(Session session) {
            String str = session.getAttribute(STR_KEY);
            Long l = session.getAttribute(LONG_KEY);
            // ... do something with the retrieved attributes ...
        }
    });
```

### `ChannelListener`


Informs about channel related events - as with sessions, once can influence the channel to some extent, depending on the channel's **state**.
The ability to influence channels is much more limited than sessions. In this context, it is worth mentioning that one can attach to channels
**arbitrary attributes** that can be retrieved by the user's code later on - same was as it is done for sessions.


### `UnknownChannelReferenceHandler`


Invoked whenever a message intended for an unknown channel is received. By default, the code **ignores** the vast majority of such messages
and logs them at DEBUG level. For a select few types of messages the code generates an `SSH_CHANNEL_MSG_FAILURE` packet that is sent to the
peer session - see `DefaultUnknownChannelReferenceHandler` implementation. The user may register handlers at any level - client/server, session
and/or connection service - the one registered "closest" to connection service will be used.


### `SignalListener`

Informs about signal requests as described in [RFC 4254 - section 6.9](https://tools.ietf.org/html/rfc4254#section-6.9), break requests
(sent as SIGINT) as described in [RFC 4335](https://tools.ietf.org/html/rfc4335) and "window-change" (sent as SIGWINCH) requests as described
in [RFC 4254 - section 6.7](https://tools.ietf.org/html/rfc4254#section-6.7)


### `SftpEventListener`

Provides information about major SFTP protocol events. The provided `File/DirectoryHandle` to the various callbacks an also be used to
store user-defined attributes via its `AttributeStore` implementation. The listener is registered at the `SftpSubsystemFactory`:


```java
    public class MySfpEventListener implements SftpEventListener {
        private static final AttributeKey<SomeType> MY_SPECIAL_KEY = new Attribute<SomeType>();

        ...
        @Override
        public void opening(ServerSession session, String remoteHandle, Handle localHandle) throws IOException {
            localHandle.setAttribute(MY_SPECIAL_KEY, instanceOfSomeType);
        }

        @Override
        public void writing(
                ServerSession session, String remoteHandle, FileHandle localHandle,
                long offset, byte[] data, int dataOffset, int dataLen)
                    throws IOException {
            SomeType myData = localHandle.getAttribute(MY_SPECIAL_KEY);
            ...do something based on my data...
        }
    }


    SftpSubsystemFactory factory = new SftpSubsystemFactory();
    factory.addSftpEventListener(new MySftpEventListener());
    sshd.setSubsystemFactories(Collections.<NamedFactory<Command>>singletonList(factory));

```

**Note:** the attached attributed are automatically removed once handle has been closed - regardless of
whether the close attempt was successful or not. In other words, after `SftpEventListener#closed` has been
called, all attributes associated with the handle are cleared.

### `PortForwardingEventListener`

Informs and allows tracking of port forwarding events as described in [RFC 4254 - section 7](https://tools.ietf.org/html/rfc4254#section-7)
as well as the (simple) [SOCKS](https://en.wikipedia.org/wiki/SOCKS) protocol (versions 4, 5). In this context, one can create a
`PortForwardingTracker` that can be used in a `try-with-resource` block so that the set up forwarding is automatically torn down when
the tracker is `close()`-d:


```java

    try (ClientSession session = client.connect(user, host, port).verify(...timeout...).getSession()) {
        session.addPasswordIdentity(password);
        session.auth().verify(...timeout...);

        try (PortForwardingTracker tracker = session.createLocal/RemotePortForwardingTracker(...)) {
            ...do something that requires the tunnel...
        }

        // Tunnel is torn down when code reaches this point
    }
```


### `ScpTransferEventListener`

Inform about SCP related events. `ScpTransferEventListener`(s) can be registered on *both* client and server side:


```java

    // Server side
    ScpCommandFactory factory = new ScpCommandFactory(...with/out delegate..);
    factory.addEventListener(new MyServerSideScpTransferEventListener());
    sshd.setCommandFactory(factory);

    // Client side
    try (ClientSession session = client.connect(user, host, port).verify(...timeout...).getSession()) {
        session.addPasswordIdentity(password);
        session.auth().verify(...timeout...);

        ScpClient scp = session.createScpClient(new MyClientSideScpTransferEventListener());
        ...scp.upload/download...
    }
```

### Reserved messages

The implementation can be used to intercept and process the [SSH_MSG_IGNORE](https://tools.ietf.org/html/rfc4253#section-11.2),
[SSH_MSG_DEBUG](https://tools.ietf.org/html/rfc4253#section-11.3) and [SSH_MSG_UNIMPLEMENTED](https://tools.ietf.org/html/rfc4253#section-11.4)
messages. The handler can be registered on either side - server or client, as well as on the session. A special
[patch](https://issues.apache.org/jira/browse/SSHD-699) has been introduced that automatically ignores such messages
if they are malformed - i.e., they never reach the handler.

#### SSH message stream "stuffing" and keys re-exchange

[RFC 4253 - section 9](https://tools.ietf.org/html/rfc4253#section-9) recommends re-exchanging keys every once in a while
based on the amount of traffic and the selected cipher - the matter is further clarified in [RFC 4251 - section 9.3.2](https://tools.ietf.org/html/rfc4251#section-9.3.2).
These recommendations are mirrored in the code via the `FactoryManager` related `REKEY_TIME_LIMIT`, `REKEY_PACKETS_LIMIT`
and `REKEY_BLOCKS_LIMIT` configuration properties that can be used to configure said behavior - please be sure to read
the relevant _Javadoc_ as well as the aforementioned RFC section(s) when manipulating them. This behavior can also be
controlled programmatically by overriding the `AbstractSession#isRekeyRequired()` method.

As an added security mechanism [RFC 4251 - section 9.3.1](https://tools.ietf.org/html/rfc4251#section-9.3.1) recommends adding
"spurious" [SSH_MSG_IGNORE](https://tools.ietf.org/html/rfc4253#section-11.2) messages. This functionality is mirrored in the
`FactoryManager` related `IGNORE_MESSAGE_FREQUENCY`, `IGNORE_MESSAGE_VARIANCE` and `IGNORE_MESSAGE_SIZE`
configuration properties that can be used to configure said behavior - please be sure to read the relevant _Javadoc_ as well
as the aforementioned RFC section when manipulating them. This behavior can also be controlled programmatically by overriding
the `AbstractSession#resolveIgnoreBufferDataLength()` method.

#### `ReservedSessionMessagesHandler`

Can be used to handle the following cases:

* [SSH_MSG_IGNORE](https://tools.ietf.org/html/rfc4253#section-11.2)
* [SSH_MSG_DEBUG](https://tools.ietf.org/html/rfc4253#section-11.3)
* [SSH_MSG_UNIMPLEMENTED](https://tools.ietf.org/html/rfc4253#section-11.4)
* Any other unrecognized message received in the session.

**Note:** The `handleUnimplementedMessage` method serves both for handling `SSH_MSG_UNIMPLEMENTED` and any other unrecognized
message received in the session as well.


```java

    class MyClientSideReservedSessionMessagesHandler implements ReservedSessionMessagesHandler {
        @Override
        public boolean handleUnimplementedMessage(Session session, int cmd, Buffer buffer) throws Exception {
            switch(cmd) {
                case MY_SPECIAL_CMD1:
                    ....
                    return true;
                case MY_SPECIAL_CMD2:
                    ....
                    return true;
                default:
                    return false;    // send SSH_MSG_UNIMPLEMENTED reply if necessary
            }
        }
    }

    // client side
    SshClient client = SshClient.setupDefaultClient();
    // This is the default for ALL sessions unless specifically overridden
    client.setReservedSessionMessagesHandler(new MyClientSideReservedSessionMessagesHandler());
    // Adding it via a session listener
    client.setSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                // Overrides the one set at the client level.
                if (isSomeSessionOfInterest(session)) {
                    session.setReservedSessionMessagesHandler(new MyClientSessionReservedSessionMessagesHandler(session));
                }
            }
    });

    try (ClientSession session = client.connect(user, host, port).verify(...timeout...).getSession()) {
        // setting it explicitly
        session.setReservedSessionMessagesHandler(new MyOtherClientSessionReservedSessionMessagesHandler(session));
        session.addPasswordIdentity(password);
        session.auth().verify(...timeout...);

        ...use the session...
    }


    // server side
    SshServer server = SshServer.setupDefaultServer();
    // This is the default for ALL sessions unless specifically overridden
    server.setReservedSessionMessagesHandler(new MyServerSideReservedSessionMessagesHandler());
    // Adding it via a session listener
    server.setSessionListener(new SessionListener() {
            @Override
            public void sessionCreated(Session session) {
                // Overrides the one set at the server level.
                if (isSomeSessionOfInterest(session)) {
                    session.setReservedSessionMessagesHandler(new MyServerSessionReservedSessionMessagesHandler(session));
                }
            }
    });

```

**NOTE:** Unlike "regular" event listeners, the handler is not cumulative - i.e., setting it overrides the previous instance
rather than being accumulated. However, one can use the `EventListenerUtils` and create a cumulative listener - see how
`SessionListener` or `ChannelListener` proxies were implemented.


### `RequestHandler`(s)

The code supports both [global](https://tools.ietf.org/html/rfc4254#section-4) and [channel-specific](https://tools.ietf.org/html/rfc4254#section-5.4)
requests via the registration of `RequestHandler`(s). The global handlers are derived from `ConnectionServiceRequestHandler`(s) whereas the channel-specific
ones are derived from `ChannelRequestHandler`(s). In order to add a handler one need only register the correct implementation and handle the request when
it is detected. For global request handlers this is done by registering them on the server:

```java

    // NOTE: the following code can be employed on BOTH client and server - the example is for the server
    SshServer server = SshServer.setUpDefaultServer();
    List<RequestHandler<ConnectionService>> oldGlobals = server.getGlobalRequestHandlers();
    // Create a copy in case current one is null/empty/un-modifiable
    List<RequestHandler<ConnectionService>> newGlobals = new ArrayList<>();
    if (GenericUtils.size(oldGlobals) > 0) {
        newGlobals.addAll(oldGLobals);
    }
    newGlobals.add(new MyGlobalRequestHandler());
    server.setGlobalRequestHandlers(newGlobals);

```

For channel-specific requests, one uses the channel's `add/removeRequestHandler` method to manage its handlers. The way
request handlers are invoked when a global/channel-specific request is received  is as follows:

* All currently registered handlers' `process` method is invoked with the request type string parameter (among others).
The implementation should examine the request parameters and decide whether it is able to process it.


* If the handler returns `Result.Unsupported` then the next registered handler is invoked.
In other words, processing stops at the **first** handler that returned a valid response. Thus the importance of
the `List<RequestHandler<...>>` that defines the **order** in which the handlers are invoked. **Note**: while
it is possible to register multiple handlers for the same request and rely on their order, it is highly recommended
to avoid this situation as it makes debugging the code and diagnosing problems much more difficult.


* If no handler reported a valid result value then a failure message is sent back to the peer. Otherwise, the returned
result is translated into the appropriate success/failure response (if the sender asked for a response). In this context,
the handler may choose to build and send the response within its own code, in which case it should return the
`Result.Replied` value indicating that it has done so.


```java

    public class MySpecialChannelRequestHandler implements ChannelRequestHandler {
        ...

        @Override
        public Result process(Channel channel, String request, boolean wantReply, Buffer buffer) throws Exception {
            if (!"my-special-request".equals(request)) {
               return Result.Unsupported;   // Not mine - maybe someone else can handle it
            }

            ...handle the request - can read more parameters from the message buffer...

            return Result.ReplySuccess/Failure/Replied; // signal processing result
        }
    }
```


#### Default registered handlers

* `exit-signal`, `exit-status` - As described in [RFC4254 section 6.10](https://tools.ietf.org/html/rfc4254#section-6.10)


* `*@putty.projects.tartarus.org` - As described in [Appendix F: SSH-2 names specified for PuTTY](http://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixF.html)


* `hostkeys-prove-00@openssh.com`, `hostkeys-00@openssh.com` - As described in [OpenSSH protocol - section 2.5](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)


* `tcpip-forward`, `cancel-tcpip-forward` - As described in [RFC4254 section 7](https://tools.ietf.org/html/rfc4254#section-7)


* `keepalive@*` - Used by many implementations (including this one) to "ping" the peer and make sure the connection is still alive.
In this context, the SSHD code allows the user to configure both the frequency and content of the heartbeat request (including whether
to send this request at all) via the `ClientFactoryManager`-s `HEARTBEAT_INTERVAL`, `HEARTBEAT_REQUEST` and `DEFAULT_KEEP_ALIVE_HEARTBEAT_STRING`
configuration properties.


* `no-more-sessions@*` - As described in [OpenSSH protocol section 2.2](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL).
In this context, the code consults the `ServerFactoryManagder.MAX_CONCURRENT_SESSIONS` server-side configuration property in order to
decide whether to accept a successfully authenticated session.


# Extension modules

There are several extension modules available - specifically, the _sshd-contrib_ module contains some of them. **Note:** the
module contains experimental code that may find its way some time in the future to a standard artifact. It is also subject to
changes and/or deletion without any prior announcement. Therefore, any code that relies on it should also store a copy of the
sources in case the classes it used it are modified or deleted.

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

## GIT support

The _sshd-git_ artifact contains both client and server-side command factories for issuing and handling some _git_ commands. The code is based
on [JGit](https://github.com/eclipse/jgit) and iteracts with it smoothly.

### Client-side

This module provides SSHD-based replacements for the SSH and SFTP transports used by the JGIT client - see `GitSshdSessionFactory` - it
can be used as a drop-in replacement for the [JSCH](http://www.jcraft.com/jsch/) based built-in session factory provided by _jgit_. In
this context, it is worth noting that the `GitSshdSessionFactory` has been tailored so as to provide flexible control over which `SshClient`
instance to use, and even which `ClientSession`. The default instance allocates a **new** client every time a new `GitSshdSession` is
created - which is started and stopped as necessary. However, this can be pretty wasteful, so if one intends to issue several commands
that access GIT repositories via SSH, one should maintain a **single** client instance and re-use it:


```java

    SshClient client = ...create and setup the client...
    try {
        client.start();

        GitSshdSessionFactory sshdFactory = new GitSshdSessionFactory(client);  // re-use the same client for all SSH sessions
        org.eclipse.jgit.transport.SshSessionFactory.setInstance(sshdFactory);  // replace the JSCH-based factory

        ... issue GIT commands that access remote repositories via SSH ....

    } finally {
        client.stop();
    }

```

### Server-side

See `GitPackCommandFactory` and `GitPgmCommandFactory` - in order for the various commands to function correctly, they require a `GitLocationResolver`
that is invoked in order to allow the user to decide which is the correct GIT repository root location for a given command. The resolver is provided
with all the relevant details - including the command and server session through which the command was received:


```java

    GitLocationResolver resolver = (cmd, session, fs) -> ...consult some code - perhaps based on the authenticated username...
    sshd.setCommandFactory(new GitPackCommandFactory().withGitLocationResolver(resolver));

```

 These command factories also accept a delegate to which non-_git_ commands are routed:


```java

    sshd.setCommandFactory(new GitPackCommandFactory()
        .withDelegate(new MyCommandFactory())
        .withGitLocationResolver(resolver));

    // Here is how it looks if SCP is also requested
    sshd.setCommandFactory(new GitPackCommandFactory()
        .withDelegate(new ScpCommandFactory()
            .withDelegate(new MyCommandFactory()))
        .withGitLocationResolver(resolver));

    // or
    sshd.setCommandFactory(new ScpCommandFactory()
        .withDelegate(new GitPackCommandFactory()
            .withDelegate(new MyCommandFactory())
            .withGitLocationResolver(resolver)));

    // or any other combination ...

```

as with all other built-in commands, the factories allow the user to provide an `ExecutorService` in order to control the spawned threads
for servicing the commands. If none provided, an internal single-threaded "pool" is created ad-hoc and destroyed once the command execution
is completed (regardless of whether successful or not):


```java

    sshd.setCommandFactory(new GitPackCommandFactory(resolver)
        .withDelegate(new MyCommandFactory())
        .withExecutorService(myService)
        .withShutdownOnExit(false));

```


## LDAP adaptors

The _sshd-ldap_ artifact contains an [LdapPasswordAuthenticator](https://issues.apache.org/jira/browse/SSHD-607) and
an [LdapPublicKeyAuthenticator](https://issues.apache.org/jira/browse/SSHD-608) that have been written along the same
lines as the [openssh-ldap-publickey](https://github.com/AndriiGrytsenko/openssh-ldap-publickey) project. The authenticators
can be easily configured to match most LDAP schemes, or alternatively serve as base classes for code that extends them
and adds proprietary logic.

## PROXY / SSLH protocol hooks

The code contains [support for "wrapper" protocols](https://issues.apache.org/jira/browse/SSHD-656) such
as [PROXY](http://www.haproxy.org/download/1.6/doc/proxy-protocol.txt) or [sslh](http://www.rutschle.net/tech/sslh.shtml).
The idea is that one can register either a `ClientProxyConnector` or `ServerProxyAcceptor` and intercept
the 1st packet being sent/received (respectively) **before** it reaches the SSHD code. This gives the programmer
the capability to write a front-end that routes outgoing/incoming packets:

* `SshClient/ClientSesssion#setClientProxyConnector` - sets a proxy that intercepts the 1st packet before being sent to the server

* `SshServer/ServerSession#setServerProxyAcceptor` - sets a proxy that intercept the 1st incoming packet before being processed by the server

## Configuration/data files parsing support

Most of the configuration data files parsing support resides in the _sshd-common_ artfiact:

```xml
    <dependency>
        <groupId>org.apache.sshd</groupId>
        <artifactId>sshd-common</artifactId>
        <version>...same version as the rest of the artifacts...</version>
    </dependency>
```

The code contains support for parsing the [_authorized_keys_](http://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT),
[_known\_hosts_](http://www.manpagez.com/man/8/sshd/), [_ssh\_config_, _sshd\_config_](https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5),
and [_~/config_](http://www.gsp.com/cgi-bin/man.cgi?topic=ssh_config) files. The code resides in the _sshd-common_ artifact - specifically
the `KeyUtils#getPublicKeyEntryDecoder`, `AuthorizedKeyEntry#readAuthorizedKeys`, `KnownHostEntry#readKnownHostEntries`
and `HostConfigEntry#readHostConfigEntries`.

### PEM/OpenSSH

The common code contains built-in support for parsing PEM and/or _OpenSSH_ formatted key files and using them for authentication purposes.
As mentioned previously, it can leverage _Bouncycastle_ if available, but can do most of the work without it as well. For _ed25519_ support,
one must provide the _eddsa_ artifact dependency.

### [PUTTY](https://www.putty.org/)

The code contains built-in support for parsing PUTTY key files (usually _.ppk_) and using them same as SSH ones as key-pair
providers for autentication purposes. The PUTTY key file(s) readers are contained in the `org.apache.sshd.common.config.keys.loader.putty`
package (specifically `PuttyKeyUtils#DEFAULT_INSTANCE KeyPairResourceParser`) of the _sshd-putty_ artifact. **Note:** the artifact should
be included as an extra dependency:

```xml
    <dependency>
        <groupId>org.apache.sshd</groupId>
        <artifactId>sshd-putty</artifactId>
        <version>...same version as the rest of the artifacts...</version>
    </dependency>
```

### [OpenPGP](https://www.openpgp.org/)

The code contains the _sshd-openpgp_ module that enables using _OpenPGP_ private key files as identity providers.

```xml
    <dependency>
        <groupId>org.apache.sshd</groupId>
        <artifactId>sshd-openpgp</artifactId>
        <version>...same version as the rest of the artifacts...</version>
    </dependency>
```

The [support](https://issues.apache.org/jira/browse/SSHD-757) for it is currently still in its infancy, and therefore
this feature should be considered **experimental** for the time being. However, within its limitations it supports

* RSA keys
* DSA keys
* ECDSA keys

(*) For now `ed25519` keys are not supported by this module.

The code reads **all** the available key pairs in the key file without any distinction between encryption, decryption,
authentication or signature ones.

This code relies on the [jpgpgj](https://github.com/justinludwig/jpgpj) support module

```xml
    <dependency>
        <groupId>org.c02e.jpgpj</groupId>
        <artifactId>jpgpj</artifactId>
        <version>0.5</version>
    </dependency>
```

(which in turn automatically uses _Bouncycastle_ - so if one does not want _Bouncycastle_ one cannot use this module).

#### Using OpenPGP authorized keys entries

In order to be able to read `authorized_keys` files that may contain _OpenPGP_ keys references, one needs to register
the relevant `PublicKeyEntryDataResolver`-s. This is done by calling `PGPPublicKeyEntryDataResolver#registerDefaultKeyEntryDataResolvers`
once during the _main_ code setup. This will enable the code to safely read authorized keys entries having the format
specified in the [OpenSSH PGP configuration](https://www.red-bean.com/~nemo/openssh-gpg/):

```
    pgp-sign-dss 87C36E60187451050A4F26B134824FC95C781A18 with-comment
    pgp-sign-rsa 87C36E60187451050A4F26B134824FC95C781A18
```

Where the key data following the key type specification is the fingerprint value of the referenced key. In order to
use a "mixed mode" file (i.e., one that has both SSH and _OpenPGP_ keys) one needs to replace the default `AuthorizedKeysAuthenticator`
instance with one that is derived from it and overrides the `createDelegateAuthenticator` method in a manner similar
as shown below:

```java
// Using PGPAuthorizedEntriesTracker
public class MyAuthorizedKeysAuthenticatorWithBothPGPAndSsh extends AuthorizedKeysAuthenticator {
    ... constructor(s) ...

    @Override
    protected PublickeyAuthenticator createDelegateAuthenticator(
            String username, ServerSession session, Path path,
            Collection<AuthorizedKeyEntry> entries, PublicKeyEntryResolver fallbackResolver)
                throws IOException, GeneralSecurityException {
        PGPAuthorizedEntriesTracker tracker = ... obtain an instance ...
        // Note: need to catch the PGPException and transform it into either an IOException or a GeneralSecurityException
        Collection<PublicKey> keys = tracker.resolveAuthorizedEntries(session, entries, fallbackResolver);
        if (GenericUtils.isEmpty(keys)) {
            return RejectAllPublickeyAuthenticator.INSTANCE;
        } else {
            return new KeySetPublickeyAuthenticator(id, keys);
        }
    }
}

// Using PGPPublicRingWatcher
public class MyAuthorizedKeysAuthenticatorWithBothPGPAndSsh extends AuthorizedKeysAuthenticator {
    ... constructor(s) ...

    @Override
    protected PublickeyAuthenticator createDelegateAuthenticator(
            String username, ServerSession session, Path path,
            Collection<AuthorizedKeyEntry> entries, PublicKeyEntryResolver fallbackResolver)
                throws IOException, GeneralSecurityException {
        PGPPublicRingWatcher watcher = ... obtain an instance ...
        // Note: need to catch the PGPException and transform it into either an IOException or a GeneralSecurityException
        Collection<PublicKey> keys = watcher.resolveAuthorizedEntries(session, entries, fallbackResolver);
        if (GenericUtils.isEmpty(keys)) {
            return RejectAllPublickeyAuthenticator.INSTANCE;
        } else {
            return new KeySetPublickeyAuthenticator(id, keys);
        }
    }
}

```

**Note:** seems that currently, this capability is limited to v1.x key rings (see [jpgpj - issue 21](https://github.com/justinludwig/jpgpj/issues/21))

## Useful extra components in _sshd-contrib_

* `InteractivePasswordIdentityProvider` - helps implement a `PasswordIdentityProvider` by delegating calls
to `UserInteraction#getUpdatedPassword`. The way to use it would be as follows:


```java
try (ClientSession session = client.connect(login, host, port).await().getSession()) {
     session.setUserInteraction(...);     // this can also be set at the client level
     PasswordIdentityProvider passwordIdentityProvider =
          InteractivePasswordIdentityProvider.providerOf(session, "My prompt");
     session.setPasswordIdentityProvider(passwordIdentityProvider);
     session.auth.verify(...timeout...);
     ... continue with the authenticated session ...
}
```

or


```java
UserInteraction ui = ....;
try (ClientSession session = client.connect(login, host, port).await().getSession()) {
    PasswordIdentityProvider passwordIdentityProvider =
         InteractivePasswordIdentityProvider.providerOf(session, ui, "My prompt");
    session.setPasswordIdentityProvider(passwordIdentityProvider);
    session.auth.verify(...timeout...);
     ... continue with the authenticated session ...
}
```


**Note:** `UserInteraction#isInteractionAllowed` is consulted prior to invoking `getUpdatedPassword` - if it
returns _false_ then password retrieval method is not invoked, and it is assumed that no more passwords are available


* `SimpleAccessControlScpEventListener` - Provides a simple access control by making a distinction between
methods that upload data and ones that download it via SCP. In order to use it, simply extend it and override
its `isFileUpload/DownloadAllowed` methods


* `SimpleAccessControlSftpEventListener` - Provides a simple access control by making a distinction between
methods that provide SFTP file information - including reading data - and those that modify it


* `ProxyProtocolAcceptor` - A working prototype to support the PROXY protocol as described in
[HAProxy Documentation](http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt)


* `ThrottlingPacketWriter` - An example of a way to overcome big window sizes when sending data - as
described in [SSHD-754](https://issues.apache.org/jira/browse/SSHD-754) and [SSHD-768](https://issues.apache.org/jira/browse/SSHD-768)

* `AndroidOpenSSLSecurityProviderRegistrar` - A security registrar that uses the [AndroidOpenSSL](https://github.com/guardianproject/openssl-android)
security provider

# Builtin components

Below is the list of builtin components:

* **Ciphers**: aes128cbc, aes128ctr, aes192cbc, aes192ctr, aes256cbc, aes256ctr, arcfour128, arcfour256, blowfishcbc, tripledescbc
* **Digests**: md5, sha1, sha224, sha384, sha512
* **Macs**: hmacmd5, hmacmd596, hmacsha1, hmacsha196, hmacsha256, hmacsha512
* **Key exchange**: dhg1, dhg14, dhgex, dhgex256, ecdhp256, ecdhp384, ecdhp521
* **Compressions**: none, zlib, zlib@openssh.com
* **Signatures/Keys**: ssh-dss, ssh-rsa, nistp256, nistp384, nistp521, ed25519 (requires `eddsa` optional module)
