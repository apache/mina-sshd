# [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)

# [Version 2.2.0 to 2.3.0](./docs/changes/2.3.0.md)

# [Version 2.3.0 to 2.4.0](./docs/changes/2.4.0.md)

# [Version 2.4.0 to 2.5.0](./docs/changes/2.5.0.md)

# [Version 2.5.0 to 2.5.1](./docs/changes/2.5.1.md)

# [Version 2.5.1 to 2.6.0](./docs/changes/2.6.0.md)

# [Version 2.6.0 to 2.7.0](./docs/changes/2.7.0.md)

# [Version 2.7.0 to 2.8.0](./docs/changes/2.8.0.md)

# Planned for next version

## Major code re-factoring

## Potential compatibility issues

Changes that may affect existing code

### A **new** SFTP configuration property has been introduced that limits the maximum amount of data that can be sent in a single *SSH_FXP_WRITE* packet - default=256KB

```java
    /**
     * Force the use of a max. packet length for {@link AbstractSftpSubsystemHelper#doWrite(Buffer, int)} protection
     * against malicious packets
     */
    public static final Property<Integer> MAX_WRITE_DATA_PACKET_LENGTH
            = Property.integer("sftp-max-writedata-packet-length", 256 * 1024);
```

This might cause SFTP write failures for clients that might have sent larger buffers and they have been accepted so far. If this happens, simply increase
this value (though the choice of 256KB should be compatible with the vast majority of clients).

### SSH channel identifiers have been changed to use *long* instead of *int* in order to align them with the standard that required them to be *UINT32* values.

The relevant API(s) have been modified accordingly - which may cause a few incompatibility issues with code that extends/implements existing `Channel` classes
and interfaces. In this context, the *Channel* interface now extends *ChannelIdentifier* where *getId()* has been renamed to *getChannelId()*

### *long* used instead of *int* in most encoded/decoded packets that are specified as being *UINT32*

There are several exceptions to this rule:

* The SFTP packet *id* field - an "opaque" value anyway, not used for allocation or indexing anyway

* Various flags and mask field - there is no reason to encapsulate them into a *long* value since they do not represent a cardinal number of 32 bits

* Various status code fields - ditto.

* Cases where the value serves as argument for allocation of other data structures based on its value - e.g., arrays, lists. This was
done for *convenience* reasons since Java does not support unsigned array/list sizes. In such cases, special validation code was applied
to make sure the requested value does not exceed `Integer#MAX_VALUE` (sometimes even less) in order to protect the code from malicious
or malformed packets. It is important to bear in mind that in the vast majority of the cases we do not want to be able to allocate arrays
or lists having billions of elements as it would almost definitely cause out-of-memory issues.

## User HOME directory resolution and usage have been moved to *PathUtils*

Was originally in *HostConfigEntry*.

## Minor code helpers

## Behavioral changes and enhancements

* [SSHD-966](https://issues.apache.org/jira/browse/SSHD-966) Deadlock on disconnection at the end of key-exchange
* [SSHD-1231](https://issues.apache.org/jira/browse/SSHD-1231) Public key authentication: wrong signature algorithm used (ed25519 key with ssh-rsa signature)
* [SSHD-1233](https://issues.apache.org/jira/browse/SSHD-1233) Added support for "limits@openssh.com" SFTP extension
* [SSHD-1244](https://issues.apache.org/jira/browse/SSHD-1244) Fixed channel window adjustment handling of large UINT32 values
* [SSHD-1244](https://issues.apache.org/jira/browse/SSHD-1244) Re-defined channel identifiers as `long` rather than `int` to align with protocol UINT32 definition
* [SSHD-1246](https://issues.apache.org/jira/browse/SSHD-1246) Added SshKeyDumpMain utility
* [SSHD-1247](https://issues.apache.org/jira/browse/SSHD-1247) Added support for Argon2id encrypted PUTTY keys
* [SSHD-1257](https://issues.apache.org/jira/browse/SSHD-1257) ChannelSession: don't flush out stream if already closed
* [SSHD-1262](https://issues.apache.org/jira/browse/SSHD-1262) TCP/IP port forwarding: don't buffer, and don't read from port before channel is open
* [SSHD-1264](https://issues.apache.org/jira/browse/SSHD-1264) Create KEX negotiation proposal only once per session, not on every re-KEX
* [SSHD-1266](https://issues.apache.org/jira/browse/SSHD-1266) Fix encoding/decoding critical options in OpenSSH certificates
