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

* A **new** SFTP configuration property has been introduced that limits the maximum amount of data that can be sent in a single *SSH_FXP_WRITE* packet - default=256KB

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

## Minor code helpers

## Behavioral changes and enhancements

* [SSHD-1231](https://issues.apache.org/jira/browse/SSHD-1231) Public key authentication: wrong signature algorithm used (ed25519 key with ssh-rsa signature)
* [SSHD-1233](https://issues.apache.org/jira/browse/SSHD-1233) Added support for "limits@openssh.com" SFTP extension


