# [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)

# [Version 2.2.0 to 2.3.0](./docs/changes/2.3.0.md)

# [Version 2.3.0 to 2.4.0](./docs/changes/2.4.0.md)

# Planned for next version

## Major code re-factoring

* Reception of an `SSH_MSG_UNIMPLEMENTED` response to a `SSH_MSG_GLOBAL_REQUEST` is
translated internally into same code flow as if an `SSH_MSH_REQUEST_FAILURE` has
been received - see [SSHD-968](https://issues.apache.org/jira/browse/SSHD-968).

* Server SFTP subsystem internal code dealing with the local files has been delegated to
the `SftpFileSystemAccessor` in order to allow easier hooking into the SFTP subsystem.

    * Resolving a local file path for an SFTP remote one
    * Reading/Writing a file's attribute(s)
    * Creating files links
    * Copying / Renaming / Deleting files

* `SftpVersionSelector` is now consulted when client sends initial command (as well
as when session is re-negotiated)

## Minor code helpers

* Handling of debug/ignore/unimplemented messages has been split into `handleXXX` and `doInvokeXXXMsgHandler` methods
where the former validate the messages and deal with the idle timeout, and the latter execute the actual invcation.

* Added overloaded methods that accept a `java.time.Duration` specifier for timeout value.

* The argument representing the SFTP subsystem in invocations to `SftpFileSystemAccessor` has been enhanced to expose
as much of the available functionality as possible.

## Behavioral changes and enhancements

* [SSHD-964](https://issues.apache.org/jira/browse/SSHD-964) - Send SSH_MSG_CHANNEL_EOF when tunnel channel being closed.

* [SSHD-967](https://issues.apache.org/jira/browse/SSHD-967) - Extra bytes written when `SftpRemotePathChannel#transferTo` is used.

* [SSHD-968](https://issues.apache.org/jira/browse/SSHD-968) - Interpret SSH_MSG_UNIMPLEMENTED response to a heartbeat request as a liveness indicator

* [SSHD-970](https://issues.apache.org/jira/browse/SSHD-970) - `transferTo` function of `SftpRemotePathChannel` will loop if count parameter is greater than file size

* [SSHD-972](https://issues.apache.org/jira/browse/SSHD-972) - Add support for peers using OpenSSH "security key" key types

* [SSHD-977](https://issues.apache.org/jira/browse/SSHD-977) - Apply consistent logging policy to caught exceptions

* [SSHD-660](https://issues.apache.org/jira/browse/SSHD-660) - Added support for server-side signed certificate keys

* [SSHD-984](https://issues.apache.org/jira/browse/SSHD-984) - Utility method to export KeyPair in OpenSSH format

* [SSHD-992](https://issues.apache.org/jira/browse/SSHD-984) - Provide more hooks into the SFTP server subsystem via SftpFileSystemAccessor

<<<<<<< HEAD
* [SSHD-997](https://issues.apache.org/jira/browse/SSHD-997) - Fixed OpenSSH private key decoders for RSA and Ed25519

* [SSHD-998](https://issues.apache.org/jira/browse/SSHD-998) - Take into account SFTP version preference when establishing initial channel
=======
* [SSHD-989](https://issues.apache.org/jira/browse/SSHD-989) - Implement ECDSA public key recovery for PKCS8 encoded data
>>>>>>> [SSHD-989] Implement ECDSA public key recovery from PKCS#8 encoded data
