# [Version 2.1.0 to 2.2.0](./docs/changes/2.2.0.md)

# [Version 2.2.0 to 2.3.0](./docs/changes/2.3.0.md)

# [Version 2.3.0 to 2.4.0](./docs/changes/2.4.0.md)

# Planned for next version

## Major code re-factoring

* Reception of an `SSH_MSG_UNIMPLEMENTED` response to a `SSH_MSG_GLOBAL_REQUEST` is
translated internally into same code flow as if an `SSH_MSH_REQUEST_FAILURE` has
been received - see [SSHD-968](https://issues.apache.org/jira/browse/SSHD-968).

## Minor code helpers

* Handling of debug/ignore/unimplemented messages has been split into `handleXXX` and `doInvokeXXXMsgHandler` methods
where the former validate the messages and deal with the idle timeout, and the latter execute the actual invcation.

## Behavioral changes and enhancements

* [SSHD-964](https://issues.apache.org/jira/browse/SSHD-964) - Send SSH_MSG_CHANNEL_EOF when tunnel channel being closed.

* [SSHD-967](https://issues.apache.org/jira/browse/SSHD-967) - Extra bytes written when `SftpRemotePathChannel#transferTo` is used.

* [SSHD-968](https://issues.apache.org/jira/browse/SSHD-968) - Interpret SSH_MSG_UNIMPLEMENTED response to a heartbeat request as a liveness indicator

* [SSHD-970](https://issues.apache.org/jira/browse/SSHD-970) - `transferTo` function of `SftpRemotePathChannel` will loop if count parameter is greater than file size
