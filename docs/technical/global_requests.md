## Global Requests

**Global requests** are messages sent between an SSH client and an SSH server
that are independent of any SSH channel. Such messages may just provide information
to the peer, or they may instruct it to initiate certain actions. For example,
starting or cancelling a [TCP/IP remote port forwarding](./tcpip-forwarding.md) is
done with global requests. The OpenSSH host key update and rotation extension to
the SSH protocol also uses global requests.

Global requests are specified in [RFC 4254](https://tools.ietf.org/html/rfc4254#section-4).

### Request kinds

Global requests are identified by a request name, and the sender may indicate whether
it wants a reply from the recipient. So there are two different kinds of global requests:

* `want-reply=false`: asynchronous, "fire-and-forget" one-way messages.
* `want-reply=true`: messages to which there is a reply, similar to a remote procedure call (RPC)

Other than the request name, a global request does not carry any request identifier. So
a crucial piece of a normal RPC protocol is missing in the SSH protocol. In RPC, a request
normally carries a unique identifier (some sequence number), which is repeated in the reply,
so that the sender can know which request the reply belongs to. In the SSH protocol, this
request identifier is missing in the reply.

All SSH packets are globally numbered in a session; so each message *does* have a unique
identifier. If that sequence number were included in the reply to a global request, the
sender could know easily which request a certain reply belonged to.

RFC 4254 specifies instead that *"it is REQUIRED that replies to SSH_MSG_GLOBAL_REQUESTS
MUST be sent in the same order as the corresponding request messages"*.

In other words, if one party sends two global requests

```
  SSH_MSG_GLOBAL_REQUEST "a" want-reply=true ...
  SSH_MSG_GLOBAL_REQUEST "b" want-reply=true ...
```

the other party must reply first to "a" and then to "b". (Note that in the two requests
the request-name might also be the same, for instance two "tcpip-forward" requests.)

The reply can be either a `SSH_MSG_REQUEST_SUCCESS` message, possibly with additional data,
or a `SSH_MSG_REQUEST_FAILURE` message, which carries no additional data.

To implement such RPC-style requests without request identifiers in the reply, the sender
must keep a list of requests it made (per session), and when it receives a reply associate
it with the frontmost request made.

### Unknown requests

If a recipient receives a global request with a request name it doesn't recognize, it
is supposed to reply with a `SSH_MSG_REQUEST_FAILURE` message *if it was an RPC request*
(`want-reply=true`). However, some SSH implementations respond with an `SSH_MSG_UNIMPLEMENTED`
message instead. This may indicate that the recipient doesn't implement global requests
at all. Replying on a global request with an unknown *request name* with an "unimplemented"
message is not covered by the SSH RFCs.

These "unimplemented" messages include the packet sequence number of the original
message they refer to. [RFC 4253](https://tools.ietf.org/html/rfc4253#section-11.4)
specifies that *"An implementation MUST respond to all unrecognized messages with an
SSH_MSG_UNIMPLEMENTED message in the order in which the messages were received."*
It is unspecified, though, whether this order and the order of global request replies
from RFC 4254 are independent, or whether there must one single global order.

To handle this, a sender must remember for each RPC-style request it makes also the
packet sequence number so that it can remove the correct request from its list of
global requests.

### API

Prior to version 2.9.0, `Session.request()` was the only way to make an RPC-style global
request (`want-reply=true`). There was no support for making "fire-and-forget" global
requests (`want-reply=false`), such requests had to be sent directly via `Session.writePacket()`.

Also, the implementation of `Session.request()` was *synchronous*: it sent the request
and then waited until the reply was received, blocking the thread executing the call.
There could be only one pending RPC-style request. (Some other SSH libraries also use
such a simplistic implementation, for instance JSch 0.1.55.)

Synchronous requests, however, are not a good idea with the asynchronous I/O frameworks
(NIO2, Mina, Netty) that Apache MINA sshd uses. If the request was executed on an I/O
thread, that thread would be blocked and couldn't handle any other message. Moreover,
if the request was made on an I/O thread, this means it runs as part of handling some
message in an SSH session, and Apache MINA sshd handles all messages in an SSH session
sequentially and holds a session-global lock: any other thread that might receive the
reply would not be able to deliver it because that lock would still be held by the
blocked thread waiting for the reply.

The blocking `Session.request()` implementation still exists in Apache MINA sshd 2.9.0. It
provides a simple interface and may be useful in cases where one knows that the invocation
happens in an application thread, not in an I/O thread handling some other incoming message.

But Apache MINA 2.9.0 adds another variant that associates a callback to handle the reply
with the request. That version of `Session.request()` does *not* block waiting for the reply.
It just sends the request and records the request together with the callback handler in
its list of global requests, and when the reply arrives invokes that handler on whatever
I/O thread received the reply.

Both versions of `Session.request()` in Apache MINA 2.9.0 can also be used to send
"fire-and-forget" global requests.

The asynchronous version of `Session.request()` has the interface

```java
public GlobalRequestFuture request(Buffer buffer, String request, ReplyHandler replyHandler) throws IOException;
```

The `Buffer` is supposed to contain the full request, including the `request` name (for
instance, "tcpip-forward"), the `want-reply` flag, and any additional data needed. This
can be used to make RPC-style or "fire-and-forget" requests, and there are several possible
ways to use it.

* `want-reply=true` and `replyHandler != null`: the methods sends the request and returns a
  future that is fulfilled when the request was actually sent. The future is fulfilled with
  an exception if sending the request failed, or with `null` if it was sent successfully.
  Once the reply is received, the handler is invoked with the SSH command (`SSH_MSG_REQUEST_SUCCESS`,
  `SSH_MSG_REQUEST_FAILURE`, or `SSH_MSG_UNIMPLEMENTED`) and the buffer received.
* `want-reply=true` and `replyHandler == null`: the method sends the request and returns a
  future that is fulfilled with an exception if sending it failed, or if a `SSH_MSG_REQUEST_FAILURE`
  or `SSH_MSG_UNIMPLEMENTED` reply was received. Otherwise the future is fulfilled with the received
  Buffer once the reply has been received.
* `want-reply=false`: the method sends the request and returns a future that is fulfilled when
  the request was actually sent. The future is fulfilled with an exception if sending the request
  failed, or with an empty buffer if it was sent successfully. If `replyHandler != null`, it is
  invoked with an empty buffer once the request was sent.
  
If the method throws an `IOException`, the request was not sent, and the handler will not be
invoked.

### Implementation

Global requests are implemented in Apache MINA sshd in [`AbstractSession`](../../sshd-core/src/main/java/org/apache/sshd/common/session/helpers/AbstractSession.java).

The asynchronous `Session.request()` implementation uses a FIFO queue of requests sent, and in
`AbstractSession.requestSuccess()` and `AbstractSession.requestFailure` associates a reply with the
front-most request in that FIFO list. Only RPC-style requests with `want-reply=true` go onto this
list. The FIFO list stores the [`GlobalRequestFuture`](../../sshd-core/src/main/java/org/apache/sshd/common/future/GlobalRequestFuture.java))
of the requests made.

Futures are put onto the tail of the FIFO list before actually sending the request to avoid
a possible race condition between registering the future and a reply coming in very quickly.
If the request cannot be sent, such a future for a request that never went out is removed
again from the tail of the FIFO queue.

The implementation also keeps track of the SSH packet sequence number of each request made
so that it can remove the correct request from the FIFO list when a `SSH_MSG_UNIMPLEMENTED` is
received. This sequence number is determined when the request message packet is encrypted,
and is set on the `GlobalRequestFuture` of the global request via a callback. When an
"unimplemented" message is received and the FIFO list contains a request future with a
matching sequence number, that request is removed from the list irrespective of its
position in the list, and the request is failed as if a `SSH_MSG_REQUEST_FAILURE` message
had been received.
