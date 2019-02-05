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
