/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.client.session.proxy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.function.Function;
import java.util.logging.Level;

import org.apache.sshd.client.proxy.ProxyData;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.forward.SocksConstants.Socks5;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.BufferException;
import org.apache.sshd.common.util.buffer.BufferUtils;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.io.functors.IOFunction;
import org.apache.sshd.common.util.logging.LoggingUtils;
import org.apache.sshd.common.util.logging.SimplifiedLog;
import org.ietf.jgss.GSSContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * A {@link AbstractProxyConnector} to connect through a SOCKS5 proxy.
 *
 * @see <a href="https://tools.ietf.org/html/rfc1928">RFC 1928</a>
 */
@SuppressWarnings("checkstyle:MethodCount")
public class Socks5ProxyConnector extends AbstractProxyConnector {

    private static final Logger LOG = LoggerFactory.getLogger(Socks5ProxyConnector.class);

    private static final SimplifiedLog SIMPLE = LoggingUtils.wrap(LOG);

    /**
     * Authentication methods for SOCKS5.
     *
     * @see <a href= "https://www.iana.org/assignments/socks-methods/socks-methods.xhtml">SOCKS Methods, IANA.org</a>
     */
    private enum SocksAuthenticationMethod {

        ANONYMOUS(0),
        GSSAPI(1),
        PASSWORD(2),
        // CHALLENGE_HANDSHAKE(3),
        // CHALLENGE_RESPONSE(5),
        // SSL(6),
        // NDS(7),
        // MULTI_AUTH(8),
        // JSON(9),
        NONE_ACCEPTABLE(0xFF);

        private final byte value;

        SocksAuthenticationMethod(int value) {
            this.value = (byte) value;
        }

        public byte getValue() {
            return value;
        }
    }

    private enum ProtocolState {
        NONE,

        INIT {
            @Override
            public void handleMessage(Socks5ProxyConnector connector, Buffer data) throws Exception {
                connector.versionCheck(data.getByte());
                SocksAuthenticationMethod authMethod = connector.getAuthMethod(data.getByte());
                switch (authMethod) {
                    case ANONYMOUS:
                        connector.sendConnectInfo();
                        break;
                    case PASSWORD:
                        connector.doPasswordAuth();
                        break;
                    case GSSAPI:
                        connector.doGssApiAuth();
                        break;
                    default:
                        throw new IOException("Cannot authenticate at SOCKS proxy " + connector.proxyAddress);
                }
            }
        },

        AUTHENTICATING {
            @Override
            public void handleMessage(Socks5ProxyConnector connector, Buffer data) throws Exception {
                connector.authStep(data);
            }
        },

        CONNECTING {
            @Override
            public void handleMessage(Socks5ProxyConnector connector, Buffer data) throws Exception {
                // Special case: when GSS-API authentication completes, the
                // client moves into CONNECTING as soon as the GSS context is
                // established and sends the connect request. This is per RFC
                // 1961. But for the server, RFC 1961 says it _should_ send an
                // empty token even if none generated when its server side
                // context is established. That means we may actually get an
                // empty token here. That message is 4 bytes long (and has
                // content 0x01, 0x01, 0x00, 0x00). We simply skip this message
                // if we get it here. If the server for whatever reason sends
                // back a "GSS failed" message (it shouldn't, at this point)
                // it will be two bytes 0x01 0xFF, which will fail the version
                // check.
                if (data.available() != 4) {
                    connector.versionCheck(data.getByte());
                    connector.establishConnection(data);
                }
            }
        },

        CONNECTED,

        FAILED;

        public void handleMessage(Socks5ProxyConnector connector, Buffer data) throws Exception {
            throw new IOException(MessageFormat.format("Unexpected reply from SOCKS proxy {0}: {1}", connector.proxyAddress,
                    BufferUtils.toHex(data.array())));
        }
    }

    private ProtocolState state;

    private AuthenticationHandler<Buffer, Buffer> authenticator;

    private GSSContext context;

    private byte[] authenticationProposals;

    /**
     * Creates a new {@link Socks5ProxyConnector}. The connector supports anonymous connections as well as
     * username-password or Kerberos5 (GSS-API) authentication.
     *
     * @param proxy         {@link ProxyData} of the proxy we're connected to
     * @param remoteAddress {@link InetSocketAddress} of the target server to connect to
     * @param send          a function to send data and returning an {@link IoWriteFuture}
     * @param passwordAuth  a function to query the user for proxy credentials, if needed, and returning a
     *                      {@link PasswordAuthentication}
     */
    public Socks5ProxyConnector(ProxyData proxy, InetSocketAddress remoteAddress, IOFunction<Buffer, IoWriteFuture> send,
                                Function<InetSocketAddress, PasswordAuthentication> passwordAuth) {
        super(proxy, remoteAddress, send, passwordAuth);
        this.state = ProtocolState.NONE;
    }

    @Override
    public void start() throws IOException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("SOCKS5 starting connection to {}", remoteAddress);
        }
        // Send the initial request
        Buffer buffer = new ByteArrayBuffer(5, false);
        buffer.putByte(Socks5.VERSION);
        context = getGSSContext(remoteAddress);
        authenticationProposals = getAuthenticationProposals();
        buffer.putByte((byte) authenticationProposals.length);
        buffer.putRawBytes(authenticationProposals);
        state = ProtocolState.INIT;
        write(buffer);
    }

    private byte[] getAuthenticationProposals() {
        byte[] proposals = new byte[3];
        int i = 0;
        proposals[i++] = SocksAuthenticationMethod.ANONYMOUS.getValue();
        proposals[i++] = SocksAuthenticationMethod.PASSWORD.getValue();
        if (context != null) {
            proposals[i++] = SocksAuthenticationMethod.GSSAPI.getValue();
        }
        if (i == proposals.length) {
            return proposals;
        }
        return Arrays.copyOf(proposals, i);
    }

    private void sendConnectInfo() throws IOException {
        GssApiMechanisms.closeContextSilently(context);

        if (LOG.isDebugEnabled()) {
            LOG.debug("SOCKS5 authenticated, requesting connection to {}", remoteAddress);
        }

        byte[] rawAddress = getRawAddress(remoteAddress);
        byte[] remoteName = null;
        byte type;
        int length = 0;
        if (rawAddress == null) {
            remoteName = remoteAddress.getHostString().getBytes(US_ASCII);
            if (remoteName == null || remoteName.length == 0) {
                throw new IOException("No remote host name");
            } else if (remoteName.length > 255) {
                // Should not occur; host names must not be longer than 255 US_ASCII characters.
                throw new IOException(
                        "Proxy host name too long for SOCKS (at most 255 characters): " + remoteAddress.getHostString());
            }
            type = Socks5.ADDRESS_FQDN;
            length = remoteName.length + 1;
        } else {
            length = rawAddress.length;
            type = length == 4 ? Socks5.ADDRESS_IPV4 : Socks5.ADDRESS_IPV6;
        }
        Buffer buffer = new ByteArrayBuffer(4 + length + 2, false);
        buffer.putByte(Socks5.VERSION);
        buffer.putByte(Socks5.CMD_CONNECT);
        buffer.putByte((byte) 0); // Reserved
        buffer.putByte(type);
        if (remoteName != null) {
            buffer.putByte((byte) remoteName.length);
            buffer.putRawBytes(remoteName);
        } else {
            buffer.putRawBytes(rawAddress);
        }
        int port = remoteAddress.getPort();
        if (port <= 0) {
            port = SshConstants.DEFAULT_PORT;
        }
        buffer.putByte((byte) ((port >> 8) & 0xFF));
        buffer.putByte((byte) (port & 0xFF));
        state = ProtocolState.CONNECTING;
        write(buffer);
    }

    private void doPasswordAuth() throws Exception {
        GssApiMechanisms.closeContextSilently(context);
        authenticator = new SocksBasicAuthentication();
        startAuth();
    }

    private void doGssApiAuth() throws Exception {
        authenticator = new SocksGssApiAuthentication();
        startAuth();
    }

    @Override
    public void close() {
        super.close();
        AuthenticationHandler<?, ?> handler = authenticator;
        authenticator = null;
        if (handler != null) {
            handler.close();
        }
    }

    private void startAuth() throws Exception {
        authenticator.setParams(null);
        authenticator.start();
        Buffer buffer = authenticator.getToken();
        if (buffer == null) {
            throw new IOException("No data for authenticating at proxy " + proxyAddress);
        }
        state = ProtocolState.AUTHENTICATING;
        write(buffer).addListener(f -> buffer.clear(true));
    }

    private void authStep(Buffer input) throws Exception {
        authenticator.setParams(input);
        authenticator.process();
        Buffer buffer = authenticator.getToken();
        if (buffer != null) {
            write(buffer).addListener(f -> buffer.clear(true));
        }
        if (authenticator.isDone()) {
            sendConnectInfo();
        }
    }

    private void establishConnection(Buffer data) throws IOException {
        byte reply = data.getByte();
        switch (reply) {
            case Socks5.REPLY_SUCCESS:
                // Server also returns the "bind" address it uses, but we don't care. Skip it properly, though:
                try {
                    reply = data.getByte();
                    if (reply != 0) {
                        LOG.warn("SOCKS5 proxy for connection to {} returned success with reserved byte != 0", remoteAddress);
                    }
                    skipAddress(data);
                    int port = data.getUShort();
                    if (port <= 0) {
                        LOG.warn("SOCKS5 proxy for connection to {} returned success with invalid bind port {}", remoteAddress,
                                Integer.toString(port));
                    }
                } catch (BufferException e) {
                    data.rpos(0);
                    LOG.warn("SOCKS5 proxy for connection to {} returned malformed success reply; got {}", remoteAddress,
                            e.toString());
                    BufferUtils.dumpHex(SIMPLE, Level.WARNING, "remaining", BufferUtils.DEFAULT_HEX_SEPARATOR, 32, data.array(),
                            data.rpos(), data.available());
                    // Consume the whole buffer
                    data.rpos(data.wpos());
                }
                if (LOG.isDebugEnabled()) {
                    LOG.debug("SOCKS5 connected to {}", remoteAddress);
                }
                state = ProtocolState.CONNECTED;
                done = true;
                return;
            case Socks5.REPLY_FAILURE:
                throw new IOException("Tunneling failed for proxy " + proxyAddress);
            case Socks5.REPLY_FORBIDDEN:
                throw new IOException(
                        MessageFormat.format("Forbidden tunnel at proxy {0} to {1}", proxyAddress, remoteAddress));
            case Socks5.REPLY_NETWORK_UNREACHABLE:
                throw new IOException(MessageFormat.format("Network unreachable at proxy {0} for tunnel to {1}", proxyAddress,
                        remoteAddress));
            case Socks5.REPLY_HOST_UNREACHABLE:
                throw new IOException(
                        MessageFormat.format("Host unreachable at proxy {0} for tunnel to {1}", proxyAddress, remoteAddress));
            case Socks5.REPLY_CONNECTION_REFUSED:
                throw new IOException(
                        MessageFormat.format("Connection refused at proxy {0} for tunnel to {1}", proxyAddress, remoteAddress));
            case Socks5.REPLY_TTL_EXPIRED:
                throw new IOException(
                        MessageFormat.format("TTL expired at proxy {0} for tunnel to {1}", proxyAddress, remoteAddress));
            case Socks5.REPLY_COMMAND_UNSUPPORTED:
                throw new IOException("Unsupported command at proxy " + proxyAddress);
            case Socks5.REPLY_ADDRESS_UNSUPPORTED:
                throw new IOException("Unsupported address at proxy " + proxyAddress);
            default:
                throw new IOException("Unspecified failure at proxy " + proxyAddress);
        }
    }

    private void skipAddress(Buffer data) {
        int skip = -1;
        int type = data.getUByte();
        switch (type) {
            case Socks5.ADDRESS_IPV4:
                skip = 4;
                break;
            case Socks5.ADDRESS_IPV6:
                skip = 16;
                break;
            case Socks5.ADDRESS_FQDN:
                skip = data.getUByte();
                break;
            default:
                throw new BufferException("Invalid bind address type " + type);
        }
        if (data.available() < skip) {
            throw new BufferException("Not enough data; need " + skip + ", have " + data.available());
        }
        data.rpos(data.rpos() + skip);
    }

    @Override
    public Buffer received(Readable buffer) throws Exception {
        try {
            // Dispatch according to protocol state
            ByteArrayBuffer data = new ByteArrayBuffer(buffer.available(), false);
            data.putBuffer(buffer);
            state.handleMessage(this, data);
            return data;
        } catch (Exception e) {
            state = ProtocolState.FAILED;
            if (authenticator != null) {
                authenticator.close();
                authenticator = null;
            }
            done = true;
            throw e;
        }
    }

    private void versionCheck(byte version) throws IOException {
        if (version != Socks5.VERSION) {
            throw new IOException("Unexpected SOCK version " + (version & 0xFF));
        }
    }

    private SocksAuthenticationMethod getAuthMethod(byte value) {
        if (value != SocksAuthenticationMethod.NONE_ACCEPTABLE.getValue()) {
            for (byte proposed : authenticationProposals) {
                if (proposed == value) {
                    for (SocksAuthenticationMethod method : SocksAuthenticationMethod.values()) {
                        if (method.getValue() == value) {
                            return method;
                        }
                    }
                    break;
                }
            }
        }
        return SocksAuthenticationMethod.NONE_ACCEPTABLE;
    }

    private static byte[] getRawAddress(InetSocketAddress address) {
        InetAddress ipAddress = GssApiMechanisms.resolve(address);
        return ipAddress == null ? null : ipAddress.getAddress();
    }

    private static GSSContext getGSSContext(InetSocketAddress address) {
        if (!GssApiMechanisms.getSupportedMechanisms().contains(GssApiMechanisms.KERBEROS_5)) {
            return null;
        }
        return GssApiMechanisms.createContext(GssApiMechanisms.KERBEROS_5, GssApiMechanisms.getCanonicalName(address));
    }

    /**
     * @see <a href="https://tools.ietf.org/html/rfc1929">RFC 1929</a>
     */
    private class SocksBasicAuthentication extends BasicAuthentication<Buffer, Buffer> {

        private static final byte SOCKS_BASIC_PROTOCOL_VERSION = 1;

        private static final byte SOCKS_BASIC_AUTH_SUCCESS = 0;

        SocksBasicAuthentication() {
            super(proxyAddress, proxyUser, proxyPassword);
        }

        @Override
        public void process() throws Exception {
            // Retries impossible. RFC 1929 specifies that the server MUST
            // close the connection if authentication is unsuccessful.
            done = true;
            if (params.getByte() != SOCKS_BASIC_PROTOCOL_VERSION || params.getByte() != SOCKS_BASIC_AUTH_SUCCESS) {
                throw new IOException("SOCKS BASIC authentication failed at proxy " + proxy);
            }
        }

        @Override
        protected PasswordAuthentication getCredentials() {
            return passwordAuthentication();
        }

        @Override
        public Buffer getToken() throws IOException {
            if (done) {
                return null;
            }
            try {
                byte[] rawUser = user.getBytes(UTF_8);
                if (rawUser.length > 255) {
                    throw new IOException(MessageFormat.format("User name too long for proxy {0}: {1} bytes (max 255): {2}",
                            proxy, Integer.toString(rawUser.length), user));
                }

                if (password.length > 255) {
                    throw new IOException(MessageFormat.format("Password too long for proxy {0}: {1} bytes (max 255)", proxy,
                            Integer.toString(password.length)));
                }
                ByteArrayBuffer buffer = new ByteArrayBuffer(3 + rawUser.length + password.length, false);
                buffer.putByte(SOCKS_BASIC_PROTOCOL_VERSION);
                buffer.putByte((byte) rawUser.length);
                buffer.putRawBytes(rawUser);
                buffer.putByte((byte) password.length);
                buffer.putRawBytes(password);
                return buffer;
            } finally {
                clearPassword();
                done = true;
            }
        }
    }

    /**
     * @see <a href="https://tools.ietf.org/html/rfc1961">RFC 1961</a>
     */
    private class SocksGssApiAuthentication extends GssApiAuthentication<Buffer, Buffer> {

        private static final byte SOCKS5_GSSAPI_VERSION = 1;

        private static final byte SOCKS5_GSSAPI_TOKEN = 1;

        private static final int SOCKS5_GSSAPI_FAILURE = 0xFF;

        SocksGssApiAuthentication() {
            super(proxyAddress);
        }

        @Override
        protected GSSContext createContext() throws Exception {
            return context;
        }

        @Override
        public Buffer getToken() throws IOException {
            if (token == null) {
                return null;
            }
            Buffer buffer = new ByteArrayBuffer(4 + token.length, false);
            buffer.putByte(SOCKS5_GSSAPI_VERSION);
            buffer.putByte(SOCKS5_GSSAPI_TOKEN);
            buffer.putByte((byte) ((token.length >> 8) & 0xFF));
            buffer.putByte((byte) (token.length & 0xFF));
            buffer.putRawBytes(token);
            return buffer;
        }

        @Override
        protected byte[] extractToken(Buffer input) throws Exception {
            if (context == null) {
                return null;
            }
            int version = input.getUByte();
            if (version != SOCKS5_GSSAPI_VERSION) {
                throw new IOException(MessageFormat.format("Wrong GSS-API version at SOCKS proxy {0}: {1}", proxy,
                        Integer.toString(version)));
            }
            int msgType = input.getUByte();
            if (msgType == SOCKS5_GSSAPI_FAILURE) {
                throw new IOException(MessageFormat.format("SOCKS Proxy {0} reported GSS-API failure", proxy));
            } else if (msgType != SOCKS5_GSSAPI_TOKEN) {
                throw new IOException(MessageFormat.format("Unknown GSS-API message {1} from SOCKS proxy {0}", proxy,
                        Integer.toHexString(msgType & 0xFF)));
            }
            if (input.available() >= 2) {
                int length = (input.getUByte() << 8) + input.getUByte();
                if (input.available() >= length) {
                    byte[] value = new byte[length];
                    if (length > 0) {
                        input.getRawBytes(value);
                    }
                    return value;
                }
            }
            throw new IOException("Message too short from proxy" + proxy);
        }
    }
}
