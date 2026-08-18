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
package org.apache.sshd.common.forward;

import java.io.Closeable;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.StreamingChannel.Streaming;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.common.util.threads.ThreadUtils;

/**
 * SOCKS proxy server, supporting simple socks4/5 protocols.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 * @see    <A HREF="https://en.wikipedia.org/wiki/SOCKS">SOCKS Wikipedia</A>
 */
public class SocksProxy extends AbstractCloseable implements IoHandler {

    private final ConnectionService service;
    private final Map<IoSession, Proxy> proxies = new ConcurrentHashMap<>();

    public SocksProxy(ConnectionService service) {
        this.service = service;
    }

    @Override
    public void sessionCreated(IoSession session) throws Exception {
        if (isClosing()) {
            throw new SshException("SocksProxy is closing or closed: " + state);
        }
    }

    @Override
    public void sessionClosed(IoSession session) throws Exception {
        Proxy proxy = proxies.remove(session);
        if (proxy != null) {
            proxy.close();
        }
    }

    @Override
    public void messageReceived(IoSession session, org.apache.sshd.common.util.Readable message) throws Exception {
        Buffer buffer = new ByteArrayBuffer(message.available() + Long.SIZE, false);
        buffer.putBuffer(message);
        Proxy proxy = proxies.get(session);
        if (proxy == null) {
            int version = buffer.getUByte();
            if (version == 0x04) {
                proxy = new Socks4(session);
            } else if (version == 0x05) {
                proxy = new Socks5(session);
            } else {
                throw new IllegalStateException("Unsupported version: " + version);
            }
            proxy.onMessage(buffer);
            proxies.put(session, proxy);
        } else {
            proxy.onMessage(buffer);
        }
    }

    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        log.warn("Exception caught, closing socks proxy", cause);
        session.close(false);
    }

    public abstract static class Proxy implements Closeable {
        protected IoSession session;
        protected TcpipClientChannel channel;

        protected Proxy(IoSession session) {
            this.session = session;
        }

        protected void onMessage(Buffer buffer) throws IOException {
            session.suspendRead();
            ThreadUtils.runAsInternal(channel.getAsyncIn(),
                    out -> out.writeBuffer(buffer).addListener(f -> session.resumeRead()));
        }

        @Override
        public void close() throws IOException {
            if (channel != null) {
                channel.close(false);
            }
        }

        protected int getUByte(Buffer buffer) {
            return buffer.getUByte();
        }

        protected int getUShort(Buffer buffer) {
            return (getUByte(buffer) << Byte.SIZE) + getUByte(buffer);
        }
    }

    /**
     * @see <A HREF="https://en.wikipedia.org/wiki/SOCKS#SOCKS4">SOCKS4</A>
     */
    public class Socks4 extends Proxy {
        public Socks4(IoSession session) {
            super(session);
        }

        @SuppressWarnings("synthetic-access")
        @Override
        protected void onMessage(Buffer buffer) throws IOException {
            if (channel == null) {
                int cmd = buffer.getUByte();
                if (cmd != 1) {
                    throw new IllegalStateException("Unsupported socks command: " + cmd);
                }
                int port = getUShort(buffer);
                String host = Integer.toString(getUByte(buffer)) + "."
                              + Integer.toString(getUByte(buffer)) + "."
                              + Integer.toString(getUByte(buffer)) + "."
                              + Integer.toString(getUByte(buffer));
                String userId = getNTString(buffer);
                // Socks4a
                if (host.startsWith("0.0.0.")) {
                    host = getNTString(buffer);
                }
                if (log.isDebugEnabled()) {
                    log.debug("Received socks4 connection request for {} to {}:{}", userId, host, port);
                }

                SshdSocketAddress remote = new SshdSocketAddress(host, port);
                channel = new TcpipClientChannel(TcpipClientChannel.Type.Direct, session, remote);
                channel.setStreaming(Streaming.Async);
                session.suspendRead();
                service.registerChannel(channel);
                channel.open().addListener(this::onChannelOpened);
            } else {
                super.onMessage(buffer);
            }
        }

        @SuppressWarnings("synthetic-access")
        protected void onChannelOpened(OpenFuture future) {
            session.resumeRead();
            Buffer buffer = new ByteArrayBuffer(Long.SIZE, false);
            buffer.putByte((byte) 0x00);
            Throwable t = future.getException();
            if (t != null) {
                service.unregisterChannel(channel);
                channel.close(true);
                buffer.putByte((byte) 0x5b);
            } else {
                buffer.putByte((byte) 0x5a);
            }
            buffer.putByte((byte) 0x00);
            buffer.putByte((byte) 0x00);
            buffer.putByte((byte) 0x00);
            buffer.putByte((byte) 0x00);
            buffer.putByte((byte) 0x00);
            buffer.putByte((byte) 0x00);
            try {
                session.writeBuffer(buffer);
            } catch (IOException e) {
                // TODO Auto-generated catch block
                log.error("Failed ({}) to send channel open packet for {}: {}", e.getClass().getSimpleName(), channel,
                        e.getMessage());
                throw new IllegalStateException("Failed to send packet", e);
            }
        }

        protected String getNTString(Buffer buffer) {
            StringBuilder sb = new StringBuilder();
            for (char c = (char) getUByte(buffer); c != '\0'; c = (char) getUByte(buffer)) {
                sb.append(c);
            }
            return sb.toString();
        }
    }

    private enum Socks5State {
        GREETING,
        CONNECT_REQUEST,
        OPENING_CHANNEL,
        FORWARDING,
        CLOSED
    }

    /**
     * @see <A HREF="https://en.wikipedia.org/wiki/SOCKS#SOCKS5">SOCKS5</A>
     */
    public class Socks5 extends Proxy {
        private Socks5State state = Socks5State.GREETING;
        private Buffer pending = new ByteArrayBuffer();

        public Socks5(IoSession session) {
            super(session);
        }

        @SuppressWarnings("synthetic-access")
        @Override
        protected synchronized void onMessage(Buffer buffer) throws IOException {
            if (state == Socks5State.FORWARDING && pending.available() == 0) {
                super.onMessage(buffer);
                return;
            }
            pending.putBuffer(buffer);
            processPending();
        }

        protected void processPending() throws IOException {
            if (state == Socks5State.OPENING_CHANNEL || state == Socks5State.CLOSED) {
                return;
            }

            if (state == Socks5State.FORWARDING) {
                forwardPending();
                return;
            }

            if (state == Socks5State.GREETING) {
                if (pending.available() < 1) {
                    return;
                }
                int authMethodsCount = pending.rawByte(pending.rpos()) & 0xFF;
                if (pending.available() < authMethodsCount + 1) {
                    return;
                }

                pending.getUByte();
                boolean foundNoAuth = false;
                for (int index = 0; index < authMethodsCount; index++) {
                    foundNoAuth |= pending.getUByte() == 0;
                }
                pending.compact();
                Buffer response = new ByteArrayBuffer(2, false);
                response.putByte((byte) 0x05);
                response.putByte((byte) (foundNoAuth ? 0x00 : 0xFF));
                session.writeBuffer(response);
                if (!foundNoAuth) {
                    throw new IllegalStateException("Received socks5 greeting without NoAuth method");
                } else if (log.isDebugEnabled()) {
                    log.debug("Received socks5 greeting");
                }
                state = Socks5State.CONNECT_REQUEST;
            }

            if (state == Socks5State.CONNECT_REQUEST) {
                if (pending.available() < 4) {
                    return;
                }
                int offset = pending.rpos();
                int version = pending.rawByte(offset) & 0xFF;
                if (version != 0x05) {
                    throw new IllegalStateException("Unexpected version: " + version);
                }
                int cmd = pending.rawByte(offset + 1) & 0xFF;
                if (cmd != 1) { // establish a TCP/IP stream connection
                    throw new IllegalStateException("Unsupported socks command: " + cmd);
                }
                int res = pending.rawByte(offset + 2) & 0xFF;
                if (res != 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("No zero reserved value: {}", res);
                    }
                }
                int type = pending.rawByte(offset + 3) & 0xFF;
                int addressLength;
                if (type == 0x01) {
                    addressLength = 4;
                } else if (type == 0x03) {
                    if (pending.available() < 5) {
                        return;
                    }
                    addressLength = pending.rawByte(offset + 4) & 0xFF;
                } else if (type == 0x04) {
                    addressLength = 16;
                } else {
                    throw new IllegalStateException("Unsupported address type: " + type);
                }
                int requestLength = 4 + (type == 0x03 ? 1 : 0) + addressLength + 2;
                if (pending.available() < requestLength) {
                    return;
                }

                getUByte(pending); // version already checked above
                getUByte(pending); // command already checked above
                getUByte(pending); // reserved byte
                getUByte(pending); // address type
                String host;
                if (type == 0x01) {
                    host = Integer.toString(getUByte(pending)) + "."
                           + Integer.toString(getUByte(pending)) + "."
                           + Integer.toString(getUByte(pending)) + "."
                           + Integer.toString(getUByte(pending));
                } else if (type == 0x03) {
                    host = getBLString(pending);
                } else {
                    StringBuilder address = new StringBuilder();
                    for (int index = 0; index < 8; index++) {
                        if (index > 0) {
                            address.append(':');
                        }
                        address.append(Integer.toHexString(getUShort(pending)));
                    }
                    host = address.toString();
                }
                int port = getUShort(pending);
                pending.compact();
                if (log.isDebugEnabled()) {
                    log.debug("Received socks5 connection request to {}:{}", host, port);
                }
                SshdSocketAddress remote = new SshdSocketAddress(host, port);
                channel = new TcpipClientChannel(TcpipClientChannel.Type.Direct, session, remote);
                channel.setStreaming(Streaming.Async);
                session.suspendRead();
                service.registerChannel(channel);
                state = Socks5State.OPENING_CHANNEL;
                channel.open().addListener(this::onChannelOpened);
            }
        }

        @SuppressWarnings("synthetic-access")
        protected synchronized void onChannelOpened(OpenFuture future) {
            Throwable t = future.getException();
            if (t != null) {
                service.unregisterChannel(channel);
                channel.close(true);
                pending.clear(true);
                state = Socks5State.CLOSED;
                sendReply((byte) 0x01, () -> session.close(false));
                return;
            }

            state = Socks5State.FORWARDING;
            sendReply((byte) 0x00, this::forwardPending);
        }

        protected void sendReply(byte status, Runnable completion) {
            Buffer response = new ByteArrayBuffer(10, false);
            // VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
            response.putRawBytes(new byte[] { 0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0 });
            try {
                session.writeBuffer(response).addListener(future -> {
                    if (future.isWritten()) {
                        completion.run();
                    } else {
                        session.close(true);
                    }
                });
            } catch (IOException e) {
                log.error("Failed ({}) to send channel open response for {}: {}", e.getClass().getSimpleName(), channel,
                        e.getMessage());
                session.close(true);
            }
        }

        protected synchronized void forwardPending() {
            if (state != Socks5State.FORWARDING) {
                return;
            }
            Buffer payload = pending;
            pending = new ByteArrayBuffer();
            if (payload.available() == 0) {
                session.resumeRead();
                return;
            }
            int payloadSize = payload.available();
            session.suspendRead();
            try {
                ThreadUtils.runAsInternal(channel.getAsyncIn(), out -> out.writeBuffer(payload).addListener(future -> {
                    if (future.getException() == null) {
                        if (log.isDebugEnabled()) {
                            log.debug("Forwarded {} queued socks5 bytes", payloadSize);
                        }
                        session.resumeRead();
                    } else {
                        session.close(true);
                    }
                }));
            } catch (IOException e) {
                log.error("Failed ({}) to forward {} queued bytes for {}: {}", e.getClass().getSimpleName(), payloadSize,
                        channel, e.getMessage());
                session.close(true);
            }
        }

        protected String getBLString(Buffer buffer) {
            int length = getUByte(buffer);
            StringBuilder sb = new StringBuilder(length);
            for (int i = 0; i < length; i++) {
                sb.append((char) getUByte(buffer));
            }
            return sb.toString();
        }
    }
}
