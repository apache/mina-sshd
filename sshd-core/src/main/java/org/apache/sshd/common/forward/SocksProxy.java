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
import java.io.OutputStream;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoOutputStream;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;
import org.apache.sshd.common.util.net.SshdSocketAddress;

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
            IoOutputStream asyncIn = channel.getAsyncIn();
            if (asyncIn != null) {
                asyncIn.writeBuffer(buffer);
            } else {
                OutputStream invertedIn = channel.getInvertedIn();
                invertedIn.write(buffer.array(), buffer.rpos(), buffer.available());
                invertedIn.flush();
            }
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
                service.registerChannel(channel);
                channel.open().addListener(this::onChannelOpened);
            } else {
                super.onMessage(buffer);
            }
        }

        @SuppressWarnings("synthetic-access")
        protected void onChannelOpened(OpenFuture future) {
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

    /**
     * @see <A HREF="https://en.wikipedia.org/wiki/SOCKS#SOCKS5">SOCKS5</A>
     */
    public class Socks5 extends Proxy {
        private byte[] authMethods;
        private Buffer response;

        public Socks5(IoSession session) {
            super(session);
        }

        @SuppressWarnings("synthetic-access")
        @Override
        protected void onMessage(Buffer buffer) throws IOException {
            boolean debugEnabled = log.isDebugEnabled();
            if (authMethods == null) {
                int nbAuthMethods = getUByte(buffer);
                authMethods = new byte[nbAuthMethods];
                buffer.getRawBytes(authMethods);
                boolean foundNoAuth = false;
                for (int i = 0; i < nbAuthMethods; i++) {
                    foundNoAuth |= authMethods[i] == 0;
                }
                buffer = new ByteArrayBuffer(Byte.SIZE, false);
                buffer.putByte((byte) 0x05);
                buffer.putByte((byte) (foundNoAuth ? 0x00 : 0xFF));
                session.writeBuffer(buffer);
                if (!foundNoAuth) {
                    throw new IllegalStateException("Received socks5 greeting without NoAuth method");
                } else if (debugEnabled) {
                    log.debug("Received socks5 greeting");
                }
            } else if (channel == null) {
                response = buffer;
                int version = getUByte(buffer);
                if (version != 0x05) {
                    throw new IllegalStateException("Unexpected version: " + version);
                }
                int cmd = buffer.getUByte();
                if (cmd != 1) { // establish a TCP/IP stream connection
                    throw new IllegalStateException("Unsupported socks command: " + cmd);
                }
                int res = buffer.getUByte();
                if (res != 0) {
                    if (debugEnabled) {
                        log.debug("No zero reserved value: {}", res);
                    }
                }

                int type = buffer.getUByte();
                String host;
                if (type == 0x01) {
                    host = Integer.toString(getUByte(buffer)) + "."
                           + Integer.toString(getUByte(buffer)) + "."
                           + Integer.toString(getUByte(buffer)) + "."
                           + Integer.toString(getUByte(buffer));
                } else if (type == 0x03) {
                    host = getBLString(buffer);
                } else if (type == 0x04) {
                    host = Integer.toHexString(getUShort(buffer)) + ":"
                           + Integer.toHexString(getUShort(buffer)) + ":"
                           + Integer.toHexString(getUShort(buffer)) + ":"
                           + Integer.toHexString(getUShort(buffer)) + ":"
                           + Integer.toHexString(getUShort(buffer)) + ":"
                           + Integer.toHexString(getUShort(buffer)) + ":"
                           + Integer.toHexString(getUShort(buffer)) + ":"
                           + Integer.toHexString(getUShort(buffer));
                } else {
                    throw new IllegalStateException("Unsupported address type: " + type);
                }
                int port = getUShort(buffer);
                if (debugEnabled) {
                    log.debug("Received socks5 connection request to {}:{}", host, port);
                }
                SshdSocketAddress remote = new SshdSocketAddress(host, port);
                channel = new TcpipClientChannel(TcpipClientChannel.Type.Direct, session, remote);
                service.registerChannel(channel);
                channel.open().addListener(this::onChannelOpened);
            } else {
                if (debugEnabled) {
                    log.debug("Received socks5 connection message");
                }
                super.onMessage(buffer);
            }
        }

        @SuppressWarnings("synthetic-access")
        protected void onChannelOpened(OpenFuture future) {
            int wpos = response.wpos();
            response.rpos(0);
            response.wpos(1);
            Throwable t = future.getException();
            if (t != null) {
                service.unregisterChannel(channel);
                channel.close(true);
                response.putByte((byte) 0x01);
            } else {
                response.putByte((byte) 0x00);
            }
            response.wpos(wpos);
            try {
                session.writeBuffer(response);
            } catch (IOException e) {
                log.error("Failed ({}) to send channel open response for {}: {}", e.getClass().getSimpleName(), channel,
                        e.getMessage());
                throw new IllegalStateException("Failed to send packet", e);
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
