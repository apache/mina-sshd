/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.forward;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.common.util.CloseableUtils;

/**
 * SOCKS proxy server, supporting simple socks4/5 protocols.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class SocksProxy extends CloseableUtils.AbstractCloseable implements IoHandler {

    private final ConnectionService service;
    private final Map<IoSession, Proxy> proxies = new ConcurrentHashMap<IoSession, Proxy>();

    public SocksProxy(ConnectionService service) {
        this.service = service;
    }

    public void sessionCreated(IoSession session) throws Exception {
        if (isClosing()) {
            throw new SshException("SocksProxy is closing or closed");
        }
    }

    public void sessionClosed(IoSession session) throws Exception {
        Proxy proxy = proxies.remove(session);
        if (proxy != null) {
            proxy.close();
        }
    }

    public void messageReceived(final IoSession session, org.apache.sshd.common.util.Readable message) throws Exception {
        Buffer buffer = new Buffer(message.available());
        buffer.putBuffer(message);
        Proxy proxy = proxies.get(session);
        if (proxy == null) {
            int version = buffer.getByte();
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

    public void exceptionCaught(IoSession ioSession, Throwable cause) throws Exception {
        log.warn("Exception caught, closing socks proxy", cause);
        ioSession.close(false);
    }

    public abstract class Proxy {

        IoSession session;
        TcpipClientChannel channel;

        protected Proxy(IoSession session) {
            this.session = session;
        }

        protected void onMessage(Buffer buffer) throws IOException {
            channel.getInvertedIn().write(buffer.array(), buffer.rpos(), buffer.available());
            channel.getInvertedIn().flush();
        }

        public void close() {
            if (channel != null) {
                channel.close(false);
            }
        }

        protected int getUByte(Buffer buffer) {
            return buffer.getByte() & 0xFF;
        }

        protected int getUShort(Buffer buffer) {
            return (getUByte(buffer) << 8) + getUByte(buffer);
        }
    }

    public class Socks4 extends Proxy {
        public Socks4(IoSession session) {
            super(session);
        }

        @Override
        protected void onMessage(Buffer buffer) throws IOException {
            if (channel == null) {
                int cmd = buffer.getByte();
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
                log.debug("Received socks4 connection request to {}:{}", host, port);
                SshdSocketAddress remote = new SshdSocketAddress(host, port);
                channel = new TcpipClientChannel(TcpipClientChannel.Type.Direct, session, remote);
                service.registerChannel(channel);
                channel.open().addListener(new SshFutureListener<OpenFuture>() {
                    public void operationComplete(OpenFuture future) {
                        onChannelOpened(future);
                    }
                });
            } else {
                super.onMessage(buffer);
            }
        }

        protected void onChannelOpened(OpenFuture future) {
            Buffer buffer = new Buffer(8);
            buffer.putByte((byte) 0x00);
            Throwable t = future.getException();
            if (t != null) {
                service.unregisterChannel(channel);
                channel.close(false);
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
            session.write(buffer);
        }

        private String getNTString(Buffer buffer) {
            StringBuilder sb = new StringBuilder();
            char c;
            while ((c = (char) getUByte(buffer)) != 0) {
                sb.append(c);
            }
            return sb.toString();
        }

    }

    public class Socks5 extends Proxy {

        byte[] authMethods;
        Buffer response;

        public Socks5(IoSession session) {
            super(session);
        }

        @Override
        protected void onMessage(Buffer buffer) throws IOException {
            if (authMethods == null) {
                int nbAuthMethods = getUByte(buffer);
                authMethods = new byte[nbAuthMethods];
                buffer.getRawBytes(authMethods);
                boolean foundNoAuth = false;
                for (int i = 0; i < nbAuthMethods; i++) {
                    foundNoAuth |= authMethods[i] == 0;
                }
                buffer = new Buffer(8);
                buffer.putByte((byte) 0x05);
                buffer.putByte((byte) (foundNoAuth ? 0x00 : 0xFF));
                session.write(buffer);
                if (!foundNoAuth) {
                    throw new IllegalStateException("Received socks5 greeting without NoAuth method");
                } else {
                    log.debug("Received socks5 greeting");
                }
            } else if (channel == null) {
                response = buffer;
                int version = getUByte(buffer);
                if (version != 0x05) {
                    throw new IllegalStateException("Unexpected version: " + version);
                }
                int cmd = buffer.getByte();
                if (cmd != 1) {
                    throw new IllegalStateException("Unsupported socks command: " + cmd);
                }
                final int res = buffer.getByte();
                int type = buffer.getByte();
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
                log.debug("Received socks5 connection request to {}:{}", host, port);
                SshdSocketAddress remote = new SshdSocketAddress(host, port);
                channel = new TcpipClientChannel(TcpipClientChannel.Type.Direct, session, remote);
                service.registerChannel(channel);
                channel.open().addListener(new SshFutureListener<OpenFuture>() {
                    public void operationComplete(OpenFuture future) {
                        onChannelOpened(future);
                    }
                });
            } else {
                log.debug("Received socks5 connection message");
                super.onMessage(buffer);
            }
        }

        protected void onChannelOpened(OpenFuture future) {
            int wpos = response.wpos();
            response.rpos(0);
            response.wpos(1);
            Throwable t = future.getException();
            if (t != null) {
                service.unregisterChannel(channel);
                channel.close(false);
                response.putByte((byte) 0x01);
            } else {
                response.putByte((byte) 0x00);
            }
            response.wpos(wpos);
            session.write(response);
        }

        private String getBLString(Buffer buffer) {
            int length = getUByte(buffer);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < length; i++) {
                sb.append((char) getUByte(buffer));
            }
            return sb.toString();
        }

    }

}
