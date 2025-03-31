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
package org.apache.sshd.client.channel;

import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.client.session.ClientConnectionService;
import org.apache.sshd.client.x11.X11IoHandler;
import org.apache.sshd.common.Property;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class ChannelX11 extends AbstractClientChannel {

    public static final Property<Object> X11_COOKIE = Property.object("x11-cookie");
    public static final Property<Object> X11_COOKIE_HEX = Property.object("x11-cookie-hex");

    private final AtomicBoolean isInitialized = new AtomicBoolean(false);
    private final String host;
    private final int port;

    private IoSession x11;

    public ChannelX11(String host, int port) {
        super("x11");
        this.host = host;
        this.port = port;
    }

    @Override
    public OpenFuture open(long recipient, long rwSize, long packetSize, Buffer buffer) {
        final DefaultOpenFuture defaultOpenFuture = new DefaultOpenFuture(this, futureLock);
        super.openFuture = defaultOpenFuture;

        final IoConnector connector
                = getSession().getFactoryManager().getIoServiceFactory().createConnector(createX11IoHandler());
        addCloseFutureListener(future -> {
            if (future.isClosed()) {
                connector.close(true);
            }
        });

        final IoConnectFuture connectFuture = connector.connect(new InetSocketAddress(host, port), this, null);
        connectFuture.addListener(future -> {
            if (future.isConnected()) {
                x11 = future.getSession();
                handleOpenSuccess(recipient, rwSize, packetSize, buffer);
            } else {
                if (future.getException() != null) {
                    defaultOpenFuture.setException(future.getException());
                } else {
                    defaultOpenFuture.setValue(false);
                }
                unregisterSelf();
            }
        });

        return defaultOpenFuture;

    }

    @Override
    protected void doOpen() throws IOException {
        setOut(new ChannelOutputStream(this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true));
    }

    @Override
    protected void doWriteData(byte[] data, int off, long len) throws IOException {
        if (isInitialized.compareAndSet(false, true)) {
            final byte[] xCookie = getXCookie();
            if (xCookie == null) {
                sendEof();
                return;
            }

            int l = (int) len;
            int s = 0;
            byte[] foo = new byte[l];
            System.arraycopy(data, off, foo, 0, l);

            if (l < 9) {
                return;
            }

            int plen = (foo[s + 6] & 0xff) * 256 + (foo[s + 7] & 0xff);
            int dlen = (foo[s + 8] & 0xff) * 256 + (foo[s + 9] & 0xff);

            if ((foo[s] & 0xff) == 0x6c) {
                plen = ((plen >>> 8) & 0xff) | ((plen << 8) & 0xff00);
                dlen = ((dlen >>> 8) & 0xff) | ((dlen << 8) & 0xff00);
            }

            if (l < 12 + plen + ((-plen) & 3) + dlen) {
                return;
            }

            byte[] bar = new byte[dlen];
            System.arraycopy(foo, s + 12 + plen + ((-plen) & 3), bar, 0, dlen);

            if (Objects.deepEquals(xCookie, bar)) {
                x11.writeBuffer(new ByteArrayBuffer(foo, s, l));
            } else {
                sendEof();
            }

        } else if (x11.isOpen()) {
            x11.writeBuffer(new ByteArrayBuffer(data, off, (int) len));
        } else if (x11.isClosing() || x11.isClosed()) {
            sendEof();
        }
    }

    @Override
    public void handleEof() throws IOException {
        super.handleEof();
        close(true);
    }

    private void unregisterSelf() {
        getSession().getService(ClientConnectionService.class)
                .unregisterChannel(this);
        close(true);
    }

    protected byte[] getXCookie() {
        final Object xCookie = X11_COOKIE.getOrNull(getSession());
        if (xCookie instanceof byte[]) {
            return (byte[]) xCookie;
        }
        return null;
    }

    protected IoHandler createX11IoHandler() {
        return new X11IoHandler(this, log);
    }
}
