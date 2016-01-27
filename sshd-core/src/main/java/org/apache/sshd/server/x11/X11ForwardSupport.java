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
package org.apache.sshd.server.x11;

import java.io.IOException;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.channel.AbstractClientChannel;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.closeable.AbstractInnerCloseable;
import org.apache.sshd.common.util.net.SshdSocketAddress;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class X11ForwardSupport extends AbstractInnerCloseable implements IoHandler {

    /**
     * Configuration value on the {@link FactoryManager} to control the
     * channel open timeout. If not specified then {@link #DEFAULT_CHANNEL_OPEN_TIMEOUT}
     * value is used
     */
    public static final String CHANNEL_OPEN_TIMEOUT_PROP = "x11-fwd-open-timeout";
    public static final long DEFAULT_CHANNEL_OPEN_TIMEOUT = TimeUnit.SECONDS.toMillis(30L);

    public static final int X11_DISPLAY_OFFSET = 10;
    public static final int MAX_DISPLAYS = 1000;

    /**
     * Key for the user DISPLAY variable
     */
    public static final String ENV_DISPLAY = "DISPLAY";

    private static final String XAUTH_COMMAND = System.getProperty("sshd.XAUTH_COMMAND", "xauth");

    private final ConnectionService service;
    private IoAcceptor acceptor;

    public X11ForwardSupport(ConnectionService service) {
        this.service = service;
    }

    @Override
    public void close() throws IOException {
        close(true);
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder().close(acceptor).build();
    }

    public synchronized String createDisplay(boolean singleConnection,
                                             String authenticationProtocol, String authenticationCookie,
                                             int screen) throws IOException {

        if (isClosed()) {
            throw new IllegalStateException("X11ForwardSupport is closed");
        }
        if (isClosing()) {
            throw new IllegalStateException("X11ForwardSupport is closing");
        }

        if (acceptor == null) {
            Session session = ValidateUtils.checkNotNull(service.getSession(), "No session");
            FactoryManager manager = ValidateUtils.checkNotNull(session.getFactoryManager(), "No factory manager");
            IoServiceFactory factory = ValidateUtils.checkNotNull(manager.getIoServiceFactory(), "No I/O service factory");
            acceptor = factory.createAcceptor(this);
        }

        int displayNumber;
        int port;
        InetSocketAddress addr;

        for (displayNumber = X11_DISPLAY_OFFSET; displayNumber < MAX_DISPLAYS; displayNumber++) {
            port = 6000 + displayNumber;
            try {
                addr = new InetSocketAddress("127.0.0.1", port);
                acceptor.bind(addr);
                break;
            } catch (BindException bindErr) {
                // try until bind succesful or max is reached
            }
        }

        if (displayNumber >= MAX_DISPLAYS) {
            log.error("Failed to allocate internet-domain X11 display socket.");
            if (acceptor.getBoundAddresses().isEmpty()) {
                close();
            }
            return null;
        }

        // only support non windows systems
        String os = System.getProperty("os.name").toLowerCase();
        if (!os.contains("windows")) {
            try {
                String authDisplay = "unix:" + displayNumber + "." + screen;
                Process p = new ProcessBuilder(XAUTH_COMMAND, "remove", authDisplay).start();
                int result = p.waitFor();
                if (result == 0) {
                    p = new ProcessBuilder(XAUTH_COMMAND, "add", authDisplay, authenticationProtocol, authenticationCookie).start();
                    result = p.waitFor();
                }
            } catch (Throwable e) {
                log.error("Could not run xauth", e);
                return null;
            }
            return SshdSocketAddress.LOCALHOST_NAME + ":" + displayNumber + "." + screen;
        } else {
            return null;
        }
    }

    @Override
    public void sessionCreated(IoSession session) throws Exception {
        ChannelForwardedX11 channel = new ChannelForwardedX11(session);
        session.setAttribute(ChannelForwardedX11.class, channel);
        this.service.registerChannel(channel);
        channel.open().verify(PropertyResolverUtils.getLongProperty(channel, CHANNEL_OPEN_TIMEOUT_PROP, DEFAULT_CHANNEL_OPEN_TIMEOUT));
    }

    @Override
    public void sessionClosed(IoSession session) throws Exception {
        ChannelForwardedX11 channel = (ChannelForwardedX11) session.getAttribute(ChannelForwardedX11.class);
        if (channel != null) {
            channel.close(false);
        }
    }

    @Override
    public void messageReceived(IoSession session, Readable message) throws Exception {
        ChannelForwardedX11 channel = (ChannelForwardedX11) session.getAttribute(ChannelForwardedX11.class);
        Buffer buffer = new ByteArrayBuffer(message.available() + Long.SIZE, false);
        buffer.putBuffer(message);

        OutputStream outputStream = channel.getInvertedIn();
        outputStream.write(buffer.array(), buffer.rpos(), buffer.available());
        outputStream.flush();
    }

    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        cause.printStackTrace();
        session.close(false);
    }

    public static class ChannelForwardedX11 extends AbstractClientChannel {
        private final IoSession serverSession;

        public ChannelForwardedX11(IoSession serverSession) {
            super("x11");
            this.serverSession = serverSession;
        }

        @Override
        public synchronized OpenFuture open() throws IOException {
            InetSocketAddress remote = (InetSocketAddress) serverSession.getRemoteAddress();
            if (closeFuture.isClosed()) {
                throw new SshException("Session has been closed");
            }
            openFuture = new DefaultOpenFuture(lock);

            Session session = getSession();
            if (log.isDebugEnabled()) {
                log.debug("open({}) SSH_MSG_CHANNEL_OPEN", this);
            }

            InetAddress remoteAddress = remote.getAddress();
            String remoteHost = remoteAddress.getHostAddress();
            Window wLocal = getLocalWindow();
            Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_CHANNEL_OPEN,
                    remoteHost.length() + type.length() + Integer.SIZE);
            buffer.putString(type);
            buffer.putInt(getId());
            buffer.putInt(wLocal.getSize());
            buffer.putInt(wLocal.getPacketSize());
            buffer.putString(remoteHost);
            buffer.putInt(remote.getPort());
            writePacket(buffer);
            return openFuture;
        }

        @Override
        protected synchronized void doOpen() throws IOException {
            if (streaming == Streaming.Async) {
                throw new IllegalArgumentException("Asynchronous streaming isn't supported yet on this channel");
            }
            out = new ChannelOutputStream(this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true);
            invertedIn = out;
        }

        @Override
        protected Closeable getInnerCloseable() {
            return builder().sequential(serverSession, super.getInnerCloseable()).build();
        }

        @Override
        protected synchronized void doWriteData(byte[] data, int off, int len) throws IOException {
            Window wLocal = getLocalWindow();
            wLocal.consumeAndCheck(len);
            // use a clone in case data buffer is re-used
            serverSession.write(ByteArrayBuffer.getCompactClone(data, off, len));
        }

        @Override
        public void handleEof() throws IOException {
            super.handleEof();
            serverSession.close(false);
        }
    }

}
