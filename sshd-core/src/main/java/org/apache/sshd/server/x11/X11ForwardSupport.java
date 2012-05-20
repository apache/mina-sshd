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
package org.apache.sshd.server.x11;

import java.io.IOException;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.util.EnumSet;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoEventType;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.executor.ExecutorFilter;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.sshd.client.channel.AbstractClientChannel;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class X11ForwardSupport extends IoHandlerAdapter {

    private static String xauthCommand = System.getProperty("sshd.xauthCommand", "xauth");

    public static final int X11_DISPLAY_OFFSET = 10;
    public static final int MAX_DISPLAYS = 1000;

    /**
     * Key for the user DISPLAY variable
     */
    public static final String ENV_DISPLAY = "DISPLAY";

    protected final Logger log = LoggerFactory.getLogger(getClass());

    private final ServerSession session;
    private IoAcceptor acceptor;

    public X11ForwardSupport(ServerSession session) {
        super();
        this.session = session;
    }

    public synchronized void initialize() {
        if (this.acceptor == null) {
            NioSocketAcceptor acceptor = session.getServerFactoryManager().getX11ForwardingAcceptorFactory().createNioSocketAcceptor(session);
            acceptor.setHandler(this);
            acceptor.setReuseAddress(true);
            acceptor.getFilterChain().addLast(
                    "executor",
                    new ExecutorFilter(EnumSet.complementOf(
                            EnumSet.of(IoEventType.SESSION_CREATED)).toArray(
                            new IoEventType[0])));
            this.acceptor = acceptor;
        }
    }

    public synchronized void close() {
        if (acceptor != null) {
            acceptor.dispose();
            acceptor = null;
        }
    }

    public synchronized String createDisplay(boolean singleConnection,
                                             String authenticationProtocol, String authenticationCookie,
                                             int screen) throws IOException {

        initialize();

        int displayNumber, port;
        InetSocketAddress addr = null;

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
            if (acceptor.getLocalAddresses().isEmpty()) {
                close();
            }
            return null;
        }

        // only support non windows systems
        String os = System.getProperty("os.name").toLowerCase();
        if (os.indexOf("windows") < 0) {
            try {
                String authDisplay = "unix:" + displayNumber + "." + screen;
                Process p = new ProcessBuilder(xauthCommand, "remove", authDisplay).start();
                int result = p.waitFor();
                if (result == 0) {
                    p = new ProcessBuilder(xauthCommand, "add", authDisplay, authenticationProtocol, authenticationCookie).start();
                    result = p.waitFor();
                }
            } catch (Exception e) {
                log.error("Could not run xauth", e);
                return null;
            }
            return "localhost:" + displayNumber + "." + screen;
        } else {
            return null;
        }
    }

    @Override
    public void sessionCreated(IoSession session) throws Exception {
        ChannelForwardedX11 channel = new ChannelForwardedX11(session);
        session.setAttribute(ChannelForwardedX11.class, channel);
        this.session.registerChannel(channel);
        OpenFuture future = channel.open().await();
        Throwable t = future.getException();
        if (t instanceof Exception) {
            throw (Exception) t;
        } else if (t != null) {
            throw new Exception(t);
        }
    }

    @Override
    public void sessionClosed(IoSession session) throws Exception {
        ChannelForwardedX11 channel = (ChannelForwardedX11) session.getAttribute(ChannelForwardedX11.class);
        if ( channel != null ){
        	channel.close(false);
        }
    }

    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {
        ChannelForwardedX11 channel = (ChannelForwardedX11) session.getAttribute(ChannelForwardedX11.class);
        IoBuffer ioBuffer = (IoBuffer) message;
        int r = ioBuffer.remaining();
        byte[] b = new byte[r];
        ioBuffer.get(b, 0, r);
        channel.getOut().write(b, 0, r);
        channel.getOut().flush();
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

        public synchronized OpenFuture open() throws Exception {
            InetSocketAddress remote = (InetSocketAddress) serverSession.getRemoteAddress();
            if (closeFuture.isClosed()) {
                throw new SshException("Session has been closed");
            }
            openFuture = new DefaultOpenFuture(lock);
            log.info("Send SSH_MSG_CHANNEL_OPEN on channel {}", id);
            Buffer buffer = session.createBuffer(SshConstants.Message.SSH_MSG_CHANNEL_OPEN, 0);
            buffer.putString(type);
            buffer.putInt(id);
            buffer.putInt(localWindow.getSize());
            buffer.putInt(localWindow.getPacketSize());
            buffer.putString(remote.getAddress().getHostAddress());
            buffer.putInt(remote.getPort());
            session.writePacket(buffer);
            return openFuture;
        }

        @Override
        protected synchronized void doOpen() throws Exception {
            out = new ChannelOutputStream(this, remoteWindow, log, SshConstants.Message.SSH_MSG_CHANNEL_DATA);
        }

        @Override
        protected synchronized void doClose() {
            serverSession.close(false);
            super.doClose();
        }

        protected synchronized void doWriteData(byte[] data, int off, int len) throws IOException {
            IoBuffer buf = IoBuffer.allocate(len);
            buf.put(data, off, len);
            buf.flip();
            localWindow.consumeAndCheck(len);
            serverSession.write(buf);
        }

        @Override
        public void handleEof() throws IOException {
            super.handleEof();
            serverSession.close(false);
        }
    }

}
