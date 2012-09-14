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
package org.apache.sshd.client.session;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.service.IoAcceptor;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoEventType;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.executor.ExecutorFilter;
import org.apache.mina.transport.socket.nio.NioSocketAcceptor;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.client.SshdSocketAddress;
import org.apache.sshd.client.channel.AbstractClientChannel;
import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.util.Buffer;


/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class TcpipForwardSupport extends IoHandlerAdapter {

    private final ClientSessionImpl session;
    private IoAcceptor acceptor;
    private Map<Integer, SshdSocketAddress> forwards = new HashMap<Integer, SshdSocketAddress>();

    public TcpipForwardSupport(ClientSessionImpl session) {
        this.session = session;
    }

    public synchronized void initialize() {
        if (this.acceptor == null) {
            NioSocketAcceptor acceptor = session.getClientFactoryManager().getTcpipForwardingAcceptorFactory().createNioSocketAcceptor(session);
            acceptor.setHandler(this);
            acceptor.setReuseAddress(true);
            acceptor.getFilterChain().addLast("executor", new ExecutorFilter(EnumSet.complementOf(EnumSet.of(IoEventType.SESSION_CREATED)).toArray(new IoEventType[0])));
            this.acceptor = acceptor;
        }
    }

    public synchronized void close() {
        if (acceptor != null) {
            acceptor.dispose();
            acceptor = null;
        }
    }

    synchronized void request(SshdSocketAddress local, SshdSocketAddress remote) throws IOException {
        initialize();
        boolean ok = false;
        if (forwards.get(local.getPort()) != null) {
            throw new IOException("The local port is already forwarded");
        }
        acceptor.bind(local.toInetSocketAddress());
        forwards.put(local.getPort(), remote);
    }

    synchronized void cancel(SshdSocketAddress local) throws IOException {
        forwards.remove(local.getPort());
        if (acceptor != null) {
            acceptor.unbind(local.toInetSocketAddress());
        }
    }

    @Override
    public void sessionCreated(final IoSession session) throws Exception {
        SshdSocketAddress remote = forwards.get(((InetSocketAddress) session.getLocalAddress()).getPort());
        final ChannelForwardedTcpip channel = new ChannelForwardedTcpip(session, remote);
        session.setAttribute(ChannelForwardedTcpip.class, channel);
        this.session.registerChannel(channel);
        channel.open().addListener(new SshFutureListener<OpenFuture>() {
            public void operationComplete(OpenFuture future) {
                Throwable t = future.getException();
                if (t != null) {
                    TcpipForwardSupport.this.session.unregisterChannel(channel);
                    channel.close(false);
                }
            }
        });
    }

    @Override
    public void sessionClosed(IoSession session) throws Exception {
        ChannelForwardedTcpip channel = (ChannelForwardedTcpip) session.getAttribute(ChannelForwardedTcpip.class);
        if (channel != null) {
        	channel.close(false);
        }
    }

    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {
        ChannelForwardedTcpip channel = (ChannelForwardedTcpip) session.getAttribute(ChannelForwardedTcpip.class);
        IoBuffer ioBuffer = (IoBuffer) message;
        int r = ioBuffer.remaining();
        byte[] b = new byte[r];
        ioBuffer.get(b, 0, r);
        channel.waitFor(ClientChannel.OPENED | ClientChannel.CLOSED, Long.MAX_VALUE);
        channel.getOut().write(b, 0, r);
        channel.getOut().flush();
    }

    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        cause.printStackTrace();
        session.close(false);
    }

    public static class ChannelForwardedTcpip extends AbstractClientChannel {

        private final IoSession serverSession;
        private final SshdSocketAddress remote;

        public ChannelForwardedTcpip(IoSession serverSession, SshdSocketAddress remote) {
            super("direct-tcpip");
            this.serverSession = serverSession;
            this.remote = remote;
        }


        public OpenFuture getOpenFuture() {
            return openFuture;
        }

        public synchronized OpenFuture open() throws Exception {
            InetSocketAddress origin = (InetSocketAddress) serverSession.getRemoteAddress();
            InetSocketAddress remote = this.remote.toInetSocketAddress();
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
            buffer.putString(origin.getAddress().getHostAddress());
            buffer.putInt(origin.getPort());
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
