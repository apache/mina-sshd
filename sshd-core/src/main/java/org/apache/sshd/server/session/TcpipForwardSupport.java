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
package org.apache.sshd.server.session;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.EnumSet;
import java.util.Set;

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
import org.apache.sshd.server.ForwardingFilter;

/**
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class TcpipForwardSupport extends IoHandlerAdapter {

    private final ServerSession session;
    private IoAcceptor acceptor;

    public TcpipForwardSupport(ServerSession session) {
        this.session = session;
    }

    public synchronized void initialize() {
        if (this.acceptor == null) {
            NioSocketAcceptor acceptor = new NioSocketAcceptor();
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

    synchronized void request(Buffer buffer, boolean wantReply) throws IOException {
        String address = buffer.getString();
        int port = buffer.getInt();
        InetSocketAddress addr;

        try {
            addr = new InetSocketAddress(address, port);
        } catch (RuntimeException e) {
            addr = null;
        }

        final ForwardingFilter filter = session.getServerFactoryManager().getForwardingFilter();
        if (addr == null || filter == null || !filter.canListen(addr, session)) {
            if (wantReply) {
                buffer = session.createBuffer(SshConstants.Message.SSH_MSG_REQUEST_FAILURE, 0);
                session.writePacket(buffer);
            }
            return;
        }

        initialize();
        Set<SocketAddress> a1 = acceptor.getLocalAddresses();
        try {
            acceptor.bind(addr);
        } catch (IOException bindErr) {
            if (acceptor.getLocalAddresses().isEmpty()) {
                close();
            }
            if (wantReply) {
                buffer = session.createBuffer(SshConstants.Message.SSH_MSG_REQUEST_FAILURE, 0);
                session.writePacket(buffer);
            }
            return;
        }
        Set<SocketAddress> a2 = acceptor.getLocalAddresses();
        a2.removeAll(a1);
        if (a2.size() == 1) {
            SocketAddress a = a2.iterator().next();
            if (a instanceof InetSocketAddress) {
                port = ((InetSocketAddress) a).getPort();
            }
        }
        if (wantReply){
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_REQUEST_SUCCESS, 0);
            buffer.putInt(port);
            session.writePacket(buffer);
        }
    }

    synchronized void cancel(Buffer buffer, boolean wantReply) throws IOException {
        String address = buffer.getString();
        int port = buffer.getInt();
        if (acceptor != null) {
            acceptor.unbind(new InetSocketAddress(address, port));
        }
        if (wantReply) {
            buffer = session.createBuffer(SshConstants.Message.SSH_MSG_REQUEST_SUCCESS, 0);
            session.writePacket(buffer);
        }
    }

    @Override
    public void sessionCreated(IoSession session) throws Exception {
        ChannelForwardedTcpip channel = new ChannelForwardedTcpip(session);
        session.setAttribute(ChannelForwardedTcpip.class, channel);
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
        ChannelForwardedTcpip channel = (ChannelForwardedTcpip) session.getAttribute(ChannelForwardedTcpip.class);
        channel.close(false);
    }

    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {
        ChannelForwardedTcpip channel = (ChannelForwardedTcpip) session.getAttribute(ChannelForwardedTcpip.class);
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

    public static class ChannelForwardedTcpip extends AbstractClientChannel {

        private final IoSession serverSession;

        public ChannelForwardedTcpip(IoSession serverSession) {
            super("forwarded-tcpip");
            this.serverSession = serverSession;
        }

        public synchronized OpenFuture open() throws Exception {
            InetSocketAddress remote = (InetSocketAddress) serverSession.getRemoteAddress();
            InetSocketAddress local = (InetSocketAddress) serverSession.getLocalAddress();
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
            buffer.putString(local.getHostName());
            buffer.putInt(local.getPort());
            buffer.putString(remote.getHostName());
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
