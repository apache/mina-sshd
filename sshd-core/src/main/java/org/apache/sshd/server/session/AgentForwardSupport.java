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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.EnumSet;
import java.util.Set;

/**
 * The server side fake agent, acting as an agent, but actually forwarding the requests to the auth channel on the client side.
 */
public class AgentForwardSupport extends IoHandlerAdapter {

    private final ServerSession session;
    private IoAcceptor acceptor;

    public AgentForwardSupport(ServerSession session) {
        this.session = session;
    }

    public synchronized int initialize() throws IOException {
        if (this.acceptor == null) {
            NioSocketAcceptor acceptor = new NioSocketAcceptor();
            acceptor.setHandler(this);
            acceptor.setReuseAddress(true);
            acceptor.getFilterChain().addLast("executor", new ExecutorFilter(EnumSet.complementOf(EnumSet.of(IoEventType.SESSION_CREATED)).toArray(new IoEventType[0])));
            this.acceptor = acceptor;
            SocketAddress address = new InetSocketAddress("localhost", 0);
            acceptor.bind(address);
        }
        return ((InetSocketAddress) acceptor.getLocalAddress()).getPort();
    }

    public synchronized void close() {
        if (acceptor != null) {
            acceptor.dispose();
            acceptor = null;
        }
    }

    @Override
    public void sessionCreated(IoSession session) throws Exception {
        AgentForwardedChannel channel = new AgentForwardedChannel(session);
        session.setAttribute(AgentForwardedChannel.class, channel);
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
        AgentForwardedChannel channel = (AgentForwardedChannel) session.getAttribute(AgentForwardedChannel.class);
        channel.close(false);
    }

    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {
        AgentForwardedChannel channel = (AgentForwardedChannel) session.getAttribute(AgentForwardedChannel.class);
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

    public static class AgentForwardedChannel extends AbstractClientChannel {

        private final IoSession serverSession;

        public AgentForwardedChannel(IoSession serverSession) {
            super("auth-agent@openssh.com");
            this.serverSession = serverSession;
        }

        public synchronized OpenFuture open() throws Exception {
            return internalOpen();
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
