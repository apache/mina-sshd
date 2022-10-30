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
package org.apache.sshd.server.forward;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketAddress;
import java.util.Collections;
import java.util.Objects;

import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelAsyncOutputStream;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.channel.exception.SshChannelOpenException;
import org.apache.sshd.common.forward.ChannelToPortHandler;
import org.apache.sshd.common.forward.Forwarder;
import org.apache.sshd.common.forward.ForwardingTunnelEndpointsProvider;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.ExceptionUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.common.util.threads.CloseableExecutorService;
import org.apache.sshd.common.util.threads.ExecutorServiceCarrier;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.channel.AbstractServerChannel;
import org.apache.sshd.server.forward.TcpForwardingFilter.Type;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class TcpipServerChannel extends AbstractServerChannel implements ForwardingTunnelEndpointsProvider {

    public abstract static class TcpipFactory implements ChannelFactory, ExecutorServiceCarrier {

        private final TcpForwardingFilter.Type type;

        protected TcpipFactory(TcpForwardingFilter.Type type) {
            this.type = type;
        }

        public final TcpForwardingFilter.Type getType() {
            return type;
        }

        @Override
        public final String getName() {
            return type.getName();
        }

        @Override
        public CloseableExecutorService getExecutorService() {
            return null;
        }

        @Override
        public Channel createChannel(Session session) throws IOException {
            return new TcpipServerChannel(getType(), ThreadUtils.noClose(getExecutorService()));
        }
    }

    private final TcpForwardingFilter.Type type;
    private IoConnector connector;
    private ChannelToPortHandler port;
    private ChannelAsyncOutputStream out;
    private SshdSocketAddress tunnelEntrance;
    private SshdSocketAddress tunnelExit;
    private SshdSocketAddress originatorAddress;
    private SocketAddress localAddress;

    public TcpipServerChannel(TcpForwardingFilter.Type type, CloseableExecutorService executor) {
        super("", Collections.emptyList(), executor);
        this.type = Objects.requireNonNull(type, "No channel type specified");
    }

    public TcpForwardingFilter.Type getTcpipChannelType() {
        return type;
    }

    public SocketAddress getLocalAddress() {
        return localAddress;
    }

    public void setLocalAddress(SocketAddress localAddress) {
        this.localAddress = localAddress;
    }

    @Override
    public SshdSocketAddress getTunnelEntrance() {
        return tunnelEntrance;
    }

    @Override
    public SshdSocketAddress getTunnelExit() {
        return tunnelExit;
    }

    public SshdSocketAddress getOriginatorAddress() {
        return originatorAddress;
    }

    @Override
    public void handleWindowAdjust(Buffer buffer) throws IOException {
        super.handleWindowAdjust(buffer);
        if (out != null) {
            out.onWindowExpanded();
        }
    }

    @Override
    protected OpenFuture doInit(Buffer buffer) {
        String hostToConnect = buffer.getString();
        int portToConnect = buffer.getInt();
        String originatorIpAddress = buffer.getString();
        int originatorPort = buffer.getInt();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("doInit({}) Receiving request for direct tcpip:"
                      + " hostToConnect={}, portToConnect={}, originatorIpAddress={}, originatorPort={}",
                    this, hostToConnect, portToConnect, originatorIpAddress, originatorPort);
        }

        SshdSocketAddress address;
        Type channelType = getTcpipChannelType();
        switch (type) {
            case Direct:
                address = new SshdSocketAddress(hostToConnect, portToConnect);
                break;
            case Forwarded: {
                Forwarder forwarder = service.getForwarder();
                address = forwarder.getForwardedPort(portToConnect);
                break;
            }
            default:
                throw new IllegalStateException("Unknown server channel type: " + channelType);
        }

        originatorAddress = new SshdSocketAddress(originatorIpAddress, originatorPort);
        tunnelEntrance = new SshdSocketAddress(hostToConnect, portToConnect);
        tunnelExit = address;

        Session session = getSession();
        FactoryManager manager = Objects.requireNonNull(session.getFactoryManager(), "No factory manager");
        TcpForwardingFilter filter = manager.getTcpForwardingFilter();
        OpenFuture f = new DefaultOpenFuture(this, this);
        try {
            if ((address == null) || (filter == null) || (!filter.canConnect(channelType, address, session))) {
                if (debugEnabled) {
                    log.debug("doInit({})[{}][haveFilter={}] filtered out {}", this, type, filter != null, address);
                }
                try {
                    f.setException(new SshChannelOpenException(getChannelId(),
                            SshConstants.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, "Connection denied"));
                } finally {
                    super.close(true);
                }
                return f;
            }
        } catch (Error e) {
            warn("doInit({})[{}] failed ({}) to consult forwarding filter: {}",
                    session, channelType, e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }

        out = new ChannelAsyncOutputStream(this, SshConstants.SSH_MSG_CHANNEL_DATA) {
            @Override
            @SuppressWarnings("synthetic-access")
            protected CloseFuture doCloseGracefully() {
                // First get the last packets out
                CloseFuture result = super.doCloseGracefully();
                result.addListener(f -> {
                    try {
                        // The channel writes EOF directly through the SSH session
                        sendEof();
                    } catch (IOException e) {
                        session.exceptionCaught(e);
                    }
                });
                return result;
            }
        };

        IoServiceFactory ioServiceFactory = manager.getIoServiceFactory();
        connector = ioServiceFactory.createConnector(new PortIoHandler());

        IoConnectFuture future = connector.connect(address.toInetSocketAddress(), null, getLocalAddress());
        future.addListener(future1 -> handleChannelConnectResult(f, future1));
        return f;
    }

    @Override
    protected boolean mayWrite() {
        // We need to allow writing while closing in order to be able to flush the ChannelAsyncOutputStream.
        return !isClosed();
    }

    protected void handleChannelConnectResult(OpenFuture f, IoConnectFuture future) {
        try {
            if (future.isConnected()) {
                handleChannelOpenSuccess(f, future.getSession());
                return;
            }

            Throwable problem = ExceptionUtils.peelException(future.getException());
            if (problem != null) {
                handleChannelOpenFailure(f, problem);
            }
        } catch (RuntimeException t) {
            Throwable e = ExceptionUtils.peelException(t);
            signalChannelOpenFailure(e);
            try {
                f.setException(e);
            } finally {
                notifyStateChanged(e.getClass().getSimpleName());
            }
        }
    }

    protected void handleChannelOpenSuccess(OpenFuture f, IoSession session) {
        port = createChannelToPortHandler(session);
        String changeEvent = session.toString();
        try {
            signalChannelOpenSuccess();
            f.setOpened();
            // Now that we have sent the SSH_MSG_CHANNEL_OPEN_CONFIRMATION we may read from the port.
            session.resumeRead();
        } catch (Throwable t) {
            Throwable e = ExceptionUtils.peelException(t);
            changeEvent = e.getClass().getSimpleName();
            signalChannelOpenFailure(e);
            f.setException(e);
        } finally {
            notifyStateChanged(changeEvent);
        }
    }

    protected void handleChannelOpenFailure(OpenFuture f, Throwable problem) {
        signalChannelOpenFailure(problem);
        notifyStateChanged(problem.getClass().getSimpleName());
        try {
            if (problem instanceof ConnectException) {
                f.setException(new SshChannelOpenException(getChannelId(), SshConstants.SSH_OPEN_CONNECT_FAILED,
                        problem.getMessage(), problem));
            } else {
                f.setException(problem);
            }
        } finally {
            close(true);
        }
    }

    @Override
    public void handleEof() throws IOException {
        super.handleEof();
        if (port != null) {
            port.handleEof();
        }
    }

    @Override
    protected Closeable getInnerCloseable() {
        return builder()
                .close(out)
                .close(super.getInnerCloseable())
                .close(new AbstractCloseable() {
                    private final CloseableExecutorService executor
                            = ThreadUtils.newCachedThreadPool("TcpIpServerChannel-ConnectorCleanup[" + getSession() + "]");

                    @Override
                    @SuppressWarnings("synthetic-access")
                    protected CloseFuture doCloseGracefully() {
                        executor.submit(() -> connector.close(false));
                        return null;
                    }

                    @Override
                    @SuppressWarnings("synthetic-access")
                    protected void doCloseImmediately() {
                        executor.submit(() -> connector.close(true).addListener(f -> executor.close(true)));
                        super.doCloseImmediately();
                    }
                })
                .build();
    }

    @Override
    protected void doWriteData(byte[] data, int off, long len) throws IOException {
        port.sendToPort(SshConstants.SSH_MSG_CHANNEL_DATA, data, off, len);
    }

    @Override
    protected void doWriteExtendedData(byte[] data, int off, long len) throws IOException {
        throw new UnsupportedOperationException(getTcpipChannelType() + " Tcpip channel does not support extended data");
    }

    protected ChannelToPortHandler createChannelToPortHandler(IoSession session) {
        return new ChannelToPortHandler(session, this);
    }

    class PortIoHandler implements IoHandler {

        PortIoHandler() {
            super();
        }

        @Override
        public void messageReceived(IoSession session, Readable message) throws Exception {
            if (isClosing()) {
                if (log.isDebugEnabled()) {
                    log.debug("messageReceived({}) Ignoring write to channel {} in CLOSING state", session,
                            TcpipServerChannel.this);
                }
            } else {
                int length = message.available();
                Buffer buffer = new ByteArrayBuffer(length, false);
                buffer.putBuffer(message);
                session.suspendRead();
                ThreadUtils.runAsInternal(() -> out.writeBuffer(buffer).addListener(f -> {
                    session.resumeRead();
                    Throwable e = f.getException();
                    if (e != null) {
                        log.warn("messageReceived({}) channel={} signal close immediately=true due to {}[{}]", session,
                                TcpipServerChannel.this, e.getClass().getSimpleName(), e.getMessage());
                        close(true);
                    } else if (log.isTraceEnabled()) {
                        log.trace("messageReceived({}) channel={} message forwarded", session, TcpipServerChannel.this);
                    }
                }));
            }
        }

        @Override
        public void sessionCreated(IoSession session) throws Exception {
            // Delay reading until after the SSH_MSG_CHANNEL_OPEN_CONFIRMATION was sent. Otherwise we risk trying to
            // send channel data before having confirmed the channel opening.
            session.suspendRead();
        }

        @Override
        public void sessionClosed(IoSession session) throws Exception {
            close(false);
        }

        @Override
        public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
            boolean immediately = !session.isOpen();
            if (log.isDebugEnabled()) {
                log.debug("exceptionCaught({}) signal close immediately={}", TcpipServerChannel.this, immediately, cause);
            }
            close(immediately);
        }
    }
}
