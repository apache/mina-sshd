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
import java.io.OutputStream;
import java.net.ConnectException;
import java.util.Collection;
import java.util.Objects;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.channel.exception.SshChannelOpenException;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.common.util.threads.ExecutorServiceCarrier;
import org.apache.sshd.common.util.threads.ThreadUtils;
import org.apache.sshd.server.channel.AbstractServerChannel;
import org.apache.sshd.server.forward.TcpForwardingFilter.Type;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class TcpipServerChannel extends AbstractServerChannel {
    public abstract static class TcpipFactory implements ChannelFactory, ExecutorServiceCarrier {
        private final ForwardingFilter.Type type;

        protected TcpipFactory(ForwardingFilter.Type type) {
            this.type = type;
        }

        public final ForwardingFilter.Type getType() {
            return type;
        }

        @Override
        public final String getName() {
            return type.getName();
        }

        @Override   // user can override to provide an alternative
        public ExecutorService getExecutorService() {
            return null;
        }

        @Override
        public boolean isShutdownOnExit() {
            return false;
        }

        @Override
        public Channel create() {
            TcpipServerChannel channel = new TcpipServerChannel(getType());
            channel.setExecutorService(getExecutorService());
            channel.setShutdownOnExit(isShutdownOnExit());
            return channel;
        }
    }

    private final ForwardingFilter.Type type;
    private IoConnector connector;
    private IoSession ioSession;
    private OutputStream out;

    public TcpipServerChannel(ForwardingFilter.Type type) {
        this.type = Objects.requireNonNull(type, "No channel type specified");
    }

    public ForwardingFilter.Type getTcpipChannelType() {
        return type;
    }

    @Override
    protected OpenFuture doInit(Buffer buffer) {
        String hostToConnect = buffer.getString();
        int portToConnect = buffer.getInt();
        String originatorIpAddress = buffer.getString();
        int originatorPort = buffer.getInt();
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("doInit({}) Receiving request for direct tcpip: hostToConnect={}, portToConnect={}, originatorIpAddress={}, originatorPort={}",
                      this, hostToConnect, portToConnect, originatorIpAddress, originatorPort);
        }

        SshdSocketAddress address;
        Type channelType = getTcpipChannelType();
        switch (type) {
            case Direct:
                address = new SshdSocketAddress(hostToConnect, portToConnect);
                break;
            case Forwarded: {
                org.apache.sshd.common.forward.ForwardingFilter ff = service.getForwardingFilter();
                address = ff.getForwardedPort(portToConnect);
                break;
            }
            default:
                throw new IllegalStateException("Unknown server channel type: " + channelType);
        }

        Session session = getSession();
        FactoryManager manager = Objects.requireNonNull(session.getFactoryManager(), "No factory manager");
        TcpForwardingFilter filter = manager.getTcpForwardingFilter();
        OpenFuture f = new DefaultOpenFuture(this, this);
        try {
            if ((address == null) || (filter == null) || (!filter.canConnect(channelType, address, session))) {
                if (debugEnabled) {
                    log.debug("doInit(" + this + ")[" + type + "][haveFilter=" + (filter != null) + "] filtered out " + address);
                }
                try {
                    f.setException(new SshChannelOpenException(getId(), SshConstants.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, "Connection denied"));
                } finally {
                    super.close(true);
                }
                return f;
            }
        } catch (Error e) {
            log.warn("doInit({})[{}] failed ({}) to consult forwarding filter: {}",
                     session, channelType, e.getClass().getSimpleName(), e.getMessage());
            if (debugEnabled) {
                log.debug("doInit(" + this + ")[" + type + "] filter consultation failure details", e);
            }
            throw new RuntimeSshException(e);
        }

        // TODO: revisit for better threading. Use async io ?
        out = new ChannelOutputStream(this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true);
        IoHandler handler = new IoHandler() {
            @Override
            @SuppressWarnings("synthetic-access")
            public void messageReceived(IoSession session, Readable message) throws Exception {
                if (isClosing()) {
                    if (debugEnabled) {
                        log.debug("doInit({}) Ignoring write to channel in CLOSING state", TcpipServerChannel.this);
                    }
                } else {
                    Buffer buffer = new ByteArrayBuffer(message.available() + Long.SIZE, false);
                    buffer.putBuffer(message);
                    out.write(buffer.array(), buffer.rpos(), buffer.available());
                    out.flush();
                }
            }

            @Override
            public void sessionCreated(IoSession session) throws Exception {
                // ignored
            }

            @Override
            public void sessionClosed(IoSession session) throws Exception {
                close(false);
            }

            @Override
            @SuppressWarnings("synthetic-access")
            public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
                boolean immediately = !session.isOpen();
                if (debugEnabled) {
                    log.debug("exceptionCaught({}) signal close immediately={} due to {}[{}]",
                            TcpipServerChannel.this, immediately, cause.getClass().getSimpleName(), cause.getMessage());
                }
                close(immediately);
            }
        };

        IoServiceFactory ioServiceFactory = manager.getIoServiceFactory();
        connector = ioServiceFactory.createConnector(handler);
        IoConnectFuture future = connector.connect(address.toInetSocketAddress());
        future.addListener(future1 -> handleChannelConnectResult(f, future1));
        return f;
    }

    protected void handleChannelConnectResult(OpenFuture f, IoConnectFuture future) {
        try {
            if (future.isConnected()) {
                handleChannelOpenSuccess(f, future.getSession());
                return;
            }

            Throwable problem = GenericUtils.peelException(future.getException());
            if (problem != null) {
                handleChannelOpenFailure(f, problem);
            }
        } catch (RuntimeException t) {
            Throwable e = GenericUtils.peelException(t);
            signalChannelOpenFailure(e);
            try {
                f.setException(e);
            } finally {
                notifyStateChanged(e.getClass().getSimpleName());
            }
        }
    }

    protected void handleChannelOpenSuccess(OpenFuture f, IoSession session) {
        ioSession = session;

        String changeEvent = session.toString();
        try {
            signalChannelOpenSuccess();
            f.setOpened();
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
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
                f.setException(new SshChannelOpenException(getId(), SshConstants.SSH_OPEN_CONNECT_FAILED, problem.getMessage(), problem));
            } else {
                f.setException(problem);
            }
        } finally {
            close(true);
        }
    }

    @Override
    public CloseFuture close(boolean immediately) {
        boolean debugEnabled = log.isDebugEnabled();
        /*
         * In case of graceful shutdown (e.g. when the remote channel is gently closed)
         * we also need to close the ChannelOutputStream which flushes remaining buffer
         * and sends SSH_MSG_CHANNEL_EOF back to the client.
         */
        if ((!immediately) && (out != null)) {
            try {
                if (debugEnabled) {
                    log.debug("Closing channel output stream of {}", this);
                }

                out.close();
            } catch (IOException | RuntimeException ignored) {
                if (debugEnabled) {
                    log.debug("{} while closing channel output stream of {}: {}",
                        ignored.getClass().getSimpleName(), this, ignored.getMessage());
                }
            }
        }

        CloseFuture closingFeature = super.close(immediately);

        // We also need to dispose of the connector, but unfortunately we
        // are being invoked by the connector thread or the connector's
        // own processor thread. Disposing of the connector within either
        // causes deadlock. Instead create a thread to dispose of the
        // connector in the background.
        ExecutorService service = getExecutorService();

        // allocate a temporary executor service if none provided
        ExecutorService executors = (service == null)
                ? ThreadUtils.newSingleThreadExecutor("TcpIpServerChannel-ConnectorCleanup[" + getSession() + "]")
                : service;
        // shutdown the temporary executor service if had to create it
        boolean shutdown = (executors != service) || isShutdownOnExit();

        return builder().when(closingFeature).run(toString(), () -> {
            executors.submit(() -> {
                try {
                    if (debugEnabled) {
                        log.debug("disposing connector: {} for: {}", connector, TcpipServerChannel.this);
                    }
                    connector.close(immediately);
                } finally {
                    if (shutdown && (!executors.isShutdown())) {
                        Collection<Runnable> runners = executors.shutdownNow();
                        if (debugEnabled) {
                            log.debug("destroy({}) - shutdown executor service - runners count={}",
                                      TcpipServerChannel.this, runners.size());
                        }
                    }
                }
            });
        }).build().close(false);
    }

    @Override
    protected void doWriteData(byte[] data, int off, long len) throws IOException {
        ValidateUtils.checkTrue(len <= Integer.MAX_VALUE, "Data length exceeds int boundaries: %d", len);
        // Make sure we copy the data as the incoming buffer may be reused
        Buffer buf = ByteArrayBuffer.getCompactClone(data, off, (int) len);
        ioSession.writePacket(buf).addListener(future -> {
            if (future.isWritten()) {
                handleWriteDataSuccess(SshConstants.SSH_MSG_CHANNEL_DATA, buf.array(), 0, (int) len);
            } else {
                handleWriteDataFailure(SshConstants.SSH_MSG_CHANNEL_DATA, buf.array(), 0, (int) len, future.getException());
            }
        });
    }

    @Override
    protected void doWriteExtendedData(byte[] data, int off, long len) throws IOException {
        throw new UnsupportedOperationException(getTcpipChannelType() + "Tcpip channel does not support extended data");
    }

    protected void handleWriteDataSuccess(byte cmd, byte[] data, int off, int len) {
        Session session = getSession();
        try {
            Window wLocal = getLocalWindow();
            wLocal.consumeAndCheck(len);
        } catch (Throwable e) {
            if (log.isDebugEnabled()) {
                log.debug("handleWriteDataSuccess({})[{}] failed ({}) to consume len={}: {}",
                          this, SshConstants.getCommandMessageName(cmd & 0xFF),
                          e.getClass().getSimpleName(), len, e.getMessage());
            }
            session.exceptionCaught(e);
        }
    }

    protected void handleWriteDataFailure(byte cmd, byte[] data, int off, int len, Throwable t) {
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("handleWriteDataFailure({})[{}] failed ({}) to write len={}: {}",
                      this, SshConstants.getCommandMessageName(cmd & 0xFF),
                      t.getClass().getSimpleName(), len, t.getMessage());
        }

        if (log.isTraceEnabled()) {
            log.trace("handleWriteDataFailure(" + this + ")[" + SshConstants.getCommandMessageName(cmd & 0xFF) + "]"
                    + " len=" + len + " write failure details", t);
        }

        if (ioSession.isOpen()) {
            // SSHD-795 IOException (Broken pipe) on a socket local forwarding channel causes SSH client-server connection down
            if (debugEnabled) {
                log.debug("handleWriteDataFailure({})[{}] closing session={}",
                        this, SshConstants.getCommandMessageName(cmd & 0xFF), ioSession);
            }
            close(false);
        } else {
            // In case remote entity has closed the socket (the ioSession), data coming from the SSH channel should be simply discarded
            if (debugEnabled) {
                log.debug("Ignoring writeDataFailure {} because ioSession {} is already closing ", t, ioSession);
            }
        }
    }
}
