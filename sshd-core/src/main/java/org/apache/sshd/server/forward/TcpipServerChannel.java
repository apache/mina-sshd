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
import java.util.concurrent.ExecutorService;

import org.apache.sshd.client.future.DefaultOpenFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.channel.ChannelListener;
import org.apache.sshd.common.channel.ChannelOutputStream;
import org.apache.sshd.common.channel.OpenChannelException;
import org.apache.sshd.common.channel.Window;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
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
        this.type = type;
    }

    public final ForwardingFilter.Type getChannelType() {
        return type;
    }

    @Override
    protected OpenFuture doInit(Buffer buffer) {
        String hostToConnect = buffer.getString();
        int portToConnect = buffer.getInt();
        String originatorIpAddress = buffer.getString();
        int originatorPort = buffer.getInt();
        if (log.isDebugEnabled()) {
            log.debug("doInit({}) Receiving request for direct tcpip: hostToConnect={}, portToConnect={}, originatorIpAddress={}, originatorPort={}",
                      this, hostToConnect, portToConnect, originatorIpAddress, originatorPort);
        }

        final SshdSocketAddress address;
        switch (type) {
            case Direct:
                address = new SshdSocketAddress(hostToConnect, portToConnect);
                break;
            case Forwarded:
                address = service.getTcpipForwarder().getForwardedPort(portToConnect);
                break;
            default:
                throw new IllegalStateException("Unknown server channel type: " + type);
        }

        Session session = getSession();
        FactoryManager manager = ValidateUtils.checkNotNull(session.getFactoryManager(), "No factory manager");
        ForwardingFilter filter = manager.getTcpipForwardingFilter();
        final OpenFuture f = new DefaultOpenFuture(this);
        try {
            if ((address == null) || (filter == null) || (!filter.canConnect(type, address, session))) {
                if (log.isDebugEnabled()) {
                    log.debug("doInit(" + this + ")[" + type + "][haveFilter=" + (filter != null) + "] filtered out " + address);
                }
                super.close(true);
                f.setException(new OpenChannelException(SshConstants.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, "Connection denied"));
                return f;
            }
        } catch (Error e) {
            log.warn("doInit({})[{}] failed ({}) to consult forwarding filter: {}",
                     session, type, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("doInit(" + this + ")[" + type + "] filter consultation failure details", e);
            }
            throw new RuntimeSshException(e);
        }

        // TODO: revisit for better threading. Use async io ?
        out = new ChannelOutputStream(this, getRemoteWindow(), log, SshConstants.SSH_MSG_CHANNEL_DATA, true);
        IoHandler handler = new IoHandler() {
            @SuppressWarnings("synthetic-access")
            @Override
            public void messageReceived(IoSession session, Readable message) throws Exception {
                if (isClosing()) {
                    if (log.isDebugEnabled()) {
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
            public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
                close(true);
            }
        };

        connector = manager.getIoServiceFactory().createConnector(handler);
        IoConnectFuture future = connector.connect(address.toInetSocketAddress());
        future.addListener(new SshFutureListener<IoConnectFuture>() {
            @Override
            public void operationComplete(IoConnectFuture future) {
                handleChannelConnectResult(f, future);
            }
        });
        return f;
    }

    protected void handleChannelConnectResult(OpenFuture f, IoConnectFuture future) {
        ChannelListener listener = getChannelListenerProxy();
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
            try {
                listener.channelOpenFailure(this, e);
            } catch (Throwable err) {
                Throwable ignored = GenericUtils.peelException(err);
                log.warn("handleChannelConnectResult({})[exception] failed ({}) to inform listener of open failure={}: {}",
                         this, ignored.getClass().getSimpleName(), e.getClass().getSimpleName(), ignored.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("handleChannelConnectResult(" + this + ")[exception] listener exception details", ignored);
                }
                if (log.isTraceEnabled()) {
                    Throwable[] suppressed = ignored.getSuppressed();
                    if (GenericUtils.length(suppressed) > 0) {
                        for (Throwable s : suppressed) {
                            log.trace("handleChannelConnectResult(" + this + ") suppressed channel open failure signalling", s);
                        }
                    }
                }
            }
            f.setException(e);
        }
    }

    protected void handleChannelOpenSuccess(OpenFuture f, IoSession session) {
        ioSession = session;

        ChannelListener listener = getChannelListenerProxy();
        try {
            listener.channelOpenSuccess(this);
            f.setOpened();
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            try {
                listener.channelOpenFailure(this, e);
            } catch (Throwable err) {
                Throwable ignored = GenericUtils.peelException(err);
                log.warn("handleChannelOpenSuccess({}) failed ({}) to inform listener of open failure={}: {}",
                         this, ignored.getClass().getSimpleName(), e.getClass().getSimpleName(), ignored.getMessage());
                if (log.isDebugEnabled()) {
                    log.debug("doInit(" + this + ") listener inform failure details", ignored);
                }
                if (log.isTraceEnabled()) {
                    Throwable[] suppressed = ignored.getSuppressed();
                    if (GenericUtils.length(suppressed) > 0) {
                        for (Throwable s : suppressed) {
                            log.trace("handleChannelOpenSuccess(" + this + ") suppressed channel open failure signalling", s);
                        }
                    }
                }
            }
            f.setException(e);
        }
    }

    protected void handleChannelOpenFailure(OpenFuture f, Throwable problem) {
        ChannelListener listener = getChannelListenerProxy();
        try {
            listener.channelOpenFailure(this, problem);
        } catch (Throwable err) {
            Throwable ignored = GenericUtils.peelException(err);
            log.warn("handleChannelOpenFailure({}) failed ({}) to inform listener of open failure={}: {}",
                     this, ignored.getClass().getSimpleName(), problem.getClass().getSimpleName(), ignored.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("handleChannelOpenFailure(" + this + ") listener inform open failure details", ignored);
            }
            if (log.isTraceEnabled()) {
                Throwable[] suppressed = ignored.getSuppressed();
                if (GenericUtils.length(suppressed) > 0) {
                    for (Throwable s : suppressed) {
                        log.trace("handleOpenChannelFailure(" + this + ") suppressed channel open failure signalling", s);
                    }
                }
            }
        }

        closeImmediately0();

        if (problem instanceof ConnectException) {
            f.setException(new OpenChannelException(SshConstants.SSH_OPEN_CONNECT_FAILED, problem.getMessage(), problem));
        } else {
            f.setException(problem);
        }

    }
    private void closeImmediately0() {
        // We need to close the channel immediately to remove it from the
        // server session's channel table and *not* send a packet to the
        // client.  A notification was already sent by our caller, or will
        // be sent after we return.
        //
        super.close(true);

        // We also need to dispose of the connector, but unfortunately we
        // are being invoked by the connector thread or the connector's
        // own processor thread.  Disposing of the connector within either
        // causes deadlock.  Instead create a thread to dispose of the
        // connector in the background.

        ExecutorService service = getExecutorService();
        // allocate a temporary executor service if none provided
        final ExecutorService executors = (service == null)
                ? ThreadUtils.newSingleThreadExecutor("TcpIpServerChannel-ConnectorCleanup[" + getSession() + "]")
                : service;
        // shutdown the temporary executor service if had to create it
        final boolean shutdown = (executors == service) ? isShutdownOnExit() : true;
        executors.submit(new Runnable() {
            @SuppressWarnings("synthetic-access")
            @Override
            public void run() {
                try {
                    connector.close(true);
                } finally {
                    if ((executors != null) && (!executors.isShutdown()) && shutdown) {
                        Collection<Runnable> runners = executors.shutdownNow();
                        if (log.isDebugEnabled()) {
                            log.debug("destroy({}) - shutdown executor service - runners count={}", TcpipServerChannel.this, runners.size());
                        }
                    }
                }
            }
        });
    }

    @Override
    public CloseFuture close(boolean immediately) {
        return super.close(immediately).addListener(new SshFutureListener<CloseFuture>() {
            @SuppressWarnings("synthetic-access")
            @Override
            public void operationComplete(CloseFuture sshFuture) {
                closeImmediately0();
            }
        });
    }

    @Override
    protected void doWriteData(byte[] data, int off, final int len) throws IOException {
        // Make sure we copy the data as the incoming buffer may be reused
        final Buffer buf = ByteArrayBuffer.getCompactClone(data, off, len);
        ioSession.write(buf).addListener(new SshFutureListener<IoWriteFuture>() {
            @Override
            public void operationComplete(IoWriteFuture future) {
                if (future.isWritten()) {
                    handleWriteDataSuccess(SshConstants.SSH_MSG_CHANNEL_DATA, buf.array(), 0, len);
                } else {
                    handleWriteDataFailure(SshConstants.SSH_MSG_CHANNEL_DATA, buf.array(), 0, len, future.getException());
                }
            }
        });
    }

    @Override
    protected void doWriteExtendedData(byte[] data, int off, int len) throws IOException {
        throw new UnsupportedOperationException(type + "Tcpip channel does not support extended data");
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
        Session session = getSession();
        if (log.isDebugEnabled()) {
            log.debug("handleWriteDataFailure({})[{}] failed ({}) to write len={}: {}",
                      this, SshConstants.getCommandMessageName(cmd & 0xFF),
                      t.getClass().getSimpleName(), len, t.getMessage());
        }

        if (log.isTraceEnabled()) {
            log.trace("doWriteData(" + this + ")[" + SshConstants.getCommandMessageName(cmd & 0xFF) + "]"
                    + " len=" + len + " write failure details", t);
        }

        session.exceptionCaught(t);
    }
}
