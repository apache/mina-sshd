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
package org.apache.sshd.common.forward;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoHandlerFactory;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.closeable.AbstractInnerCloseable;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.forward.ForwardingFilter;

/**
 * Requests a &quot;tcpip-forward&quot; action
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultTcpipForwarder
        extends AbstractInnerCloseable
        implements TcpipForwarder, SessionHolder<Session> {

    /**
     * Used to configure the timeout (milliseconds) for receiving a response
     * for the forwarding request
     *
     * @see #DEFAULT_FORWARD_REQUEST_TIMEOUT
     */
    public static final String FORWARD_REQUEST_TIMEOUT = "tcpip-forward-request-timeout";

    /**
     * Default value for {@link #FORWARD_REQUEST_TIMEOUT} if none specified
     */
    public static final long DEFAULT_FORWARD_REQUEST_TIMEOUT = TimeUnit.SECONDS.toMillis(15L);

    public static final Set<ClientChannelEvent> STATIC_IO_MSG_RECEIVED_EVENTS =
            Collections.unmodifiableSet(EnumSet.of(ClientChannelEvent.OPENED, ClientChannelEvent.CLOSED));

    private final ConnectionService service;
    private final IoHandlerFactory socksProxyIoHandlerFactory = new IoHandlerFactory() {
        @Override
        public IoHandler create() {
            return new SocksProxy(getConnectionService());
        }
    };
    private final Session sessionInstance;
    private final Map<Integer, SshdSocketAddress> localToRemote = new HashMap<>();
    private final Map<Integer, SshdSocketAddress> remoteToLocal = new HashMap<>();
    private final Map<Integer, SocksProxy> dynamicLocal = new HashMap<>();
    private final Set<LocalForwardingEntry> localForwards = new HashSet<>();
    private final IoHandlerFactory staticIoHandlerFactory = new IoHandlerFactory() {
        @Override
        public IoHandler create() {
            return new StaticIoHandler();
        }
    };
    private IoAcceptor acceptor;

    public DefaultTcpipForwarder(ConnectionService service) {
        this.service = ValidateUtils.checkNotNull(service, "No connection service");
        this.sessionInstance = ValidateUtils.checkNotNull(service.getSession(), "No session");
    }

    @Override
    public Session getSession() {
        return sessionInstance;
    }

    public final ConnectionService getConnectionService() {
        return service;
    }

    //
    // TcpIpForwarder implementation
    //

    @Override
    public synchronized SshdSocketAddress startLocalPortForwarding(SshdSocketAddress local, SshdSocketAddress remote) throws IOException {
        ValidateUtils.checkNotNull(local, "Local address is null");
        ValidateUtils.checkTrue(local.getPort() >= 0, "Invalid local port: %s", local);
        ValidateUtils.checkNotNull(remote, "Remote address is null");

        if (isClosed()) {
            throw new IllegalStateException("TcpipForwarder is closed");
        }
        if (isClosing()) {
            throw new IllegalStateException("TcpipForwarder is closing");
        }

        InetSocketAddress bound = doBind(local, staticIoHandlerFactory);
        int port = bound.getPort();
        SshdSocketAddress prev;
        synchronized (localToRemote) {
            prev = localToRemote.put(port, remote);
        }

        if (prev != null) {
            throw new IOException("Multiple local port forwarding bindings on port=" + port + ": current=" + remote + ", previous=" + prev);
        }

        SshdSocketAddress result = new SshdSocketAddress(bound.getHostString(), port);
        if (log.isDebugEnabled()) {
            log.debug("startLocalPortForwarding(" + local + " -> " + remote + "): " + result);
        }
        return result;
    }

    @Override
    public synchronized void stopLocalPortForwarding(SshdSocketAddress local) throws IOException {
        ValidateUtils.checkNotNull(local, "Local address is null");

        SshdSocketAddress bound;
        synchronized (localToRemote) {
            bound = localToRemote.remove(local.getPort());
        }

        if ((bound != null) && (acceptor != null)) {
            if (log.isDebugEnabled()) {
                log.debug("stopLocalPortForwarding(" + local + ") unbind " + bound);
            }
            acceptor.unbind(bound.toInetSocketAddress());
        } else {
            if (log.isDebugEnabled()) {
                log.debug("stopLocalPortForwarding(" + local + ") no mapping/acceptor for " + bound);
            }
        }
    }

    @Override
    public synchronized SshdSocketAddress startRemotePortForwarding(SshdSocketAddress remote, SshdSocketAddress local) throws IOException {
        ValidateUtils.checkNotNull(local, "Local address is null");
        ValidateUtils.checkNotNull(remote, "Remote address is null");

        String remoteHost = remote.getHostName();
        int remotePort = remote.getPort();
        Session session = getSession();
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST, remoteHost.length() + Long.SIZE);
        buffer.putString("tcpip-forward");
        buffer.putBoolean(true);    // want reply
        buffer.putString(remoteHost);
        buffer.putInt(remotePort);

        long timeout = PropertyResolverUtils.getLongProperty(session, FORWARD_REQUEST_TIMEOUT, DEFAULT_FORWARD_REQUEST_TIMEOUT);
        Buffer result = session.request("tcpip-forward", buffer, timeout, TimeUnit.MILLISECONDS);
        if (result == null) {
            throw new SshException("Tcpip forwarding request denied by server");
        }
        int port = (remotePort == 0) ? result.getInt() : remote.getPort();
        // TODO: Is it really safe to only store the local address after the request ?
        SshdSocketAddress prev;
        synchronized (remoteToLocal) {
            prev = remoteToLocal.put(port, local);
        }

        if (prev != null) {
            throw new IOException("Multiple remote port forwarding bindings on port=" + port + ": current=" + remote + ", previous=" + prev);
        }

        SshdSocketAddress bound = new SshdSocketAddress(remoteHost, port);
        if (log.isDebugEnabled()) {
            log.debug("startRemotePortForwarding(" + remote + " -> " + local + "): " + bound);
        }

        return bound;
    }

    @Override
    public synchronized void stopRemotePortForwarding(SshdSocketAddress remote) throws IOException {
        SshdSocketAddress bound;
        synchronized (remoteToLocal) {
            bound = remoteToLocal.remove(remote.getPort());
        }

        if (bound != null) {
            if (log.isDebugEnabled()) {
                log.debug("stopRemotePortForwarding(" + remote + ") cancel forwarding to " + bound);
            }

            String remoteHost = remote.getHostName();
            Session session = getSession();
            Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST, remoteHost.length() + Long.SIZE);
            buffer.putString("cancel-tcpip-forward");
            buffer.putBoolean(false);   // want reply
            buffer.putString(remoteHost);
            buffer.putInt(remote.getPort());
            session.writePacket(buffer);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("stopRemotePortForwarding(" + remote + ") no binding found");
            }
        }
    }

    @Override
    public synchronized SshdSocketAddress startDynamicPortForwarding(SshdSocketAddress local) throws IOException {
        ValidateUtils.checkNotNull(local, "Local address is null");
        ValidateUtils.checkTrue(local.getPort() >= 0, "Invalid local port: %s", local);

        if (isClosed()) {
            throw new IllegalStateException("TcpipForwarder is closed");
        }
        if (isClosing()) {
            throw new IllegalStateException("TcpipForwarder is closing");
        }

        SocksProxy socksProxy = new SocksProxy(service);
        SocksProxy prev;
        InetSocketAddress bound = doBind(local, socksProxyIoHandlerFactory);
        int port = bound.getPort();
        synchronized (dynamicLocal) {
            prev = dynamicLocal.put(port, socksProxy);
        }

        if (prev != null) {
            throw new IOException("Multiple dynamic port mappings found for port=" + port + ": current=" + socksProxy + ", previous=" + prev);
        }

        SshdSocketAddress result = new SshdSocketAddress(bound.getHostString(), port);
        if (log.isDebugEnabled()) {
            log.debug("startDynamicPortForwarding(" + local + "): " + result);
        }

        return result;
    }

    @Override
    public synchronized void stopDynamicPortForwarding(SshdSocketAddress local) throws IOException {
        Closeable obj;
        synchronized (dynamicLocal) {
            obj = dynamicLocal.remove(local.getPort());
        }

        if (obj != null) {
            if (log.isDebugEnabled()) {
                log.debug("stopDynamicPortForwarding(" + local + ") unbinding");
            }
            obj.close(true);
            acceptor.unbind(local.toInetSocketAddress());
        } else {
            if (log.isDebugEnabled()) {
                log.debug("stopDynamicPortForwarding(" + local + ") no binding found");
            }
        }
    }

    @Override
    public synchronized SshdSocketAddress getForwardedPort(int remotePort) {
        synchronized (remoteToLocal) {
            return remoteToLocal.get(remotePort);
        }
    }

    @Override
    public synchronized SshdSocketAddress localPortForwardingRequested(SshdSocketAddress local) throws IOException {
        ValidateUtils.checkNotNull(local, "Local address is null");
        ValidateUtils.checkTrue(local.getPort() >= 0, "Invalid local port: %s", local);

        Session session = getSession();
        FactoryManager manager = ValidateUtils.checkNotNull(session.getFactoryManager(), "No factory manager");
        ForwardingFilter filter = manager.getTcpipForwardingFilter();
        try {
            if ((filter == null) || (!filter.canListen(local, session))) {
                if (log.isDebugEnabled()) {
                    log.debug("localPortForwardingRequested(" + session + ")[" + local + "][haveFilter=" + (filter != null) + "] rejected");
                }
                return null;
            }
        } catch (Error e) {
            log.warn("localPortForwardingRequested({})[{}] failed ({}) to consult forwarding filter: {}",
                     session, local, e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("localPortForwardingRequested(" + this + ")[" + local + "] filter consultation failure details", e);
            }
            throw new RuntimeSshException(e);
        }

        InetSocketAddress bound = doBind(local, staticIoHandlerFactory);
        SshdSocketAddress result = new SshdSocketAddress(bound.getHostString(), bound.getPort());
        if (log.isDebugEnabled()) {
            log.debug("localPortForwardingRequested(" + local + "): " + result);
        }

        boolean added;
        synchronized (localForwards) {
            // NOTE !!! it is crucial to use the bound address host name first
            added = localForwards.add(new LocalForwardingEntry(result.getHostName(), local.getHostName(), result.getPort()));
        }

        if (!added) {
            throw new IOException("Failed to add local port forwarding entry for " + local + " -> " + result);
        }
        return result;
    }

    @Override
    public synchronized void localPortForwardingCancelled(SshdSocketAddress local) throws IOException {
        LocalForwardingEntry entry;
        synchronized (localForwards) {
            entry = LocalForwardingEntry.findMatchingEntry(local.getHostName(), local.getPort(), localForwards);
            if (entry != null) {
                localForwards.remove(entry);
            }
        }

        if ((entry != null) && (acceptor != null)) {
            if (log.isDebugEnabled()) {
                log.debug("localPortForwardingCancelled(" + local + ") unbind " + entry);
            }
            acceptor.unbind(entry.toInetSocketAddress());
        } else {
            if (log.isDebugEnabled()) {
                log.debug("localPortForwardingCancelled(" + local + ") no match/acceptor: " + entry);
            }
        }
    }

    @Override
    protected synchronized Closeable getInnerCloseable() {
        return builder().parallel(dynamicLocal.values()).close(acceptor).build();
    }

    /**
     * @param address        The request bind address
     * @param handlerFactory A {@link Factory} to create an {@link IoHandler} if necessary
     * @return The {@link InetSocketAddress} to which the binding occurred
     * @throws IOException If failed to bind
     */
    private InetSocketAddress doBind(SshdSocketAddress address, Factory<? extends IoHandler> handlerFactory) throws IOException {
        if (acceptor == null) {
            Session session = getSession();
            FactoryManager manager = ValidateUtils.checkNotNull(session.getFactoryManager(), "No factory manager");
            IoServiceFactory factory = ValidateUtils.checkNotNull(manager.getIoServiceFactory(), "No I/O service factory");
            IoHandler handler = handlerFactory.create();
            acceptor = factory.createAcceptor(handler);
        }

        // TODO find a better way to determine the resulting bind address - what if multi-threaded calls...
        Set<SocketAddress> before = acceptor.getBoundAddresses();
        try {
            InetSocketAddress bindAddress = address.toInetSocketAddress();
            acceptor.bind(bindAddress);

            Set<SocketAddress> after = acceptor.getBoundAddresses();
            if (GenericUtils.size(after) > 0) {
                after.removeAll(before);
            }
            if (GenericUtils.isEmpty(after)) {
                throw new IOException("Error binding to " + address + "[" + bindAddress + "]: no local addresses bound");
            }

            if (after.size() > 1) {
                throw new IOException("Multiple local addresses have been bound for " + address + "[" + bindAddress + "]");
            }
            return (InetSocketAddress) after.iterator().next();
        } catch (IOException bindErr) {
            Set<SocketAddress> after = acceptor.getBoundAddresses();
            if (GenericUtils.isEmpty(after)) {
                close();
            }
            throw bindErr;
        }
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + "[" + getSession() + "]";
    }

    //
    // Static IoHandler implementation
    //

    class StaticIoHandler implements IoHandler {
        StaticIoHandler() {
            super();
        }

        @Override
        @SuppressWarnings("synthetic-access")
        public void sessionCreated(final IoSession session) throws Exception {
            InetSocketAddress local = (InetSocketAddress) session.getLocalAddress();
            int localPort = local.getPort();
            SshdSocketAddress remote = localToRemote.get(localPort);
            if (log.isDebugEnabled()) {
                log.debug("sessionCreated({}) remote={}", session, remote);
            }

            final TcpipClientChannel channel;
            if (remote != null) {
                channel = new TcpipClientChannel(TcpipClientChannel.Type.Direct, session, remote);
            } else {
                channel = new TcpipClientChannel(TcpipClientChannel.Type.Forwarded, session, null);
            }
            session.setAttribute(TcpipClientChannel.class, channel);

            service.registerChannel(channel);
            channel.open().addListener(new SshFutureListener<OpenFuture>() {
                @Override
                public void operationComplete(OpenFuture future) {
                    Throwable t = future.getException();
                    if (t != null) {
                        log.warn("Failed ({}) to open channel for session={}: {}",
                                 t.getClass().getSimpleName(), session, t.getMessage());
                        if (log.isDebugEnabled()) {
                            log.debug("sessionCreated(" + session + ") channel=" + channel + " open failure details", t);
                        }
                        DefaultTcpipForwarder.this.service.unregisterChannel(channel);
                        channel.close(false);
                    }
                }
            });
        }

        @Override
        @SuppressWarnings("synthetic-access")
        public void sessionClosed(IoSession session) throws Exception {
            TcpipClientChannel channel = (TcpipClientChannel) session.getAttribute(TcpipClientChannel.class);
            if (channel != null) {
                if (log.isDebugEnabled()) {
                    log.debug("sessionClosed({}) closing channel={}", session, channel);
                }
                channel.close(false);
            }
        }

        @Override
        @SuppressWarnings("synthetic-access")
        public void messageReceived(IoSession session, Readable message) throws Exception {
            TcpipClientChannel channel = (TcpipClientChannel) session.getAttribute(TcpipClientChannel.class);
            Buffer buffer = new ByteArrayBuffer(message.available() + Long.SIZE, false);
            buffer.putBuffer(message);

            Collection<ClientChannelEvent> result = channel.waitFor(STATIC_IO_MSG_RECEIVED_EVENTS, Long.MAX_VALUE);
            if (log.isTraceEnabled()) {
                log.trace("messageReceived({}) channel={}, len={} wait result: {}",
                          session, channel, result, buffer.array());
            }

            OutputStream outputStream = channel.getInvertedIn();
            outputStream.write(buffer.array(), buffer.rpos(), buffer.available());
            outputStream.flush();
        }

        @Override
        @SuppressWarnings("synthetic-access")
        public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
            if (log.isDebugEnabled()) {
                log.debug("exceptionCaught({}) {}: {}", session, cause.getClass().getSimpleName(), cause.getMessage());
            }
            if (log.isTraceEnabled()) {
                log.trace("exceptionCaught(" + session + ") caught exception details", cause);
            }
            session.close(false);
        }
    }
}
