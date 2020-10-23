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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.time.Duration;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.channel.ClientChannelPendingMessagesQueue;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoHandlerFactory;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.common.util.EventListenerUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Invoker;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.common.util.closeable.AbstractInnerCloseable;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.forward.TcpForwardingFilter;

/**
 * Requests a &quot;tcpip-forward&quot; action
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultForwarder
        extends AbstractInnerCloseable
        implements Forwarder, SessionHolder<Session>, PortForwardingEventListenerManager {

    public static final Set<ClientChannelEvent> STATIC_IO_MSG_RECEIVED_EVENTS
            = Collections.unmodifiableSet(EnumSet.of(ClientChannelEvent.OPENED, ClientChannelEvent.CLOSED));

    private final ConnectionService service;
    private final IoHandlerFactory socksProxyIoHandlerFactory = () -> new SocksProxy(getConnectionService());
    private final Session sessionInstance;

    private final Object localLock = new Object();
    private final Map<SshdSocketAddress, SshdSocketAddress> localToRemote = new HashMap<>();
    private final Map<SshdSocketAddress, InetSocketAddress> boundLocals = new HashMap<>();

    private final Object dynamicLock = new Object();
    private final Map<Integer, SshdSocketAddress> remoteToLocal = new HashMap<>();
    private final Map<Integer, SocksProxy> dynamicLocal = new HashMap<>();
    private final Map<Integer, InetSocketAddress> boundDynamic = new HashMap<>();

    private final Set<LocalForwardingEntry> localForwards = new HashSet<>();
    private final IoHandlerFactory staticIoHandlerFactory = StaticIoHandler::new;
    private final Collection<PortForwardingEventListener> listeners = new CopyOnWriteArraySet<>();
    private final Collection<PortForwardingEventListenerManager> managersHolder = new CopyOnWriteArraySet<>();
    private final PortForwardingEventListener listenerProxy;

    private IoAcceptor localAcceptor;
    private IoAcceptor dynamicAcceptor;

    public DefaultForwarder(ConnectionService service) {
        this.service = Objects.requireNonNull(service, "No connection service");
        this.sessionInstance = Objects.requireNonNull(service.getSession(), "No session");
        this.listenerProxy = EventListenerUtils.proxyWrapper(PortForwardingEventListener.class, listeners);
    }

    @Override
    public PortForwardingEventListener getPortForwardingEventListenerProxy() {
        return listenerProxy;
    }

    @Override
    public void addPortForwardingEventListener(PortForwardingEventListener listener) {
        listeners.add(PortForwardingEventListener.validateListener(listener));
    }

    @Override
    public void removePortForwardingEventListener(PortForwardingEventListener listener) {
        if (listener == null) {
            return;
        }

        listeners.remove(PortForwardingEventListener.validateListener(listener));
    }

    @Override
    public Collection<PortForwardingEventListenerManager> getRegisteredManagers() {
        return managersHolder.isEmpty() ? Collections.emptyList() : new ArrayList<>(managersHolder);
    }

    @Override
    public boolean addPortForwardingEventListenerManager(PortForwardingEventListenerManager manager) {
        return managersHolder.add(Objects.requireNonNull(manager, "No manager"));
    }

    @Override
    public boolean removePortForwardingEventListenerManager(PortForwardingEventListenerManager manager) {
        if (manager == null) {
            return false;
        }

        return managersHolder.remove(manager);
    }

    @Override
    public Session getSession() {
        return sessionInstance;
    }

    public final ConnectionService getConnectionService() {
        return service;
    }

    protected Collection<PortForwardingEventListener> getDefaultListeners() {
        Collection<PortForwardingEventListener> defaultListeners = new ArrayList<>();
        defaultListeners.add(getPortForwardingEventListenerProxy());

        Session session = getSession();
        PortForwardingEventListener l = session.getPortForwardingEventListenerProxy();
        if (l != null) {
            defaultListeners.add(l);
        }

        FactoryManager manager = (session == null) ? null : session.getFactoryManager();
        l = (manager == null) ? null : manager.getPortForwardingEventListenerProxy();
        if (l != null) {
            defaultListeners.add(l);
        }

        return defaultListeners;
    }

    @Override
    public synchronized SshdSocketAddress startLocalPortForwarding(SshdSocketAddress local, SshdSocketAddress remote)
            throws IOException {
        Objects.requireNonNull(local, "Local address is null");
        ValidateUtils.checkTrue(local.getPort() >= 0, "Invalid local port: %s", local);
        Objects.requireNonNull(remote, "Remote address is null");

        if (isClosed() || isClosing()) {
            throw new IllegalStateException("TcpipForwarder is closed or closing: " + state);
        }

        signalEstablishingExplicitTunnel(local, remote, true);

        InetSocketAddress bound = null;
        SshdSocketAddress result;
        try {
            bound = doBind(local, getLocalIoAcceptor());
            int port = bound.getPort();
            result = new SshdSocketAddress(bound.getHostString(), port);

            synchronized (localLock) {
                SshdSocketAddress prevRemote = SshdSocketAddress.findByOptionalWildcardAddress(localToRemote, result);
                if (prevRemote != null) {
                    throw new IOException(
                            "Multiple local port forwarding addressing on port=" + result
                                          + ": current=" + remote + ", previous=" + prevRemote);
                }

                InetSocketAddress prevBound = SshdSocketAddress.findByOptionalWildcardAddress(boundLocals, result);
                if (prevBound != null) {
                    throw new IOException(
                            "Multiple local port forwarding bindings on port=" + result
                                          + ": current=" + bound + ", previous=" + prevBound);
                }

                localToRemote.put(result, remote);
                boundLocals.put(result, bound);
            }
        } catch (IOException | RuntimeException e) {
            try {
                unbindLocalForwarding(local, remote, bound);
            } catch (IOException | RuntimeException err) {
                e.addSuppressed(err);
            }
            signalEstablishedExplicitTunnel(local, remote, true, null, e);
            throw e;
        }

        try {
            if (log.isDebugEnabled()) {
                log.debug("startLocalPortForwarding(" + local + " -> " + remote + "): " + result);
            }
            signalEstablishedExplicitTunnel(local, remote, true, result, null);
            return result;
        } catch (IOException | RuntimeException e) {
            stopLocalPortForwarding(local);
            throw e;
        }
    }

    @Override
    public synchronized void stopLocalPortForwarding(SshdSocketAddress local) throws IOException {
        Objects.requireNonNull(local, "Local address is null");

        SshdSocketAddress remote;
        InetSocketAddress bound;
        synchronized (localLock) {
            remote = SshdSocketAddress.removeByOptionalWildcardAddress(localToRemote, local);
            bound = SshdSocketAddress.removeByOptionalWildcardAddress(boundLocals, local);
        }

        unbindLocalForwarding(local, remote, bound);
    }

    protected void unbindLocalForwarding(
            SshdSocketAddress local, SshdSocketAddress remote, InetSocketAddress bound)
            throws IOException {
        if ((bound != null) && (localAcceptor != null)) {
            if (log.isDebugEnabled()) {
                log.debug("unbindLocalForwarding({} => {}) unbind {}", local, remote, bound);
            }

            SshdSocketAddress boundAddress = new SshdSocketAddress(bound);
            try {
                signalTearingDownExplicitTunnel(boundAddress, true, remote);
            } finally {
                try {
                    localAcceptor.unbind(bound);
                } catch (RuntimeException e) {
                    signalTornDownExplicitTunnel(boundAddress, true, remote, e);
                    throw e;
                }
            }

            signalTornDownExplicitTunnel(boundAddress, true, remote, null);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("unbindLocalForwarding({} => {}) no mapping({}) or acceptor({})",
                        local, remote, bound, localAcceptor);
            }
        }
    }

    @Override
    public synchronized SshdSocketAddress startRemotePortForwarding(SshdSocketAddress remote, SshdSocketAddress local)
            throws IOException {
        Objects.requireNonNull(local, "Local address is null");
        Objects.requireNonNull(remote, "Remote address is null");

        String remoteHost = remote.getHostName();
        int remotePort = remote.getPort();
        Session session = getSession();
        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST, remoteHost.length() + Long.SIZE);
        buffer.putString("tcpip-forward");
        buffer.putBoolean(true); // want reply
        buffer.putString(remoteHost);
        buffer.putInt(remotePort);

        Duration timeout = CoreModuleProperties.FORWARD_REQUEST_TIMEOUT.getRequired(session);
        Buffer result;
        int port;
        signalEstablishingExplicitTunnel(local, remote, false);
        try {
            result = session.request("tcpip-forward", buffer, timeout);
            if (result == null) {
                throw new SshException("Tcpip forwarding request denied by server");
            }
            port = (remotePort == 0) ? result.getInt() : remote.getPort();
            // TODO: Is it really safe to only store the local address after the request ?
            synchronized (remoteToLocal) {
                SshdSocketAddress prev = remoteToLocal.get(port);
                if (prev != null) {
                    throw new IOException(
                            "Multiple remote port forwarding bindings on port=" + port + ": current=" + remote + ", previous="
                                          + prev);
                }
                remoteToLocal.put(port, local);
            }

        } catch (IOException | RuntimeException e) {
            try {
                stopRemotePortForwarding(remote);
            } catch (IOException | RuntimeException err) {
                e.addSuppressed(err);
            }
            signalEstablishedExplicitTunnel(local, remote, false, null, e);
            throw e;
        }

        try {
            SshdSocketAddress bound = new SshdSocketAddress(remoteHost, port);
            if (log.isDebugEnabled()) {
                log.debug("startRemotePortForwarding(" + remote + " -> " + local + "): " + bound);
            }

            signalEstablishedExplicitTunnel(local, remote, false, bound, null);
            return bound;
        } catch (IOException | RuntimeException e) {
            stopRemotePortForwarding(remote);
            throw e;
        }
    }

    @Override
    public synchronized void stopRemotePortForwarding(SshdSocketAddress remote) throws IOException {
        SshdSocketAddress bound;
        int port = remote.getPort();
        synchronized (remoteToLocal) {
            bound = remoteToLocal.remove(port);
        }

        if (bound != null) {
            if (log.isDebugEnabled()) {
                log.debug("stopRemotePortForwarding(" + remote + ") cancel forwarding to " + bound);
            }

            String remoteHost = remote.getHostName();
            Session session = getSession();
            Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST, remoteHost.length() + Long.SIZE);
            buffer.putString("cancel-tcpip-forward");
            buffer.putBoolean(false); // want reply
            buffer.putString(remoteHost);
            buffer.putInt(port);

            signalTearingDownExplicitTunnel(bound, false, remote);
            try {
                session.writePacket(buffer);
            } catch (IOException | RuntimeException e) {
                signalTornDownExplicitTunnel(bound, false, remote, e);
                throw e;
            }

            signalTornDownExplicitTunnel(bound, false, remote, null);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("stopRemotePortForwarding(" + remote + ") no binding found");
            }
        }
    }

    protected void signalTearingDownExplicitTunnel(
            SshdSocketAddress boundAddress, boolean localForwarding, SshdSocketAddress remote)
            throws IOException {
        try {
            invokePortEventListenerSignaller(l -> {
                signalTearingDownExplicitTunnel(l, boundAddress, localForwarding, remote);
                return null;
            });
        } catch (Throwable t) {
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            } else if (t instanceof Error) {
                throw (Error) t;
            } else if (t instanceof IOException) {
                throw (IOException) t;
            } else {
                throw new IOException(
                        "Failed (" + t.getClass().getSimpleName() + ")"
                                      + " to signal tearing down explicit tunnel for local=" + localForwarding
                                      + " on bound=" + boundAddress,
                        t);
            }
        }
    }

    protected void signalTearingDownExplicitTunnel(
            PortForwardingEventListener listener, SshdSocketAddress boundAddress, boolean localForwarding,
            SshdSocketAddress remoteAddress)
            throws IOException {
        if (listener == null) {
            return;
        }

        listener.tearingDownExplicitTunnel(getSession(), boundAddress, localForwarding, remoteAddress);
    }

    protected void signalTornDownExplicitTunnel(
            SshdSocketAddress boundAddress, boolean localForwarding, SshdSocketAddress remoteAddress, Throwable reason)
            throws IOException {
        try {
            invokePortEventListenerSignaller(l -> {
                signalTornDownExplicitTunnel(l, boundAddress, localForwarding, remoteAddress, reason);
                return null;
            });
        } catch (Throwable t) {
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            } else if (t instanceof Error) {
                throw (Error) t;
            } else if (t instanceof IOException) {
                throw (IOException) t;
            } else {
                throw new IOException(
                        "Failed (" + t.getClass().getSimpleName() + ")"
                                      + " to signal torn down explicit tunnel local=" + localForwarding
                                      + " on bound=" + boundAddress,
                        t);
            }
        }
    }

    protected void signalTornDownExplicitTunnel(
            PortForwardingEventListener listener, SshdSocketAddress boundAddress, boolean localForwarding,
            SshdSocketAddress remoteAddress, Throwable reason)
            throws IOException {
        if (listener == null) {
            return;
        }

        listener.tornDownExplicitTunnel(getSession(), boundAddress, localForwarding, remoteAddress, reason);
    }

    @Override
    public synchronized SshdSocketAddress startDynamicPortForwarding(SshdSocketAddress local) throws IOException {
        Objects.requireNonNull(local, "Local address is null");
        ValidateUtils.checkTrue(local.getPort() >= 0, "Invalid local port: %s", local);

        if (isClosed() || isClosing()) {
            throw new IllegalStateException("DefaultForwarder is closed or closing: " + state);
        }

        SocksProxy proxy = null;
        InetSocketAddress bound = null;
        int port;
        signalEstablishingDynamicTunnel(local);
        try {
            bound = doBind(local, getDynamicIoAcceptor());
            port = bound.getPort();
            synchronized (dynamicLock) {
                SocksProxy prevProxy = dynamicLocal.get(port);
                if (prevProxy != null) {
                    throw new IOException(
                            "Multiple dynamic port mappings found for port=" + port
                                          + ": current=" + proxy + ", previous=" + prevProxy);
                }

                InetSocketAddress prevBound = boundDynamic.get(port);
                if (prevBound != null) {
                    throw new IOException(
                            "Multiple dynamic port bindings found for port=" + port
                                          + ": current=" + bound + ", previous=" + prevBound);
                }

                proxy = new SocksProxy(service);
                dynamicLocal.put(port, proxy);
                boundDynamic.put(port, bound);
            }
        } catch (IOException | RuntimeException e) {
            try {
                unbindDynamicForwarding(local, proxy, bound);
            } catch (IOException | RuntimeException err) {
                e.addSuppressed(err);
            }
            signalEstablishedDynamicTunnel(local, null, e);
            throw e;
        }

        try {
            SshdSocketAddress result = new SshdSocketAddress(bound.getHostString(), port);
            if (log.isDebugEnabled()) {
                log.debug("startDynamicPortForwarding(" + local + "): " + result);
            }

            signalEstablishedDynamicTunnel(local, result, null);
            return result;
        } catch (IOException | RuntimeException e) {
            stopDynamicPortForwarding(local);
            throw e;
        }
    }

    protected void signalEstablishedDynamicTunnel(
            SshdSocketAddress local, SshdSocketAddress boundAddress, Throwable reason)
            throws IOException {
        try {
            invokePortEventListenerSignaller(l -> {
                signalEstablishedDynamicTunnel(l, local, boundAddress, reason);
                return null;
            });
        } catch (Throwable t) {
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            } else if (t instanceof Error) {
                throw (Error) t;
            } else if (t instanceof IOException) {
                throw (IOException) t;
            } else {
                throw new IOException(
                        "Failed (" + t.getClass().getSimpleName() + ")"
                                      + " to signal establishing dynamic tunnel for local=" + local
                                      + " on bound=" + boundAddress,
                        t);
            }
        }
    }

    protected void signalEstablishedDynamicTunnel(
            PortForwardingEventListener listener,
            SshdSocketAddress local, SshdSocketAddress boundAddress, Throwable reason)
            throws IOException {
        if (listener == null) {
            return;
        }

        listener.establishedDynamicTunnel(getSession(), local, boundAddress, reason);
    }

    protected void signalEstablishingDynamicTunnel(SshdSocketAddress local) throws IOException {
        try {
            invokePortEventListenerSignaller(l -> {
                signalEstablishingDynamicTunnel(l, local);
                return null;
            });
        } catch (Throwable t) {
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            } else if (t instanceof Error) {
                throw (Error) t;
            } else if (t instanceof IOException) {
                throw (IOException) t;
            } else {
                throw new IOException(
                        "Failed (" + t.getClass().getSimpleName() + ")"
                                      + " to signal establishing dynamic tunnel for local=" + local,
                        t);
            }
        }
    }

    protected void signalEstablishingDynamicTunnel(PortForwardingEventListener listener, SshdSocketAddress local)
            throws IOException {
        if (listener == null) {
            return;
        }

        listener.establishingDynamicTunnel(getSession(), local);
    }

    @Override
    public synchronized void stopDynamicPortForwarding(SshdSocketAddress local) throws IOException {
        SocksProxy proxy;
        InetSocketAddress bound;
        int port = local.getPort();
        synchronized (dynamicLock) {
            proxy = dynamicLocal.remove(port);
            bound = boundDynamic.remove(port);
        }

        unbindDynamicForwarding(local, proxy, bound);
    }

    protected void unbindDynamicForwarding(
            SshdSocketAddress local, SocksProxy proxy, InetSocketAddress bound)
            throws IOException {
        boolean debugEnabled = log.isDebugEnabled();
        if ((bound != null) || (proxy != null)) {

            try {
                signalTearingDownDynamicTunnel(local);
            } finally {
                try {
                    try {
                        if (proxy != null) {
                            if (debugEnabled) {
                                log.debug("stopDynamicPortForwarding({}) close proxy={}", local, proxy);
                            }

                            proxy.close(true);
                        }
                    } finally {
                        if ((bound != null) && (dynamicAcceptor != null)) {
                            if (debugEnabled) {
                                log.debug("stopDynamicPortForwarding({}) unbind address={}", local, bound);
                            }
                            dynamicAcceptor.unbind(bound);
                        } else {
                            if (debugEnabled) {
                                log.debug("stopDynamicPortForwarding({}) no acceptor({}) or no binding({})",
                                        local, dynamicAcceptor, bound);
                            }
                        }
                    }
                } catch (RuntimeException e) {
                    signalTornDownDynamicTunnel(local, e);
                    throw e;
                }
            }

            signalTornDownDynamicTunnel(local, null);
        } else {
            if (debugEnabled) {
                log.debug("stopDynamicPortForwarding({}) no binding found", local);
            }
        }
    }

    protected void signalTearingDownDynamicTunnel(SshdSocketAddress address) throws IOException {
        try {
            invokePortEventListenerSignaller(l -> {
                signalTearingDownDynamicTunnel(l, address);
                return null;
            });
        } catch (Throwable t) {
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            } else if (t instanceof Error) {
                throw (Error) t;
            } else if (t instanceof IOException) {
                throw (IOException) t;
            } else {
                throw new IOException(
                        "Failed (" + t.getClass().getSimpleName() + ")"
                                      + " to signal tearing down dynamic tunnel for address=" + address,
                        t);
            }
        }
    }

    protected void signalTearingDownDynamicTunnel(PortForwardingEventListener listener, SshdSocketAddress address)
            throws IOException {
        if (listener == null) {
            return;
        }

        listener.tearingDownDynamicTunnel(getSession(), address);
    }

    protected void signalTornDownDynamicTunnel(SshdSocketAddress address, Throwable reason) throws IOException {
        try {
            invokePortEventListenerSignaller(l -> {
                signalTornDownDynamicTunnel(l, address, reason);
                return null;
            });
        } catch (Throwable t) {
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            } else if (t instanceof Error) {
                throw (Error) t;
            } else if (t instanceof IOException) {
                throw (IOException) t;
            } else {
                throw new IOException(
                        "Failed (" + t.getClass().getSimpleName() + ")"
                                      + " to signal torn down dynamic tunnel for address=" + address,
                        t);
            }
        }
    }

    protected void signalTornDownDynamicTunnel(
            PortForwardingEventListener listener, SshdSocketAddress address, Throwable reason)
            throws IOException {
        if (listener == null) {
            return;
        }

        listener.tornDownDynamicTunnel(getSession(), address, reason);
    }

    @Override
    public synchronized SshdSocketAddress getForwardedPort(int remotePort) {
        synchronized (remoteToLocal) {
            return remoteToLocal.get(remotePort);
        }
    }

    @Override
    public synchronized SshdSocketAddress localPortForwardingRequested(SshdSocketAddress local) throws IOException {
        Objects.requireNonNull(local, "Local address is null");
        ValidateUtils.checkTrue(local.getPort() >= 0, "Invalid local port: %s", local);

        Session session = getSession();
        FactoryManager manager = Objects.requireNonNull(session.getFactoryManager(), "No factory manager");
        TcpForwardingFilter filter = manager.getTcpForwardingFilter();
        try {
            if ((filter == null) || (!filter.canListen(local, session))) {
                if (log.isDebugEnabled()) {
                    log.debug("localPortForwardingRequested(" + session + ")[" + local + "][haveFilter=" + (filter != null)
                              + "] rejected");
                }
                return null;
            }
        } catch (Error e) {
            warn("localPortForwardingRequested({})[{}] failed ({}) to consult forwarding filter: {}",
                    session, local, e.getClass().getSimpleName(), e.getMessage(), e);
            throw new RuntimeSshException(e);
        }

        signalEstablishingExplicitTunnel(local, null, true);

        SshdSocketAddress result;
        try {
            InetSocketAddress bound = doBind(local, getLocalIoAcceptor());
            result = new SshdSocketAddress(bound);
            if (log.isDebugEnabled()) {
                log.debug("localPortForwardingRequested(" + local + "): " + result);
            }

            boolean added;
            LocalForwardingEntry localEntry = new LocalForwardingEntry(local, result);
            synchronized (localForwards) {
                added = localForwards.add(localEntry);
            }

            if (!added) {
                throw new IOException("Failed to add local port forwarding entry for " + local + " -> " + result);
            }
        } catch (IOException | RuntimeException | Error e) {
            try {
                localPortForwardingCancelled(local);
            } catch (IOException | RuntimeException | Error err) {
                e.addSuppressed(err);
            }
            signalEstablishedExplicitTunnel(local, null, true, null, e);
            throw e;
        }

        try {
            signalEstablishedExplicitTunnel(local, null, true, result, null);
            return result;
        } catch (IOException | RuntimeException e) {
            throw e;
        }
    }

    @Override
    public synchronized void localPortForwardingCancelled(SshdSocketAddress local) throws IOException {
        LocalForwardingEntry entry;
        synchronized (localForwards) {
            entry = LocalForwardingEntry.findMatchingEntry(
                    local.getHostName(), local.getPort(), localForwards);
            if (entry != null) {
                localForwards.remove(entry);
            }
        }

        if ((entry != null) && (localAcceptor != null)) {
            if (log.isDebugEnabled()) {
                log.debug("localPortForwardingCancelled(" + local + ") unbind " + entry);
            }

            SshdSocketAddress reportedBoundAddress = entry.getCombinedBoundAddress();
            signalTearingDownExplicitTunnel(reportedBoundAddress, true, null);

            SshdSocketAddress boundAddress = entry.getBoundAddress();
            try {
                localAcceptor.unbind(boundAddress.toInetSocketAddress());
            } catch (RuntimeException | Error e) {
                signalTornDownExplicitTunnel(reportedBoundAddress, true, null, e);
                throw e;
            }

            signalTornDownExplicitTunnel(reportedBoundAddress, true, null, null);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("localPortForwardingCancelled(" + local + ") no match/acceptor: " + entry);
            }
        }
    }

    protected void signalEstablishingExplicitTunnel(
            SshdSocketAddress local, SshdSocketAddress remote, boolean localForwarding)
            throws IOException {
        try {
            invokePortEventListenerSignaller(l -> {
                signalEstablishingExplicitTunnel(l, local, remote, localForwarding);
                return null;
            });
        } catch (Throwable t) {
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            } else if (t instanceof Error) {
                throw (Error) t;
            } else if (t instanceof IOException) {
                throw (IOException) t;
            } else {
                throw new IOException(
                        "Failed (" + t.getClass().getSimpleName() + ")"
                                      + " to signal establishing explicit tunnel for local=" + local
                                      + ", remote=" + remote + ", localForwarding=" + localForwarding,
                        t);
            }
        }
    }

    protected void signalEstablishingExplicitTunnel(
            PortForwardingEventListener listener, SshdSocketAddress local, SshdSocketAddress remote, boolean localForwarding)
            throws IOException {
        if (listener == null) {
            return;
        }

        listener.establishingExplicitTunnel(getSession(), local, remote, localForwarding);
    }

    protected void signalEstablishedExplicitTunnel(
            SshdSocketAddress local, SshdSocketAddress remote, boolean localForwarding,
            SshdSocketAddress boundAddress, Throwable reason)
            throws IOException {
        try {
            invokePortEventListenerSignaller(l -> {
                signalEstablishedExplicitTunnel(l, local, remote, localForwarding, boundAddress, reason);
                return null;
            });
        } catch (Throwable t) {
            if (t instanceof RuntimeException) {
                throw (RuntimeException) t;
            } else if (t instanceof Error) {
                throw (Error) t;
            } else if (t instanceof IOException) {
                throw (IOException) t;
            } else {
                throw new IOException(
                        "Failed (" + t.getClass().getSimpleName() + ")"
                                      + " to signal established explicit tunnel for local=" + local
                                      + ", remote=" + remote + ", localForwarding=" + localForwarding
                                      + ", bound=" + boundAddress,
                        t);
            }
        }
    }

    protected void signalEstablishedExplicitTunnel(
            PortForwardingEventListener listener,
            SshdSocketAddress local, SshdSocketAddress remote, boolean localForwarding,
            SshdSocketAddress boundAddress, Throwable reason)
            throws IOException {
        if (listener == null) {
            return;
        }

        listener.establishedExplicitTunnel(getSession(), local, remote, localForwarding, boundAddress, reason);
    }

    protected void invokePortEventListenerSignaller(Invoker<PortForwardingEventListener, Void> invoker) throws Throwable {
        Throwable err = null;
        try {
            invokePortEventListenerSignallerListeners(getDefaultListeners(), invoker);
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            err = GenericUtils.accumulateException(err, e);
        }

        try {
            invokePortEventListenerSignallerHolders(managersHolder, invoker);
        } catch (Throwable t) {
            Throwable e = GenericUtils.peelException(t);
            err = GenericUtils.accumulateException(err, e);
        }

        if (err != null) {
            throw err;
        }
    }

    protected void invokePortEventListenerSignallerListeners(
            Collection<? extends PortForwardingEventListener> listeners, Invoker<PortForwardingEventListener, Void> invoker)
            throws Throwable {
        if (GenericUtils.isEmpty(listeners)) {
            return;
        }

        Throwable err = null;
        // Need to go over the hierarchy (session, factory managed, connection service, etc...)
        for (PortForwardingEventListener l : listeners) {
            if (l == null) {
                continue;
            }

            try {
                invoker.invoke(l);
            } catch (Throwable t) {
                Throwable e = GenericUtils.peelException(t);
                err = GenericUtils.accumulateException(err, e);
            }
        }

        if (err != null) {
            throw err;
        }
    }

    protected void invokePortEventListenerSignallerHolders(
            Collection<? extends PortForwardingEventListenerManager> holders,
            Invoker<PortForwardingEventListener, Void> invoker)
            throws Throwable {
        if (GenericUtils.isEmpty(holders)) {
            return;
        }

        Throwable err = null;
        // Need to go over the hierarchy (session, factory managed, connection service, etc...)
        for (PortForwardingEventListenerManager m : holders) {
            try {
                PortForwardingEventListener listener = m.getPortForwardingEventListenerProxy();
                if (listener != null) {
                    invoker.invoke(listener);
                }
            } catch (Throwable t) {
                Throwable e = GenericUtils.peelException(t);
                err = GenericUtils.accumulateException(err, e);
            }

            if (m instanceof PortForwardingEventListenerManagerHolder) {
                try {
                    invokePortEventListenerSignallerHolders(
                            ((PortForwardingEventListenerManagerHolder) m).getRegisteredManagers(), invoker);
                } catch (Throwable t) {
                    Throwable e = GenericUtils.peelException(t);
                    err = GenericUtils.accumulateException(err, e);
                }
            }
        }

        if (err != null) {
            throw err;
        }
    }

    @Override
    protected synchronized Closeable getInnerCloseable() {
        return builder().parallel(toString(), dynamicLocal.values())
                .close(localAcceptor).close(dynamicAcceptor).build();
    }

    @Override
    protected void preClose() {
        this.listeners.clear();
        this.managersHolder.clear();
        super.preClose();
    }

    protected IoAcceptor createIoAcceptor(Factory<? extends IoHandler> handlerFactory) {
        Session session = getSession();
        FactoryManager manager = Objects.requireNonNull(session.getFactoryManager(), "No factory manager");
        IoServiceFactory factory = Objects.requireNonNull(manager.getIoServiceFactory(), "No I/O service factory");
        IoHandler handler = handlerFactory.create();
        return factory.createAcceptor(handler);
    }

    protected IoAcceptor getLocalIoAcceptor() {
        if (localAcceptor == null) {
            localAcceptor = createIoAcceptor(staticIoHandlerFactory);
        }
        return localAcceptor;
    }

    protected IoAcceptor getDynamicIoAcceptor() {
        if (dynamicAcceptor == null) {
            dynamicAcceptor = createIoAcceptor(socksProxyIoHandlerFactory);
        }
        return dynamicAcceptor;
    }

    /**
     * @param  address     The request bind address
     * @param  acceptor    An {@link IoAcceptor} to bind addresses
     * @return             The {@link InetSocketAddress} to which the binding occurred
     * @throws IOException If failed to bind
     */
    protected InetSocketAddress doBind(SshdSocketAddress address, IoAcceptor acceptor)
            throws IOException {
        // TODO find a better way to determine the resulting bind address - what if multi-threaded calls...
        Collection<SocketAddress> before = acceptor.getBoundAddresses();
        try {
            InetSocketAddress bindAddress = address.toInetSocketAddress();
            acceptor.bind(bindAddress);

            Collection<SocketAddress> after = acceptor.getBoundAddresses();
            if (GenericUtils.size(after) > 0) {
                after.removeAll(before);
            }
            if (GenericUtils.isEmpty(after)) {
                throw new IOException("Error binding to " + address + "[" + bindAddress + "]: no local addresses bound");
            }

            if (after.size() > 1) {
                throw new IOException("Multiple local addresses have been bound for " + address + "[" + bindAddress + "]");
            }

            InetSocketAddress boundAddress = (InetSocketAddress) GenericUtils.head(after);
            return boundAddress;
        } catch (IOException bindErr) {
            Collection<SocketAddress> after = acceptor.getBoundAddresses();
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

    @SuppressWarnings("synthetic-access")
    class StaticIoHandler implements IoHandler {
        private final AtomicLong messagesCounter = new AtomicLong(0L);

        StaticIoHandler() {
            super();
        }

        @Override
        public void sessionCreated(IoSession session) throws Exception {
            InetSocketAddress localAddress = (InetSocketAddress) session.getLocalAddress();
            SshdSocketAddress local = new SshdSocketAddress(localAddress);
            SshdSocketAddress remote;
            synchronized (localLock) {
                remote = SshdSocketAddress.findByOptionalWildcardAddress(localToRemote, local);
            }

            TcpipClientChannel.Type channelType = (remote == null)
                    ? TcpipClientChannel.Type.Forwarded
                    : TcpipClientChannel.Type.Direct;
            TcpipClientChannel channel = new TcpipClientChannel(channelType, session, remote);
            session.setAttribute(TcpipClientChannel.class, channel);

            // Propagate original requested host name - see SSHD-792
            if (channelType == TcpipClientChannel.Type.Forwarded) {
                SocketAddress accepted = session.getAcceptanceAddress();
                LocalForwardingEntry localEntry = null;
                if (accepted instanceof InetSocketAddress) {
                    InetSocketAddress inetSocketAddress = (InetSocketAddress) accepted;
                    InetAddress inetAddress = inetSocketAddress.getAddress();
                    synchronized (localForwards) {
                        localEntry = LocalForwardingEntry.findMatchingEntry(
                                inetSocketAddress.getHostString(), inetAddress.isAnyLocalAddress(), local.getPort(),
                                localForwards);
                    }
                }

                if (localEntry != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("sessionCreated({})[local={}, remote={}, accepted={}] localEntry={}",
                                session, local, remote, accepted, localEntry);
                    }
                    channel.updateLocalForwardingEntry(localEntry);
                } else {
                    log.warn("sessionCreated({})[local={}, remote={}] cannot locate original local entry for accepted={}",
                            session, local, remote, accepted);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("sessionCreated({}) local={}, remote={}", session, local, remote);
                }
            }

            service.registerChannel(channel);
            channel.open().addListener(future -> {
                Throwable t = future.getException();
                if (t != null) {
                    warn("Failed ({}) to open channel for session={}: {}",
                            t.getClass().getSimpleName(), session, t.getMessage(), t);
                    DefaultForwarder.this.service.unregisterChannel(channel);
                    channel.close(false);
                }
            });
        }

        @Override
        public void sessionClosed(IoSession session) throws Exception {
            TcpipClientChannel channel = (TcpipClientChannel) session.removeAttribute(TcpipClientChannel.class);
            Throwable cause = (Throwable) session.removeAttribute(TcpipForwardingExceptionMarker.class);
            if (log.isDebugEnabled()) {
                log.debug("sessionClosed({}) closing channel={} after {} messages - cause={}",
                        session, channel, messagesCounter, (cause == null) ? null : cause.getClass().getSimpleName());
            }
            if (channel == null) {
                return;
            }

            if (cause != null) {
                // If exception occurred close the channel immediately
                channel.close(true);
            } else {
                /*
                 * Make sure channel is pending messages have all been sent in case the client was very fast and sent
                 * data + closed the connection before channel open was completed.
                 */
                OpenFuture openFuture = channel.getOpenFuture();
                Throwable err = openFuture.getException();
                ClientChannelPendingMessagesQueue queue = channel.getPendingMessagesQueue();
                OpenFuture completedFuture = queue.getCompletedFuture();
                if (err == null) {
                    err = completedFuture.getException();
                }
                boolean immediately = err != null;
                if (immediately) {
                    channel.close(true);
                } else {
                    completedFuture.addListener(f -> {
                        Throwable thrown = f.getException();
                        channel.close(immediately || (thrown != null));
                    });
                }
            }
        }

        @Override
        public void messageReceived(IoSession session, Readable message) throws Exception {
            TcpipClientChannel channel = (TcpipClientChannel) session.getAttribute(TcpipClientChannel.class);
            long totalMessages = messagesCounter.incrementAndGet();
            Buffer buffer = new ByteArrayBuffer(message.available() + Long.SIZE, false);
            buffer.putBuffer(message);

            boolean traceEnabled = log.isTraceEnabled();
            if (traceEnabled) {
                log.trace("messageReceived({}) channel={}, count={}, handle len={}",
                        session, channel, totalMessages, message.available());
            }

            ClientChannelPendingMessagesQueue messagesQueue = channel.getPendingMessagesQueue();
            OpenFuture future = messagesQueue.getCompletedFuture();
            Consumer<Throwable> errHandler = future.isOpened() ? null : e -> {
                try {
                    exceptionCaught(session, e);
                } catch (Exception err) {
                    warn("messageReceived({}) failed ({}) to signal {}[{}] on channel={}: {}",
                            session, err.getClass().getSimpleName(), e.getClass().getSimpleName(),
                            e.getMessage(), channel, err.getMessage(), err);
                }
            };

            int pendCount = messagesQueue.handleIncomingMessage(buffer, errHandler);
            if (traceEnabled) {
                log.trace("messageReceived({}) channel={} pend count={} after processing message",
                        session, channel, pendCount);
            }
        }

        @Override
        public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
            session.setAttribute(TcpipForwardingExceptionMarker.class, cause);
            warn("exceptionCaught({}) {}: {}", session, cause.getClass().getSimpleName(), cause.getMessage(), cause);
            session.close(true);
        }
    }

    @Override
    public List<SshdSocketAddress> getBoundLocalPortForwards(int port) {
        synchronized (localLock) {
            return localToRemote.isEmpty()
                    ? Collections.emptyList()
                    : localToRemote.keySet()
                            .stream()
                            .filter(k -> k.getPort() == port)
                            .collect(Collectors.toList());
        }
    }

    @Override
    public boolean isLocalPortForwardingStartedForPort(int port) {
        synchronized (localLock) {
            return localToRemote.isEmpty()
                    ? false
                    : localToRemote.keySet()
                            .stream()
                            .filter(e -> e.getPort() == port)
                            .findAny()
                            .isPresent();
        }
    }

    @Override
    public List<Map.Entry<SshdSocketAddress, SshdSocketAddress>> getLocalForwardsBindings() {
        synchronized (localLock) {
            return localToRemote.isEmpty()
                    ? Collections.emptyList()
                    : localToRemote.entrySet()
                            .stream() // return an immutable clone to avoid 'setValue' calls on a shared instance
                            .map(e -> new SimpleImmutableEntry<>(e.getKey(), e.getValue()))
                            .collect(Collectors.toCollection(() -> new ArrayList<>(localToRemote.size())));
        }
    }

    @Override
    public List<SshdSocketAddress> getStartedLocalPortForwards() {
        synchronized (localLock) {
            return localToRemote.isEmpty() ? Collections.emptyList() : new ArrayList<>(localToRemote.keySet());
        }
    }

    @Override
    public List<Map.Entry<Integer, SshdSocketAddress>> getRemoteForwardsBindings() {
        synchronized (remoteToLocal) {
            return remoteToLocal.isEmpty()
                    ? Collections.emptyList()
                    : remoteToLocal.entrySet()
                            .stream() // return an immutable clone to avoid 'setValue' calls on a shared instance
                            .map(e -> new SimpleImmutableEntry<>(e.getKey(), e.getValue()))
                            .collect(Collectors.toCollection(() -> new ArrayList<>(remoteToLocal.size())));
        }
    }

    @Override
    public SshdSocketAddress getBoundRemotePortForward(int port) {
        ValidateUtils.checkTrue(port > 0, "Invalid remote port: %d", port);

        Integer portKey = Integer.valueOf(port);
        synchronized (remoteToLocal) {
            return remoteToLocal.get(portKey);
        }
    }

    @Override
    public NavigableSet<Integer> getStartedRemotePortForwards() {
        synchronized (remoteToLocal) {
            return remoteToLocal.isEmpty() ? Collections.emptyNavigableSet() : GenericUtils.asSortedSet(remoteToLocal.keySet());
        }
    }
}
