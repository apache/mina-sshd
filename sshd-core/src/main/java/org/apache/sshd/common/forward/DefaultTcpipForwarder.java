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
package org.apache.sshd.common.forward;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.FactoryManager;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.SshdSocketAddress;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoHandlerFactory;
import org.apache.sshd.common.io.IoServiceFactory;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.util.CloseableUtils;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.Readable;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.forward.ForwardingFilter;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class DefaultTcpipForwarder extends CloseableUtils.AbstractInnerCloseable implements TcpipForwarder {

    private final ConnectionService service;
    private final IoHandlerFactory socksProxyIoHandlerFactory = new IoHandlerFactory() {
            @Override
            public IoHandler create() {
                return new SocksProxy(getConnectionService());
            }
        };
    private final Session session;
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
    protected IoAcceptor acceptor;

    public DefaultTcpipForwarder(ConnectionService service) {
        this.service = ValidateUtils.checkNotNull(service, "No connection service");
        this.session = ValidateUtils.checkNotNull(service.getSession(), "No session");
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
        synchronized(localToRemote) {
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
        synchronized(localToRemote) {
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

        Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
        buffer.putString("tcpip-forward");
        buffer.putBoolean(true);
        buffer.putString(remote.getHostName());
        buffer.putInt(remote.getPort());
        Buffer result = session.request(buffer);
        if (result == null) {
            throw new SshException("Tcpip forwarding request denied by server");
        }
        int port = (remote.getPort() == 0) ? result.getInt() : remote.getPort();
        // TODO: Is it really safe to only store the local address after the request ?
        SshdSocketAddress prev;
        synchronized(remoteToLocal) {
            prev = remoteToLocal.put(port, local);
        }
        
        if (prev != null) {
            throw new IOException("Multiple remote port forwarding bindings on port=" + port + ": current=" + remote + ", previous=" + prev);
        }

        SshdSocketAddress bound = new SshdSocketAddress(remote.getHostName(), port);
        if (log.isDebugEnabled()) {
            log.debug("startRemotePortForwarding(" + remote + " -> " + local + "): " + bound);
        }

        return bound;
    }

    @Override
    public synchronized void stopRemotePortForwarding(SshdSocketAddress remote) throws IOException {
        SshdSocketAddress bound;
        synchronized(remoteToLocal) {
            bound = remoteToLocal.remove(remote.getPort());
        }

        if (bound != null) {
            if (log.isDebugEnabled()) {
                log.debug("stopRemotePortForwarding(" + remote + ") cancel forwarding to " + bound);
            }

            Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
            buffer.putString("cancel-tcpip-forward");
            buffer.putBoolean(false);
            buffer.putString(remote.getHostName());
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

        SocksProxy socksProxy = new SocksProxy(service), prev;
        InetSocketAddress bound = doBind(local, socksProxyIoHandlerFactory);
        int port = bound.getPort();
        synchronized(dynamicLocal) {
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
        synchronized(dynamicLocal) {
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
        synchronized(remoteToLocal) {
            return remoteToLocal.get(remotePort);
        }
    }

    @Override
    public synchronized SshdSocketAddress localPortForwardingRequested(SshdSocketAddress local) throws IOException {
        ValidateUtils.checkNotNull(local, "Local address is null");
        ValidateUtils.checkTrue(local.getPort() >= 0, "Invalid local port: %s", local);
        
        FactoryManager manager = session.getFactoryManager();
        ForwardingFilter filter = manager.getTcpipForwardingFilter();
        if ((filter == null) || (!filter.canListen(local, session))) {
            if (log.isDebugEnabled()) {
                log.debug("localPortForwardingRequested(" + session + ")[" + local + "][haveFilter=" + (filter != null) + "] rejected");
            }
            throw new IOException("Rejected address: " + local);
        }
        InetSocketAddress bound = doBind(local, staticIoHandlerFactory);
        SshdSocketAddress result = new SshdSocketAddress(bound.getHostString(), bound.getPort());
        if (log.isDebugEnabled()) {
            log.debug("localPortForwardingRequested(" + local + "): " + result);
        }

        boolean added;
        synchronized(localForwards) {
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
        synchronized(localForwards) {
            if ((entry=LocalForwardingEntry.findMatchingEntry(local.getHostName(), local.getPort(), localForwards)) != null) {
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
     * @param address The request bind address
     * @param handlerFactory A {@link Factory} to create an {@link IoHandler} if necessary
     * @return The {@link InetSocketAddress} to which the binding occurred
     * @throws IOException If failed to bind
     */
    private InetSocketAddress doBind(SshdSocketAddress address, Factory<? extends IoHandler> handlerFactory) throws IOException {
        if (acceptor == null) {
            FactoryManager manager = session.getFactoryManager();
            IoServiceFactory factory = manager.getIoServiceFactory();
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
        return getClass().getSimpleName() + "[" + session + "]";
    }

    //
    // Static IoHandler implementation
    //

    class StaticIoHandler implements IoHandler {
        StaticIoHandler() {
            super();
        }

        @SuppressWarnings("synthetic-access")
        @Override
        public void sessionCreated(final IoSession session) throws Exception {
            InetSocketAddress local = (InetSocketAddress) session.getLocalAddress(); 
            int localPort = local.getPort();
            SshdSocketAddress remote = localToRemote.get(localPort);
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
                        DefaultTcpipForwarder.this.service.unregisterChannel(channel);
                        channel.close(false);
                    }
                }
            });
        }

        @SuppressWarnings("synthetic-access")
        @Override
        public void sessionClosed(IoSession session) throws Exception {
            TcpipClientChannel channel = (TcpipClientChannel) session.getAttribute(TcpipClientChannel.class);
            if (channel != null) {
                log.debug("IoSession {} closed, will now close the channel", session);
                channel.close(false);
            }
        }

        @Override
        public void messageReceived(IoSession session, Readable message) throws Exception {
            TcpipClientChannel channel = (TcpipClientChannel) session.getAttribute(TcpipClientChannel.class);
            Buffer buffer = new ByteArrayBuffer();
            buffer.putBuffer(message);
            channel.waitFor(ClientChannel.OPENED | ClientChannel.CLOSED, Long.MAX_VALUE);
            channel.getInvertedIn().write(buffer.array(), buffer.rpos(), buffer.available());
            channel.getInvertedIn().flush();
        }

        @Override
        public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
            cause.printStackTrace();
            session.close(false);
        }
    }
}
