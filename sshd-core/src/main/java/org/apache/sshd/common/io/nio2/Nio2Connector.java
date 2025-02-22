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
package org.apache.sshd.common.io.nio2;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketAddress;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.future.CancelFuture;
import org.apache.sshd.common.io.DefaultIoConnectFuture;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoServiceEventListener;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.util.ExceptionUtils;
import org.apache.sshd.common.util.ValidateUtils;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * TODO Add javadoc
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class Nio2Connector extends Nio2Service implements IoConnector {
    private final Nio2ServiceFactory nio2ServiceFactory;

    public Nio2Connector(Nio2ServiceFactory nio2ServiceFactory, PropertyResolver propertyResolver, IoHandler handler,
                         AsynchronousChannelGroup group,
                         ExecutorService resumeTasks) {
        super(propertyResolver, handler, group, resumeTasks);
        this.nio2ServiceFactory = nio2ServiceFactory;
    }

    @Override
    public IoConnectFuture connect(
            SocketAddress address, AttributeRepository context, SocketAddress localAddress) {
        boolean debugEnabled = log.isDebugEnabled();
        if (debugEnabled) {
            log.debug("Connecting to {}", address);
        }

        IoConnectFuture future = new DefaultIoConnectFuture(address, null);
        AsynchronousSocketChannel channel = null;
        AsynchronousSocketChannel socket = null;
        try {
            AsynchronousChannelGroup group = getChannelGroup();
            channel = openAsynchronousSocketChannel(address, group);
            socket = setSocketOptions(channel);
            if (localAddress != null) {
                socket.bind(localAddress);
            }
            Nio2CompletionHandler<Void, Object> completionHandler = ValidateUtils.checkNotNull(
                    createConnectionCompletionHandler(
                            future, socket, context, propertyResolver, getIoHandler()),
                    "No connection completion handler created for %s",
                    address);
            // With a completion handler there is no way to cancel an ongoing connection attempt. We could only let
            // the attempt proceed to failure or success, and if successful, close the established channel again. With a
            // future, we can cancel the future to abort the connection attempt, but we need to use our own thread pool
            // for waiting on the future and invoking the completion handler.
            Future<Void> cf = socket.connect(address);
            Long connectTimeout = CoreModuleProperties.IO_CONNECT_TIMEOUT.get(propertyResolver).map(d -> {
                if (d.isZero() || d.isNegative()) {
                    return null;
                }
                long millis;
                try {
                    millis = d.toMillis();
                } catch (ArithmeticException e) {
                    millis = Long.MAX_VALUE;
                }
                return Long.valueOf(millis);
            }).orElse(null);

            Future<?> rf = getExecutorService().submit(() -> {
                try {
                    if (connectTimeout != null) {
                        log.debug("connect({}): waiting for connection (timeout={}ms)", address, connectTimeout);
                        cf.get(connectTimeout.longValue(), TimeUnit.MILLISECONDS);
                    } else {
                        log.debug("connect({}): waiting for connection", address);
                        cf.get();
                    }
                    completionHandler.onCompleted(null, null);
                } catch (CancellationException e) {
                    CancelFuture cancellation = future.cancel();
                    if (cancellation != null) {
                        cancellation.setCanceled(e);
                    }
                } catch (TimeoutException e) {
                    cf.cancel(true);
                    ConnectException c = new ConnectException("I/O connection time-out of " + connectTimeout + "ms expired");
                    c.initCause(e);
                    completionHandler.onFailed(c, null);
                } catch (ExecutionException e) {
                    completionHandler.onFailed(e, null);
                } catch (InterruptedException e) {
                    completionHandler.onFailed(e, null);
                    Thread.currentThread().interrupt();
                }
            });
            future.addListener(f -> {
                if (f.isCanceled()) {
                    // Don't interrupt if already running; if inside completionHandler.onCompleted() it might cause
                    // general confusion.
                    rf.cancel(false);
                    cf.cancel(true);
                }
            });
        } catch (Throwable exc) {
            Throwable t = ExceptionUtils.peelException(exc);
            debug("connect({}) failed ({}) to schedule connection: {}",
                    address, t.getClass().getSimpleName(), t.getMessage(), t);

            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException err) {
                if (debugEnabled) {
                    log.debug("connect({}) - failed ({}) to close socket: {}",
                            address, err.getClass().getSimpleName(), err.getMessage());
                }
            }

            try {
                if (channel != null) {
                    channel.close();
                }
            } catch (IOException err) {
                if (debugEnabled) {
                    log.debug("connect({}) - failed ({}) to close channel: {}",
                            address, err.getClass().getSimpleName(), err.getMessage());
                }
            }

            future.setException(t);
        }

        return future;
    }

    protected AsynchronousSocketChannel openAsynchronousSocketChannel(
            SocketAddress address, AsynchronousChannelGroup group)
            throws IOException {
        return AsynchronousSocketChannel.open(group);
    }

    protected Nio2CompletionHandler<Void, Object> createConnectionCompletionHandler(
            IoConnectFuture future, AsynchronousSocketChannel socket,
            AttributeRepository context, PropertyResolver propertyResolver, IoHandler handler) {
        return new ConnectionCompletionHandler(future, socket, context, propertyResolver, handler);
    }

    protected class ConnectionCompletionHandler extends Nio2CompletionHandler<Void, Object> {
        protected final IoConnectFuture future;
        protected final AsynchronousSocketChannel socket;
        protected final AttributeRepository context;
        protected final PropertyResolver propertyResolver;
        protected final IoHandler handler;

        protected ConnectionCompletionHandler(IoConnectFuture future, AsynchronousSocketChannel socket,
                                              AttributeRepository context, PropertyResolver propertyResolver,
                                              IoHandler handler) {
            this.future = future;
            this.socket = socket;
            this.context = context;
            this.propertyResolver = propertyResolver;
            this.handler = handler;
        }

        @Override
        @SuppressWarnings("synthetic-access")
        protected void onCompleted(Void result, Object attachment) {
            Long sessionId = null;
            IoServiceEventListener listener = getIoServiceEventListener();
            try {
                if (listener != null) {
                    SocketAddress local = socket.getLocalAddress();
                    SocketAddress remote = socket.getRemoteAddress();
                    listener.connectionEstablished(Nio2Connector.this, local, context, remote);
                }

                Nio2Session session = createSession(propertyResolver, handler, socket);
                if (context != null) {
                    session.setAttribute(AttributeRepository.class, context);
                }

                handler.sessionCreated(session);
                sessionId = session.getId();
                IoSession registered = mapSession(session);
                if (registered == session) {
                    future.setSession(session);
                }
                if (session != future.getSession()) {
                    session.close(true);
                    throw new CancellationException();
                } else if (session.isClosing()) {
                    try {
                        handler.sessionClosed(session);
                    } finally {
                        unmapSession(sessionId);
                    }
                } else {
                    session.startReading();
                }
            } catch (CancellationException e) {
                throw e;
            } catch (Throwable exc) {
                Throwable t = ExceptionUtils.peelException(exc);
                boolean debugEnabled = log.isDebugEnabled();
                if (listener != null) {
                    try {
                        SocketAddress localAddress = socket.getLocalAddress();
                        SocketAddress remoteAddress = socket.getRemoteAddress();
                        listener.abortEstablishedConnection(
                                Nio2Connector.this, localAddress, context, remoteAddress, t);
                    } catch (Exception e) {
                        if (debugEnabled) {
                            log.debug("onCompleted() listener=" + listener + " ignoring abort event exception", e);
                        }
                    }
                }

                log.debug("onCompleted - failed to start session: {} {}", t.getClass().getSimpleName(), t.getMessage(), t);

                IoSession session = future.getSession();
                if (session != null) {
                    try {
                        session.close(true);
                    } finally {
                        future.setException(t);
                    }
                } else {
                    try {
                        socket.close();
                    } catch (IOException err) {
                        if (debugEnabled) {
                            log.debug("onCompleted - failed to close socket: {} {}", err.getClass().getSimpleName(),
                                    err.getMessage());
                        }
                    }
                    future.setException(t);
                    unmapSession(sessionId);
                }
            }
        }

        @Override
        protected void onFailed(Throwable exc, Object attachment) {
            future.setException(exc);
        }
    }

    protected Nio2Session createSession(
            PropertyResolver propertyResolver, IoHandler handler, AsynchronousSocketChannel socket)
            throws Throwable {
        return nio2ServiceFactory.createSession(this, handler, socket, null);
    }
}
