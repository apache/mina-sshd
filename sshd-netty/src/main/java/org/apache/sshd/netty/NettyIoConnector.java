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

package org.apache.sshd.netty;

import java.net.SocketAddress;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.util.concurrent.GlobalEventExecutor;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.future.CancelFuture;
import org.apache.sshd.common.io.DefaultIoConnectFuture;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoConnector;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoServiceEventListener;
import org.apache.sshd.core.CoreModuleProperties;

/**
 * The Netty based IoConnector implementation.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NettyIoConnector extends NettyIoService implements IoConnector {
    // Shared across all connectors
    private static final LoggingHandler LOGGING_TRACE = new LoggingHandler(NettyIoConnector.class, LogLevel.TRACE);

    public NettyIoConnector(NettyIoServiceFactory factory, IoHandler handler) {
        super(factory, handler);
        channelGroup = new DefaultChannelGroup("sshd-connector-channels", GlobalEventExecutor.INSTANCE);
    }

    @Override
    public IoConnectFuture connect(SocketAddress address, AttributeRepository context, SocketAddress localAddress) {
        if (log.isDebugEnabled()) {
            log.debug("Connecting to {}", address);
        }

        IoConnectFuture future = new DefaultIoConnectFuture(address, null);
        Bootstrap bootstrap = new Bootstrap().group(factory.eventLoopGroup)
                .channel(NioSocketChannel.class)
                .attr(CONNECT_FUTURE_KEY, future)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    @SuppressWarnings("synthetic-access")
                    protected void initChannel(SocketChannel ch) throws Exception {
                        IoServiceEventListener listener = getIoServiceEventListener();
                        SocketAddress local = ch.localAddress();
                        SocketAddress remote = ch.remoteAddress();
                        try {
                            if (listener != null) {
                                try {
                                    listener.connectionEstablished(NettyIoConnector.this, local, context, remote);
                                } catch (Exception e) {
                                    ch.close();
                                    throw e;
                                }
                            }

                            @SuppressWarnings("resource")
                            NettyIoSession session = new NettyIoSession(NettyIoConnector.this, handler, null);
                            if (context != null) {
                                session.setAttribute(AttributeRepository.class, context);
                            }

                            ChannelPipeline p = ch.pipeline();
                            p.addLast(LOGGING_TRACE); // TODO make this configurable
                            p.addLast(session.adapter);
                        } catch (Exception e) {
                            if (listener != null) {
                                try {
                                    listener.abortEstablishedConnection(NettyIoConnector.this, local, context, remote, e);
                                } catch (Exception exc) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("initChannel(" + ch + ") listener=" + listener
                                                  + " ignoring abort event exception",
                                                exc);
                                    }
                                }
                            }

                            throw e;
                        }
                    }
                });

        CoreModuleProperties.IO_CONNECT_TIMEOUT.get(factory.manager).ifPresent(d -> {
            if (d.isZero() || d.isNegative()) {
                return;
            }
            long millis;
            try {
                millis = d.toMillis();
            } catch (ArithmeticException e) {
                millis = Integer.MAX_VALUE;
            }
            if (millis > Integer.MAX_VALUE) {
                millis = Integer.MAX_VALUE;
            }
            bootstrap.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, Integer.valueOf((int) millis));
        });

        ChannelFuture chf;
        if (localAddress != null) {
            chf = bootstrap.connect(address, localAddress);
        } else {
            chf = bootstrap.connect(address);
        }
        future.addListener(f -> {
            if (f.isCanceled()) {
                if (chf.cancel(true) || chf.isCancelled()) {
                    f.getCancellation().setCanceled();
                }
            }
        });
        chf.addListener(cf -> {
            Throwable t = cf.cause();
            if (t != null) {
                future.setException(t);
            } else if (cf.isCancelled()) {
                CancelFuture cancellation = future.cancel();
                if (cancellation != null) {
                    cancellation.setCanceled();
                }
            }
        });
        // The future is completed when the session gets a channelActivated event.
        return future;
    }
}
