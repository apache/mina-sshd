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

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.io.IoAcceptor;
import org.apache.sshd.common.io.IoHandler;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.util.concurrent.GlobalEventExecutor;

/**
 * The Netty based IoAcceptor implementation.
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NettyIoAcceptor extends NettyIoService implements IoAcceptor {
    protected final ServerBootstrap bootstrap = new ServerBootstrap();
    protected final DefaultCloseFuture closeFuture = new DefaultCloseFuture(toString(), lock);
    protected final Map<SocketAddress, Channel> boundAddresses = new ConcurrentHashMap<>();
    protected final IoHandler handler;

    public NettyIoAcceptor(NettyIoServiceFactory factory, IoHandler handler) {
        this.factory = factory;
        this.handler = handler;
        channelGroup = new DefaultChannelGroup("sshd-acceptor-channels", GlobalEventExecutor.INSTANCE);
        bootstrap.group(factory.eventLoopGroup)
            .channel(NioServerSocketChannel.class)
            .option(ChannelOption.SO_BACKLOG, 100)  // TODO make this configurable
            .handler(new LoggingHandler(LogLevel.INFO)) // TODO make this configurable
            .childHandler(new ChannelInitializer<SocketChannel>() {
                @Override
                public void initChannel(SocketChannel ch) throws Exception {
                    ChannelPipeline p = ch.pipeline();
                    @SuppressWarnings("resource")
                    NettyIoSession nettyIoSession = new NettyIoSession(NettyIoAcceptor.this, handler);
                    p.addLast(nettyIoSession.adapter);
                }
            });
    }

    @Override
    public void bind(Collection<? extends SocketAddress> addresses) throws IOException {
        for (SocketAddress address : addresses) {
            bind(address);
        }
    }

    @Override
    public void bind(SocketAddress address) throws IOException {
        InetSocketAddress inetAddress = (InetSocketAddress) address;
        ChannelFuture f = bootstrap.bind(inetAddress);
        Channel channel = f.channel();
        channelGroup.add(channel);
        try {
            f.sync();
            SocketAddress bound = channel.localAddress();
            boundAddresses.put(bound, channel);
            channel.closeFuture().addListener(fut -> boundAddresses.remove(bound));
        } catch (InterruptedException e) {
            throw (InterruptedIOException) new InterruptedIOException().initCause(e);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    @Override
    public void unbind(Collection<? extends SocketAddress> addresses) {
        CountDownLatch latch = new CountDownLatch(addresses.size());
        for (SocketAddress address : addresses) {
            Channel channel = boundAddresses.remove(address);
            if (channel != null) {
                ChannelFuture fut;
                if (channel.isOpen()) {
                    fut = channel.close();
                } else {
                    fut = channel.closeFuture();
                }
                fut.addListener(f -> latch.countDown());
            } else {
                latch.countDown();
            }
        }
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void unbind(SocketAddress address) {
        Channel channel = boundAddresses.remove(address);
        if (channel != null) {
            ChannelFuture fut;
            if (channel.isOpen()) {
                fut = channel.close();
            } else {
                fut = channel.closeFuture();
            }
            try {
                fut.sync();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    @Override
    public void unbind() {
        Collection<SocketAddress> addresses = getBoundAddresses();
        if (log.isDebugEnabled()) {
            log.debug("Unbinding {}", addresses);
        }

        unbind(addresses);
    }

    @Override
    public Set<SocketAddress> getBoundAddresses() {
        return new HashSet<>(boundAddresses.keySet());
    }

    @Override
    protected CloseFuture doCloseGracefully() {
        channelGroup.close().addListener(fut -> closeFuture.setClosed());
        return closeFuture;
    }

    @Override
    protected void doCloseImmediately() {
        doCloseGracefully();
        super.doCloseImmediately();
    }
}
