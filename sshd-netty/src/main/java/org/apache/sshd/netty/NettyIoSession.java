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
import java.lang.reflect.Method;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.nio.AbstractNioChannel;
import io.netty.util.Attribute;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.io.AbstractIoWriteFuture;
import org.apache.sshd.common.io.IoConnectFuture;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.closeable.AbstractCloseable;

/**
 * The Netty based IoSession implementation.
 *
 * @author <a href="mailto:julien@julienviet.com">Julien Viet</a>
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class NettyIoSession extends AbstractCloseable implements IoSession {
    public static final Method NIO_JAVA_CHANNEL_METHOD = Stream.of(AbstractNioChannel.class.getDeclaredMethods())
            .filter(m -> "javaChannel".equals(m.getName()) && (m.getParameterCount() == 0))
            .map(m -> {
                m.setAccessible(true);
                return m;
            }).findFirst()
            .orElse(null);

    protected final Map<Object, Object> attributes = new HashMap<>();
    protected final NettyIoService service;
    protected final IoHandler handler;
    protected final long id;
    protected ChannelHandlerContext context;
    protected SocketAddress remoteAddr;
    protected ChannelFuture prev;
    protected final ChannelInboundHandlerAdapter adapter = new Adapter();

    private final SocketAddress acceptanceAddress;

    public NettyIoSession(NettyIoService service, IoHandler handler, SocketAddress acceptanceAddress) {
        super(Objects.toString(acceptanceAddress, ""));

        this.service = service;
        this.handler = handler;
        this.id = service.sessionSeq.incrementAndGet();
        this.acceptanceAddress = acceptanceAddress;
    }

    @Override
    public long getId() {
        return id;
    }

    @Override
    public Object getAttribute(Object key) {
        synchronized (attributes) {
            return attributes.get(key);
        }
    }

    @Override
    public Object setAttribute(Object key, Object value) {
        synchronized (attributes) {
            return attributes.put(key, value);
        }
    }

    @Override
    public Object setAttributeIfAbsent(Object key, Object value) {
        synchronized (attributes) {
            return attributes.putIfAbsent(key, value);
        }
    }

    @Override
    public Object removeAttribute(Object key) {
        synchronized (attributes) {
            return attributes.remove(key);
        }
    }

    @Override
    public SocketAddress getRemoteAddress() {
        return remoteAddr;
    }

    @Override
    public SocketAddress getLocalAddress() {
        Channel channel = (context == null) ? null : context.channel();
        return (channel == null) ? null : channel.localAddress();
    }

    @Override
    public SocketAddress getAcceptanceAddress() {
        return acceptanceAddress;
    }

    @Override
    public IoWriteFuture writeBuffer(Buffer buffer) {
        int bufLen = buffer.available();
        ByteBuf buf = Unpooled.buffer(bufLen);
        buf.writeBytes(buffer.array(), buffer.rpos(), bufLen);
        DefaultIoWriteFuture msg = new DefaultIoWriteFuture(getRemoteAddress(), null);
        ChannelPromise next = context.newPromise();
        prev.addListener(whatever -> {
            if (context != null) {
                context.writeAndFlush(buf, next);
            }
        });
        prev = next;
        next.addListener(fut -> {
            if (fut.isSuccess()) {
                msg.setValue(Boolean.TRUE);
            } else {
                msg.setValue(fut.cause());
            }
        });
        return msg;
    }

    @Override
    public IoService getService() {
        return service;
    }

    @Override // see SSHD-902
    public void shutdownOutputStream() throws IOException {
        Channel ch = context.channel();
        boolean debugEnabled = log.isDebugEnabled();
        if (!(ch instanceof AbstractNioChannel)) {
            if (debugEnabled) {
                log.debug("shudownOutputStream({}) channel is not AbstractNioChannel: {}",
                        this, (ch == null) ? null : ch.getClass().getSimpleName());
            }
            return;
        }

        if (NIO_JAVA_CHANNEL_METHOD == null) {
            if (debugEnabled) {
                log.debug("shudownOutputStream({}) missing channel access method", this);
            }
            return;
        }

        SelectableChannel channel;
        try {
            channel = (SelectableChannel) NIO_JAVA_CHANNEL_METHOD.invoke(ch, GenericUtils.EMPTY_OBJECT_ARRAY);
        } catch (Exception t) {
            Throwable e = GenericUtils.peelException(t);
            log.warn("shudownOutputStream({}) failed ({}) to retrieve embedded channel: {}",
                    this, e.getClass().getSimpleName(), e.getMessage());
            return;
        }

        if (!(channel instanceof SocketChannel)) {
            if (debugEnabled) {
                log.debug("shudownOutputStream({}) not a SocketChannel: {}",
                        this, (channel == null) ? null : channel.getClass().getSimpleName());
            }
            return;
        }

        Socket socket = ((SocketChannel) channel).socket();
        if (socket.isConnected() && (!socket.isClosed())) {
            if (debugEnabled) {
                log.debug("shudownOutputStream({})", this);
            }
            socket.shutdownOutput();
        }
    }

    @Override
    protected CloseFuture doCloseGracefully() {
        context.writeAndFlush(Unpooled.EMPTY_BUFFER)
                .addListener(ChannelFutureListener.CLOSE)
                .addListener(fut -> closeFuture.setClosed());
        return closeFuture;
    }

    @Override
    protected void doCloseImmediately() {
        context.close();
        super.doCloseImmediately();
    }

    protected void channelActive(ChannelHandlerContext ctx) throws Exception {
        context = ctx;
        Channel channel = ctx.channel();
        service.channelGroup.add(channel);
        service.sessions.put(id, NettyIoSession.this);
        prev = context.newPromise().setSuccess();
        remoteAddr = channel.remoteAddress();
        handler.sessionCreated(NettyIoSession.this);

        Attribute<IoConnectFuture> connectFuture = channel.attr(NettyIoService.CONNECT_FUTURE_KEY);
        IoConnectFuture future = connectFuture.get();
        if (future != null) {
            future.setSession(NettyIoSession.this);
        }
    }

    protected void channelInactive(ChannelHandlerContext ctx) throws Exception {
        service.sessions.remove(id);
        handler.sessionClosed(NettyIoSession.this);
        context = null;
    }

    protected void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        ByteBuf buf = (ByteBuf) msg;
        try {
            handler.messageReceived(NettyIoSession.this, NettySupport.asReadable(buf));
        } finally {
            buf.release();
        }
    }

    protected void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        handler.exceptionCaught(NettyIoSession.this, cause);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
               + "[local=" + getLocalAddress()
               + ", remote=" + getRemoteAddress()
               + "]";
    }

    protected static class DefaultIoWriteFuture extends AbstractIoWriteFuture {
        public DefaultIoWriteFuture(Object id, Object lock) {
            super(id, lock);
        }
    }

    /**
     * Simple netty adapter to use as a bridge.
     */
    protected class Adapter extends ChannelInboundHandlerAdapter {
        public Adapter() {
            super();
        }

        @Override
        public void channelActive(ChannelHandlerContext ctx) throws Exception {
            NettyIoSession.this.channelActive(ctx);
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            NettyIoSession.this.channelInactive(ctx);
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            NettyIoSession.this.channelRead(ctx, msg);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            NettyIoSession.this.exceptionCaught(ctx, cause);
        }
    }
}
